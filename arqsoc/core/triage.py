"""Batch triage engine - scan directory of samples and prioritize by risk."""

from __future__ import annotations

import math
from pathlib import Path

from arqsoc.core.hashes import calculate_hashes
from arqsoc.core.entropy import analyze_file_entropy
from arqsoc.core.packer import detect_packer
from arqsoc.core.strings import analyze_strings
from arqsoc.core.imports import extract_file_info, extract_imports, parse_binary
from arqsoc.core.signatures import load_rules, scan_with_yara
from arqsoc.models.batch import TriageResult
from arqsoc.models.scan_result import StringClassification


def _priority_from_score(score: float) -> str:
    if score >= 0.8:
        return "critical"
    elif score >= 0.6:
        return "high"
    elif score >= 0.4:
        return "medium"
    elif score >= 0.2:
        return "low"
    return "normal"


def triage_file(file_path: Path, vt_lookup: bool = False) -> TriageResult:
    hashes = calculate_hashes(file_path)
    sha256 = hashes.sha256

    binary, _ = parse_binary(file_path)
    file_info = extract_file_info(file_path, binary)

    imports: list = []
    if binary is not None:
        imports = extract_imports(binary)

    sections = []
    if binary is not None:
        from arqsoc.core.imports import extract_sections
        sections = extract_sections(binary)

    sections = analyze_file_entropy(file_path, sections)
    strings = analyze_strings(file_path)
    packer = detect_packer(sections, len(imports))

    vt_detections = ""
    if vt_lookup:
        from arqsoc.core.threat_intel import enrich_vt_hash
        vt_result = enrich_vt_hash(sha256)
        vt_detections = vt_result.get("detection_ratio", "")

    max_entropy = max((s.entropy for s in sections), default=0.0)
    suspicious_strings = [
        s for s in strings
        if s.classification in (
            StringClassification.URL,
            StringClassification.IP,
            StringClassification.C2,
            StringClassification.REGISTRY,
            StringClassification.CRYPTO,
            StringClassification.MUTEX,
        )
    ]

    risk_score = 0.0

    if packer.is_packed:
        risk_score += min(packer.confidence * 0.3, 0.3)

    if max_entropy >= 7.5:
        risk_score += 0.2
    elif max_entropy >= 7.0:
        risk_score += 0.1

    if len(imports) > 0 and len(imports) < 5:
        risk_score += 0.15

    suspicious_ratio = len(suspicious_strings) / max(len(strings), 1)
    risk_score += min(suspicious_ratio * 0.3, 0.3)

    if vt_detections:
        try:
            parts = vt_detections.split("/")
            if len(parts) == 2:
                pos = int(parts[0])
                if pos > 10:
                    risk_score += 0.4
                elif pos > 5:
                    risk_score += 0.25
                elif pos > 0:
                    risk_score += 0.1
        except (ValueError, IndexError):
            pass

    risk_score = min(risk_score, 1.0)

    threat_strs: list[str] = []
    if packer.is_packed:
        threat_strs.append(f"packed:{packer.packer_name}")
    if max_entropy >= 7.0:
        threat_strs.append(f"high_entropy:{max_entropy:.1f}")
    if suspicious_strings:
        threat_strs.append(f"suspicious_strings:{len(suspicious_strings)}")
    if vt_detections:
        threat_strs.append(f"vt:{vt_detections}")

    summary = " | ".join(threat_strs) if threat_strs else "clean"

    return TriageResult(
        file_path=str(file_path),
        priority=_priority_from_score(risk_score),
        risk_score=round(risk_score, 2),
        vt_detections=vt_detections,
        entropy=round(max_entropy, 2),
        is_packed=packer.is_packed,
        suspicious_strings_count=len(suspicious_strings),
        summary=summary,
        sha256=sha256,
        file_size=file_path.stat().st_size,
    )


def triage_directory(
    dir_path: Path,
    vt_lookup: bool = False,
    max_files: int = 1000,
) -> list[TriageResult]:
    results: list[TriageResult] = []

    files = sorted(
        f for f in dir_path.rglob("*")
        if f.is_file() and not f.name.startswith(".")
    )[:max_files]

    for f in files:
        try:
            result = triage_file(f, vt_lookup=vt_lookup)
            results.append(result)
        except Exception:
            results.append(TriageResult(
                file_path=str(f),
                priority="normal",
                risk_score=0.0,
                summary="error_processing",
                file_size=f.stat().st_size if f.exists() else 0,
            ))

    results.sort(key=lambda r: r.risk_score, reverse=True)
    return results
