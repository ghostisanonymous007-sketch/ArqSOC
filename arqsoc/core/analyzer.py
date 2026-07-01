"""Master analyzer that orchestrates all scan modules for ArqSOC."""

from __future__ import annotations

from pathlib import Path

from arqsoc.core.entropy import analyze_file_entropy
from arqsoc.core.hashes import calculate_hashes
from arqsoc.core.iat_reconstruct import detect_dynamic_imports
from arqsoc.core.imports import (
    extract_exports,
    extract_file_info,
    extract_imports,
    extract_sections,
    parse_binary,
)
from arqsoc.core.overlay import detect_overlay
from arqsoc.core.packer import detect_packer
from arqsoc.core.rich_header import parse_rich_header
from arqsoc.core.signature import check_signature
from arqsoc.core.signatures import load_rules, scan_with_yara
from arqsoc.core.strings import analyze_strings
from arqsoc.core.tls import detect_tls
from arqsoc.models.scan_result import (
    BinaryType,
    ClassifiedString,
    IATEntry,
    OverlayInfo,
    ScanResult,
    SignatureInfo,
    StringClassification,
    ThreatIndicator,
    ThreatLevel,
    ThreatTimelineEntry,
    TLSInfo,
)


def _correlate_indicators(
    imports: list,
    strings: list[ClassifiedString],
    sections: list,
    packer_result,
    yara_matches: list,
) -> tuple[list[ThreatIndicator], list[ThreatTimelineEntry], float, ThreatLevel]:
    indicators: list[ThreatIndicator] = []
    timeline: list[ThreatTimelineEntry] = []
    confidence = 0.0
    signals = 0

    injection_apis = {
        "virtualallocex", "writeprocessmemory", "createremotethread",
        "virtualprotectex", "openprocess", "createprocessa", "createprocessw",
        "ntcreateprocessex", "rtlcreatuserprocess",
    }
    network_apis = {
        "internetopena", "internetopenw", "internetconnecta", "internetconnectw",
        "httpopenrequesta", "httpopenrequestw", "httpsendrequesta", "httpsendrequestw",
        "socket", "connect", "send", "recv", "wsastartup",
    }
    persistence_apis = {
        "regsetvalueexa", "regsetvalueexw", "regcreatekeyexa", "regcreatekeyexw",
        "createuser servicestart", "startservicectrldispatcher",
    }
    evasion_apis = {
        "virtualprotect", "ntunmapviewofsection", "setunhandledexceptionfilter",
        "exitprocess", "getprocaddress", "loadlibrary",
    }

    import_names = {imp.name.lower() for imp in imports}

    has_injection = bool(import_names & injection_apis)
    has_network = bool(import_names & network_apis)
    has_persistence = bool(import_names & persistence_apis)
    bool(import_names & evasion_apis)

    url_strings = [s for s in strings if s.classification == StringClassification.URL]
    registry_strings = [s for s in strings if s.classification == StringClassification.REGISTRY]
    crypto_strings = [s for s in strings if s.classification == StringClassification.CRYPTO]

    if packer_result.is_packed:
        indicators.append(
            ThreatIndicator(
                type="packer", value=packer_result.packer_name,
                confidence=packer_result.confidence, source="packer_detection",
            )
        )
        signals += 1
        confidence += packer_result.confidence * 0.3
        timeline.append(
            ThreatTimelineEntry(
                step=1, description=f"Packed with {packer_result.packer_name}",
                indicators=[f"Confidence: {packer_result.confidence:.0%}"],
                confidence=packer_result.confidence,
            )
        )

    if has_injection:
        matched = import_names & injection_apis
        indicators.append(
            ThreatIndicator(
                type="injection", value=", ".join(sorted(matched)),
                confidence=0.85, source="imports",
            )
        )
        signals += 1
        confidence += 0.35
        step = len(timeline) + 1
        timeline.append(
            ThreatTimelineEntry(
                step=step, description="Potential process injection capability",
                indicators=sorted(matched), confidence=0.85,
            )
        )

    if has_network and url_strings:
        urls = [s.value for s in url_strings[:5]]
        indicators.append(
            ThreatIndicator(
                type="network_c2", value=", ".join(urls),
                confidence=0.7, source="imports+strings",
            )
        )
        signals += 1
        confidence += 0.25
        step = len(timeline) + 1
        timeline.append(
            ThreatTimelineEntry(
                step=step, description="Network communication with remote servers",
                indicators=urls, confidence=0.7,
            )
        )

    if has_persistence:
        matched = import_names & persistence_apis
        indicators.append(
            ThreatIndicator(
                type="persistence", value=", ".join(sorted(matched)),
                confidence=0.7, source="imports+strings",
            )
        )
        signals += 1
        confidence += 0.2
        step = len(timeline) + 1
        timeline.append(
            ThreatTimelineEntry(
                step=step, description="Registry-based persistence mechanism",
                indicators=sorted(matched), confidence=0.7,
            )
        )

    if registry_strings:
        indicators.append(
            ThreatIndicator(
                type="registry", value=", ".join(s.value for s in registry_strings[:3]),
                confidence=0.6, source="strings",
            )
        )

    if crypto_strings and has_network:
        indicators.append(
            ThreatIndicator(
                type="crypto_exfil",
                value=f"{len(crypto_strings)} crypto + {len(url_strings)} URLs",
                confidence=0.5, source="cross-correlation",
            )
        )
        signals += 1
        confidence += 0.15

    rwx_sections = [s for s in sections if s.is_executable and s.is_writable]
    if rwx_sections:
        indicators.append(
            ThreatIndicator(
                type="rwx_section", value=", ".join(s.name for s in rwx_sections),
                confidence=0.7, source="sections",
            )
        )
        signals += 1
        confidence += 0.15
        step = len(timeline) + 1
        timeline.append(
            ThreatTimelineEntry(
                step=step, description="RWX memory section detected (possible shellcode)",
                indicators=[s.name for s in rwx_sections], confidence=0.7,
            )
        )

    for match in yara_matches:
        severity = match.meta.get("severity", "low")
        conf_map = {"high": 0.9, "medium": 0.6, "suspicious": 0.5, "low": 0.3}
        rule_conf = conf_map.get(severity, 0.4)
        indicators.append(
            ThreatIndicator(
                type="yara", value=match.rule_name,
                confidence=rule_conf, source="yara",
            )
        )
        signals += 1
        confidence += rule_conf * 0.2

    confidence = min(confidence, 1.0)

    if confidence >= 0.7:
        threat_level = ThreatLevel.MALICIOUS
    elif confidence >= 0.4:
        threat_level = ThreatLevel.SUSPICIOUS
    elif signals > 0:
        threat_level = ThreatLevel.SUSPICIOUS
    else:
        threat_level = ThreatLevel.BENIGN

    return indicators, timeline, round(confidence, 2), threat_level


def _enrich_correlation(
    indicators: list[ThreatIndicator],
    timeline: list[ThreatTimelineEntry],
    overlay: OverlayInfo,
    tls_info: TLSInfo,
    signature_info: SignatureInfo,
    dynamic_imports: list[IATEntry],
) -> None:
    if overlay.has_overlay and overlay.size > 0:
        risk = 0.5
        if overlay.magic in ("PE (nested)", "ELF (nested)"):
            risk = 0.85
        elif overlay.entropy > 7.5:
            risk = 0.7
        elif overlay.magic:
            risk = 0.4
        indicators.append(
            ThreatIndicator(
                type="overlay",
                value=f"{overlay.size}B at 0x{overlay.offset:x}"
                + (f" [{overlay.magic}]" if overlay.magic else ""),
                confidence=risk,
                source="overlay",
            )
        )
        step = len(timeline) + 1
        timeline.append(
            ThreatTimelineEntry(
                step=step,
                description=f"Overlay data appended ({overlay.magic or 'unknown'})",
                indicators=[f"offset=0x{overlay.offset:x} size={overlay.size}"],
                confidence=risk,
            )
        )

    if tls_info.has_tls and tls_info.callbacks:
        indicators.append(
            ThreatIndicator(
                type="tls_callback",
                value=f"{len(tls_info.callbacks)} callback(s): "
                + ", ".join(c.callback_hex for c in tls_info.callbacks[:5]),
                confidence=0.6,
                source="tls",
            )
        )
        step = len(timeline) + 1
        timeline.append(
            ThreatTimelineEntry(
                step=step,
                description="TLS callbacks detected (code runs before entry point)",
                indicators=[c.callback_hex for c in tls_info.callbacks[:5]],
                confidence=0.6,
            )
        )

    if not signature_info.is_signed:
        indicators.append(
            ThreatIndicator(
                type="unsigned",
                value="No Authenticode signature",
                confidence=0.2,
                source="signature",
            )
        )
    elif not signature_info.is_valid:
        indicators.append(
            ThreatIndicator(
                type="invalid_sig",
                value=f"Invalid signature (signer: {signature_info.signer})",
                confidence=0.6,
                source="signature",
            )
        )

    high_risk_dynamic = [
        d for d in dynamic_imports if d.confidence >= 0.7 and d.source == "dynamic_string"
    ]
    if high_risk_dynamic:
        apis = ", ".join(d.api_name for d in high_risk_dynamic[:10])
        indicators.append(
            ThreatIndicator(
                type="dynamic_resolve",
                value=f"Potential runtime API resolution: {apis}",
                confidence=0.7,
                source="iat_reconstruction",
            )
        )
        step = len(timeline) + 1
        timeline.append(
            ThreatTimelineEntry(
                step=step,
                description="Dynamic API resolution detected (IAT obfuscation)",
                indicators=[d.api_name for d in high_risk_dynamic[:5]],
                confidence=0.7,
            )
        )


def scan_file(file_path: Path, rules_dir: Path | None = None) -> ScanResult:
    errors: list[str] = []

    binary, parse_err = parse_binary(file_path)
    if parse_err:
        errors.append(f"Binary parsing: {parse_err}")

    file_info = extract_file_info(file_path, binary)
    hashes = calculate_hashes(file_path)

    sections: list = []
    imports: list = []
    exports: list = []

    if binary is not None:
        sections = extract_sections(binary)
        imports = extract_imports(binary)
        exports = extract_exports(binary)

    sections = analyze_file_entropy(file_path, sections)

    strings = analyze_strings(file_path)

    packer_result = detect_packer(sections, len(imports))

    yara_matches = []
    yara_rules = load_rules(rules_dir)
    if yara_rules is not None:
        yara_matches = scan_with_yara(file_path, yara_rules)

    indicators, timeline, overall_confidence, threat_level = _correlate_indicators(
        imports, strings, sections, packer_result, yara_matches,
    )

    rich_header = parse_rich_header(file_path)
    overlay = detect_overlay(file_path)
    tls_info = detect_tls(file_path)
    signature_info = check_signature(file_path)
    dynamic_imports = detect_dynamic_imports(file_path)

    is_pe = file_info.binary_type in (BinaryType.PE32, BinaryType.PE64)
    if is_pe:
        _enrich_correlation(
            indicators, timeline, overlay, tls_info, signature_info,
            dynamic_imports,
        )
        overall_confidence = min(
            overall_confidence + sum(
                0.1 for i in indicators
                if i.type in ("overlay", "tls_callback", "unsigned")
            ),
            1.0,
        )
        if overall_confidence >= 0.7:
            threat_level = ThreatLevel.MALICIOUS
        elif overall_confidence >= 0.4 or any(
            i.type in ("tls_callback", "overlay") for i in indicators
        ):
            if threat_level == ThreatLevel.BENIGN:
                threat_level = ThreatLevel.SUSPICIOUS
        overall_confidence = round(overall_confidence, 2)

    return ScanResult(
        file_info=file_info,
        hashes=hashes,
        sections=sections,
        imports=imports,
        exports=exports,
        strings=strings,
        packer=packer_result,
        yara_matches=yara_matches,
        threat_level=threat_level,
        overall_confidence=overall_confidence,
        threat_indicators=indicators,
        threat_timeline=timeline,
        errors=errors,
        rich_header=rich_header,
        overlay=overlay,
        tls=tls_info,
        signature=signature_info,
        dynamic_imports=dynamic_imports,
    )
