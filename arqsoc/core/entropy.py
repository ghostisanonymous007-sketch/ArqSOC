"""Entropy analysis and heatmap generation for ArqSOC."""

from __future__ import annotations

from pathlib import Path

from arqsoc.core.hashes import calculate_entropy
from arqsoc.models.scan_result import SectionInfo

ENTROPY_SUSPICIOUS_THRESHOLD = 7.0
ENTROPY_HIGH_THRESHOLD = 7.5
BLOCK_SIZE = 1024


def compute_section_entropy(data: bytes, section_name: str, offset: int, size: int) -> SectionInfo:
    section_data = data[offset : offset + size] if size > 0 else b""
    entropy = calculate_entropy(section_data) if section_data else 0.0

    is_suspicious = entropy >= ENTROPY_SUSPICIOUS_THRESHOLD
    anomaly_reason = ""
    if entropy >= ENTROPY_HIGH_THRESHOLD:
        anomaly_reason = "High entropy - likely packed/encrypted"
    elif entropy >= ENTROPY_SUSPICIOUS_THRESHOLD:
        anomaly_reason = "Elevated entropy - possibly compressed"

    return SectionInfo(
        name=section_name,
        virtual_address=offset,
        virtual_size=size,
        raw_size=len(section_data),
        entropy=round(entropy, 4),
        is_suspicious=is_suspicious,
        anomaly_reason=anomaly_reason,
    )


def compute_block_entropy(data: bytes, block_size: int = BLOCK_SIZE) -> list[float]:
    entropies: list[float] = []
    for i in range(0, len(data), block_size):
        block = data[i : i + block_size]
        entropies.append(round(calculate_entropy(block), 4))
    return entropies


def entropy_to_bar(entropy: float, width: int = 10) -> str:
    filled = int((entropy / 8.0) * width)
    filled = max(0, min(width, filled))
    return "#" * filled + "-" * (width - filled)


def entropy_to_color(entropy: float) -> str:
    if entropy < 3.0:
        return "dim"
    elif entropy < 5.0:
        return "green"
    elif entropy < 7.0:
        return "yellow"
    elif entropy < 7.5:
        return "red"
    else:
        return "bold red"


def analyze_file_entropy(
    file_path: Path, sections: list[SectionInfo] | None = None,
) -> list[SectionInfo]:
    data = file_path.read_bytes()

    if sections:
        updated: list[SectionInfo] = []
        for sec in sections:
            updated.append(
                compute_section_entropy(
                    data, sec.name, sec.virtual_address, sec.raw_size,
                )
            )
        return updated

    whole_entropy = calculate_entropy(data)
    return [
        SectionInfo(
            name="<whole file>",
            virtual_address=0,
            virtual_size=len(data),
            raw_size=len(data),
            entropy=round(whole_entropy, 4),
            is_suspicious=whole_entropy >= ENTROPY_SUSPICIOUS_THRESHOLD,
            anomaly_reason="High entropy" if whole_entropy >= ENTROPY_HIGH_THRESHOLD else "",
        )
    ]
