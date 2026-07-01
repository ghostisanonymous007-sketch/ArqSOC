"""Packer and compiler detection for ArqSOC."""

from __future__ import annotations

from arqsoc.models.scan_result import PackerResult, SectionInfo

KNOWN_PACKER_SECTIONS = {
    "upx0": "UPX",
    "upx1": "UPX",
    "upx2": "UPX",
    ".upx0": "UPX",
    ".upx1": "UPX",
    ".upx2": "UPX",
    "mpress1": "MPRESS",
    "mpress2": "MPRESS",
    ".mpress1": "MPRESS",
    ".mpress2": "MPRESS",
    ".nsp0": "NSPack",
    ".nsp1": "NSPack",
    ".nsp2": "NSPack",
    "pebundle": "PEBundle",
    ".pertob": "PESpin",
    "themida": "Themida/WinLicense",
    ".themida": "Themida/WinLicense",
    ".vmp0": "VMProtect",
    ".vmp1": "VMProtect",
    "vmp0": "VMProtect",
    "vmp1": "VMProtect",
    "data1": "ASPack",
    "data2": "ASPack",
    ".aspack": "ASPack",
    ".shrink": "Shrinker",
    ".yp": "y0da Protector",
    ".perplex": "Perplex PE Protector",
    "pec2": "PECompact2",
    "pec1": "PECompact2",
    "fsg": "FSG",
    ".fsg": "FSG",
    ".charmve": "PE-Armor",
    "enigma1": "Enigma Protector",
    "enigma2": "Enigma Protector",
}

KNOWN_PACKER_IMPORTS = {
    "upx": "UPX",
    "mpress": "MPRESS",
    "nspack": "NSPack",
    "aspack": "ASPack",
    "themida": "Themida/WinLicense",
    "vmp": "VMProtect",
    "enigma": "Enigma Protector",
}

MIN_IMPORTS_FOR_PACKER = 5
HIGH_ENTROPY_THRESHOLD = 7.0


def detect_packer(sections: list[SectionInfo], import_count: int) -> PackerResult:
    indicators: list[str] = []
    packer_name = ""
    confidence = 0.0

    for sec in sections:
        sec_lower = sec.name.strip(".").lower()
        for known_name, known_packer in KNOWN_PACKER_SECTIONS.items():
            if sec_lower == known_name.lower() or sec_lower == known_name.lower().strip("."):
                packer_name = known_packer
                indicators.append(f"Section '{sec.name}' matches known packer signature")
                confidence = max(confidence, 0.8)
                break

    high_entropy_count = sum(1 for s in sections if s.entropy >= HIGH_ENTROPY_THRESHOLD)
    if high_entropy_count > 0:
        indicators.append(
            f"{high_entropy_count} section(s) with high "
            f"entropy (>= {HIGH_ENTROPY_THRESHOLD})"
        )
        if not packer_name:
            confidence = max(confidence, 0.5)

    non_default_sections = [
        s for s in sections
        if s.name.strip("\x00").strip().lower()
        not in {".text", ".rdata", ".data", ".rsrc", ".reloc", ".idata", ".edata", ".bss"}
    ]
    if len(non_default_sections) > 2 and not packer_name:
        indicators.append(f"{len(non_default_sections)} non-standard section(s)")
        confidence = max(confidence, 0.3)

    if import_count > 0 and import_count < MIN_IMPORTS_FOR_PACKER:
        indicators.append(f"Very few imports ({import_count}) - likely packed")
        if packer_name:
            confidence = min(confidence + 0.15, 1.0)
        else:
            confidence = max(confidence, 0.35)

    has_exec_writable = any(s.is_executable and s.is_writable for s in sections)
    if has_exec_writable:
        indicators.append("Section with both write and execute permissions (RWX)")
        confidence = min(confidence + 0.1, 1.0)

    return PackerResult(
        is_packed=confidence >= 0.5,
        packer_name=packer_name or ("Unknown packer" if confidence >= 0.5 else ""),
        confidence=round(confidence, 2),
        indicators=indicators,
    )
