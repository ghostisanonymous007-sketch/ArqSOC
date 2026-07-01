"""PE Rich Header parsing for compiler fingerprinting."""

from __future__ import annotations

from pathlib import Path

import lief

from arqsoc.models.scan_result import RichHeaderEntry, RichHeaderInfo

PRODUCT_ID_NAMES: dict[int, str] = {
    0x0000: "Unknown",
    0x0001: "Import0",
    0x0065: "Import0 (alt)",
    0x0066: "Old Resource",
    0x0073: "Resource",
    0x0078: "Data",
    0x007F: "PCH",
    0x0080: "CvtObj",
    0x0084: "ResObj",
    0x0089: "MLE",
    0x0095: "Linker",
    0x0096: "Linker510",
    0x0099: "Cvtres",
    0x009B: "ImpObj",
    0x009D: "CppObj",
    0x00AF: "ResourceObj",
    0x00B1: "PcheaderObj",
    0x00B2: "PcheaderSig",
    0x00B3: "TLSSectObj",
    0x00B5: "PrecompObj",
    0x00B6: "PrecompObj2",
    0x00B8: "MergeDataObj",
    0x00BC: "Cvtres2",
    0x00BD: "Linker5xx",
    0x00BE: "CVtres2",
    0x00CE: "Linker511",
    0x00CF: "CVTres511",
    0x00D0: "ImpObj2",
    0x00D2: "CppObj2",
    0x00D3: "ExpObj2",
    0x00D5: "Linker60",
    0x00D6: "CVtres60",
    0x00D7: "ImpObj60",
    0x00D8: "LibObj",
    0x00DA: "CppObj60",
    0x00DC: "Linker610",
    0x00DD: "CVTres610",
    0x00DE: "ImpObj610",
    0x00DF: "LibObj610",
    0x00E0: "CppObj610",
    0x00E2: "Linker700",
    0x00E3: "CVTres700",
    0x00E4: "ImpObj700",
    0x00E5: "LibObj700",
    0x00E6: "cppobj700",
    0x00E8: "Linker710",
    0x00E9: "CVTres710",
    0x00EA: "ImpObj710",
    0x00EB: "LibObj710",
    0x00EC: "cppobj710",
    0x00EE: "Linker800",
    0x00EF: "CVTres800",
    0x00F0: "ImpObj800",
    0x00F1: "LibObj800",
    0x00F2: "cppobj800",
    0x00F4: "Linker900",
    0x00F5: "CVTres900",
    0x00F6: "ImpObj900",
    0x00F7: "LibObj900",
    0x00F8: "cppobj900",
    0x00FA: "Linker1000",
    0x00FB: "CVTres1000",
    0x00FC: "ImpObj1000",
    0x00FD: "LibObj1000",
    0x00FE: "cppobj1000",
    0x0100: "Linker1010",
    0x0101: "CVTres1010",
    0x0102: "ImpObj1010",
    0x0103: "LibObj1010",
    0x0104: "cppobj1010",
    0x0106: "Linker1100",
    0x0107: "CVTres1100",
    0x0108: "ImpObj1100",
    0x0109: "LibObj1100",
    0x010A: "cppobj1100",
    0x010C: "Linker1200",
    0x010D: "CVTres1200",
    0x010E: "ImpObj1200",
    0x010F: "LibObj1200",
    0x0110: "cppobj1200",
    0x0112: "Linker1400",
    0x0113: "CVTres1400",
    0x0114: "ImpObj1400",
    0x0115: "LibObj1400",
    0x0116: "cppobj1400",
    0x0118: "Linker1420",
    0x0119: "CVTres1420",
    0x011A: "ImpObj1420",
    0x011B: "LibObj1420",
    0x011C: "cppobj1420",
}


def parse_rich_header(file_path: Path) -> RichHeaderInfo:
    binary: lief.Binary | None = None
    try:
        binary = lief.parse(str(file_path))
    except Exception:
        return RichHeaderInfo()

    if binary is None or binary.format != lief.Binary.FORMATS.PE:
        return RichHeaderInfo()

    try:
        has_rich = binary.has_rich_header
    except Exception:
        return RichHeaderInfo()

    if not has_rich:
        return RichHeaderInfo()

    rich = binary.rich_header
    xor_key = 0
    try:
        xor_key = rich.key
    except Exception:
        pass

    entries: list[RichHeaderEntry] = []
    try:
        for e in rich.entries:
            name = PRODUCT_ID_NAMES.get(e.id, f"0x{e.id:04X}")
            entries.append(
                RichHeaderEntry(
                    product_id=e.id,
                    build_id=e.build_id,
                    count=e.count,
                    name=name,
                )
            )
    except Exception:
        pass

    if not entries:
        return RichHeaderInfo(is_present=True, XOR_key=xor_key)

    sig_parts: list[str] = []
    for e in entries:
        if e.count > 0 and e.name != "Unknown":
            sig_parts.append(f"{e.name}(build={e.build_id},x{e.count})")
    decoded_signature = " | ".join(sig_parts)

    return RichHeaderInfo(
        is_present=True,
        XOR_key=xor_key,
        entries=entries,
        decoded_signature=decoded_signature,
    )
