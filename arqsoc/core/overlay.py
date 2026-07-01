"""PE overlay detection - appended data after the last section."""

from __future__ import annotations

from pathlib import Path

import lief

from arqsoc.core.hashes import calculate_entropy
from arqsoc.models.scan_result import OverlayInfo

MAGIC_SIGNATURES: dict[bytes, str] = {
    b"\x50\x4b\x03\x04": "ZIP/APK/JAR",
    b"\x52\x61\x72\x21": "RAR",
    b"\x1f\x8b": "GZIP",
    b"\x25\x50\x44\x46": "PDF",
    b"\x89\x50\x4e\x47": "PNG",
    b"\xff\xd8\xff": "JPEG",
    b"\x49\x44\x33": "MP3 (ID3v2)",
    b"\x4d\x5a": "PE (nested)",
    b"\x7f\x45\x4c\x46": "ELF (nested)",
    b"\x42\x5a\x68": "BZIP2",
    b"\x5d\x00\x00": "LZMA",
    b"\x04\x22\x4d\x18": "LZ4",
    b"\x28\xb5\x2f\xfd": "ZSTD",
    b"\x37\x7a\xbc\xaf": "7Z",
    b"\x27\x05\x19\x80": "InstallShield",
}


def detect_overlay(file_path: Path) -> OverlayInfo:
    binary: lief.Binary | None = None
    try:
        binary = lief.parse(str(file_path))
    except Exception:
        return OverlayInfo()

    if binary is None or binary.format != lief.Binary.FORMATS.PE:
        return OverlayInfo()

    if not binary.sections:
        return OverlayInfo()

    overlay_raw_offset = binary.optional_header.sizeof_headers
    for s in binary.sections:
        end = s.offset + s.sizeof_raw_data
        if end > overlay_raw_offset:
            overlay_raw_offset = end

    file_size = file_path.stat().st_size

    if overlay_raw_offset >= file_size:
        return OverlayInfo()

    overlay_size = file_size - overlay_raw_offset
    if overlay_size == 0:
        return OverlayInfo()

    data = file_path.read_bytes()
    overlay_data = data[overlay_raw_offset:]
    entropy = calculate_entropy(overlay_data[:65536])

    magic = ""
    for sig, name in MAGIC_SIGNATURES.items():
        if overlay_data[: len(sig)] == sig:
            magic = name
            break

    if not magic:
        if entropy > 7.5:
            magic = "Encrypted/Compressed (high entropy)"
        elif entropy < 1.0:
            magic = "Mostly null/padding"

    return OverlayInfo(
        has_overlay=True,
        offset=overlay_raw_offset,
        size=overlay_size,
        entropy=entropy,
        magic=magic,
    )
