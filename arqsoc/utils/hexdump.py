"""Hex dump utility for ArqSOC - ASCII-safe terminal output."""

from __future__ import annotations

HEXDUMP_WIDTH = 16
PRINTABLE_RANGE = range(0x20, 0x7F)


def hexdump(data: bytes, offset: int = 0, length: int = 0, width: int = HEXDUMP_WIDTH) -> list[str]:
    if length > 0:
        data = data[offset:offset + length]
    else:
        data = data[offset:]

    lines: list[str] = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hex_parts: list[str] = []
        for j in range(width):
            if j < len(chunk):
                hex_parts.append(f"{chunk[j]:02x}")
            else:
                hex_parts.append("  ")
            if j == width // 2 - 1:
                hex_parts.append("")

        ascii_parts: list[str] = []
        for byte in chunk:
            if byte in PRINTABLE_RANGE:
                ascii_parts.append(chr(byte))
            else:
                ascii_parts.append(".")

        addr = offset + i
        hex_str = " ".join(hex_parts)
        ascii_str = "".join(ascii_parts)
        lines.append(f"{addr:08x}  {hex_str}  |{ascii_str}|")

    return lines


def format_hexdump(data: bytes, offset: int = 0, length: int = 0) -> str:
    return "\n".join(hexdump(data, offset, length))


def hexdump_search(data: bytes, pattern: bytes, context: int = 32) -> list[str]:
    results: list[str] = []
    pos = 0
    while True:
        idx = data.find(pattern, pos)
        if idx == -1:
            break
        start = max(0, idx - context)
        end = min(len(data), idx + len(pattern) + context)
        results.append(f"--- Match at 0x{idx:08x} ---")
        results.extend(hexdump(data, start, end - start))
        pos = idx + len(pattern)
    return results
