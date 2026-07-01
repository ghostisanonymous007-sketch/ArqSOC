"""Encoding/decoding utilities for ArqSOC."""

from __future__ import annotations

import base64
import codecs


def rot13(text: str) -> str:
    return codecs.decode(text, "rot_13")


def hex_decode(hex_str: str) -> bytes:
    clean = hex_str.replace(" ", "").replace("\\x", "").replace("0x", "")
    if len(clean) % 2 != 0:
        clean = "0" + clean
    return bytes.fromhex(clean)


def hex_encode(data: bytes) -> str:
    return data.hex()


def base64_decode(b64_str: str) -> bytes:
    padded = b64_str + "=" * (4 - len(b64_str) % 4) if len(b64_str) % 4 else b64_str
    return base64.b64decode(padded)


def base64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def xor_decode(data: bytes, key: int | bytes) -> bytes:
    if isinstance(key, int):
        return bytes(b ^ key for b in data)
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(data))


def caesar_decode(text: str, shift: int) -> str:
    result: list[str] = []
    for c in text:
        if "A" <= c <= "Z":
            result.append(chr((ord(c) - ord("A") - shift) % 26 + ord("A")))
        elif "a" <= c <= "z":
            result.append(chr((ord(c) - ord("a") - shift) % 26 + ord("a")))
        else:
            result.append(c)
    return "".join(result)


def try_decode_multi(data: bytes) -> dict[str, str | bytes | None]:
    results: dict[str, str | bytes | None] = {}

    try:
        results["base64"] = base64_decode(data.decode("ascii", errors="ignore")).decode("utf-8", errors="replace")
    except Exception:
        results["base64"] = None

    for key in (0xFF, 0xAA, 0x55, 0x42, 0x13, 0x37):
        decoded = xor_decode(data, key)
        printable = sum(1 for b in decoded if 32 <= b < 127) / max(len(decoded), 1)
        if printable > 0.8:
            results[f"xor_{key:02x}"] = decoded.decode("ascii", errors="replace")
        else:
            results[f"xor_{key:02x}"] = None

    results["rot13"] = rot13(data.decode("ascii", errors="ignore"))
    results["hex"] = hex_encode(data)

    return results
