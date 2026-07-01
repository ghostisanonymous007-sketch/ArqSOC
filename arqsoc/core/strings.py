"""Smart string extraction and classification for ArqSOC."""

from __future__ import annotations

import base64
import re
from pathlib import Path

from arqsoc.models.scan_result import ClassifiedString, StringClassification

MIN_STRING_LEN = 4
MAX_STRING_LEN = 4096

ASCII_PATTERN = re.compile(rb"[\x20-\x7e]{" + str(MIN_STRING_LEN).encode() + rb",}")
WIDE_PATTERN = re.compile(rb"(?:[\x20-\x7e]\x00){" + str(MIN_STRING_LEN).encode() + rb",}")

URL_PATTERN = re.compile(r"https?://[^\s<>\"']+")
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
REGISTRY_PATTERN = re.compile(r"[Hh][Kk][Ee][Yy]_[A-Za-z_\\]+")
FILE_PATH_PATTERN = re.compile(r"[A-Za-z]:\\[^\s\"'<>|*?]+|[A-Za-z]:/[^\s\"'<>|*?]+")
MUTEX_PATTERN = re.compile(r"(?:Global|Local)\\{?[A-Fa-f0-9-]+}?")
BASE64_PATTERN = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")

C2_KEYWORDS = {
    "c2", "cnc", "beacon", "command", "control", "exfil", "callback",
    "post", "shell", "reverse", "bind", "connect", "socket", "botnet",
}

CRYPTO_KEYWORDS = {
    "aes", "rsa", "des", "chacha", "salsa", "rc4", "blowfish",
    "encrypt", "decrypt", "cipher", "key", "iv", "nonce",
}

API_PATTERNS = [
    re.compile(r"(?:Create|Open|Read|Write|Delete|Reg|Virtual|Heap|Nt|Zw|Rtl)\w+", re.IGNORECASE),
]


def extract_strings(data: bytes, min_length: int = MIN_STRING_LEN) -> list[tuple[int, str, bool]]:
    results: list[tuple[int, str, bool]] = []
    seen: set[str] = set()

    for match in ASCII_PATTERN.finditer(data):
        value = match.group().decode("ascii", errors="ignore")
        if len(value) >= min_length and value not in seen:
            seen.add(value)
            results.append((match.start(), value, False))

    for match in WIDE_PATTERN.finditer(data):
        try:
            raw = match.group()
            value = raw.decode("utf-16-le", errors="ignore").rstrip("\x00")
            if len(value) >= min_length and value not in seen:
                seen.add(value)
                results.append((match.start(), value, True))
        except Exception:
            continue

    return results


def try_decode_base64(s: str) -> str | None:
    try:
        decoded = base64.b64decode(s, validate=True)
        text = decoded.decode("utf-8", errors="strict")
        if all(32 <= ord(c) < 127 or c in "\n\r\t" for c in text):
            return text
    except Exception:
        pass
    return None


def try_decode_xor(s: str, keys: list[int] | None = None) -> str | None:
    if keys is None:
        keys = [0xFF, 0xAA, 0x55, 0x42, 0x13, 0x37]

    for key in keys:
        decoded = "".join(chr(ord(c) ^ key) for c in s)
        printable_ratio = sum(1 for c in decoded if 32 <= ord(c) < 127) / max(len(decoded), 1)
        if printable_ratio > 0.9 and len(decoded) > 3:
            return decoded
    return None


def classify_string(value: str) -> StringClassification:
    lower = value.lower()

    if URL_PATTERN.search(value):
        return StringClassification.URL
    if IP_PATTERN.search(value):
        return StringClassification.IP
    if EMAIL_PATTERN.search(value):
        return StringClassification.EMAIL
    if REGISTRY_PATTERN.search(value):
        return StringClassification.REGISTRY
    if MUTEX_PATTERN.search(value):
        return StringClassification.MUTEX
    if FILE_PATH_PATTERN.search(value):
        return StringClassification.FILE_PATH
    if any(kw in lower for kw in C2_KEYWORDS) and URL_PATTERN.search(value):
        return StringClassification.C2
    if any(kw in lower for kw in CRYPTO_KEYWORDS):
        return StringClassification.CRYPTO

    for pattern in API_PATTERNS:
        if pattern.fullmatch(value):
            return StringClassification.API

    if BASE64_PATTERN.fullmatch(value):
        return StringClassification.BASE64

    return StringClassification.OTHER


def analyze_strings(file_path: Path, min_length: int = MIN_STRING_LEN) -> list[ClassifiedString]:
    data = file_path.read_bytes()
    raw_strings = extract_strings(data, min_length)

    results: list[ClassifiedString] = []
    for offset, value, is_wide in raw_strings:
        if len(value) > MAX_STRING_LEN:
            continue

        classification = classify_string(value)

        decoded_value: str | None = None
        is_obfuscated = False

        if classification == StringClassification.BASE64:
            decoded = try_decode_base64(value)
            if decoded:
                decoded_value = decoded
                is_obfuscated = True

        results.append(
            ClassifiedString(
                value=value,
                classification=classification,
                offset=offset,
                is_obfuscated=is_obfuscated,
                decoded_value=decoded_value,
            )
        )

    return results
