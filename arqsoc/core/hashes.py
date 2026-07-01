"""Hash calculation module for ArqSOC."""

from __future__ import annotations

import hashlib
from pathlib import Path

from arqsoc.models.scan_result import HashResult


def calculate_hashes(file_path: Path) -> HashResult:
    data = file_path.read_bytes()

    md5 = hashlib.md5(data).hexdigest()
    sha1 = hashlib.sha1(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()

    ssdeep_hash: str | None = None
    try:
        import ssdeep as _ssdeep

        ssdeep_hash = _ssdeep.hash(data)
    except ImportError:
        pass

    imphash: str | None = None
    try:
        import lief

        binary = lief.parse(str(file_path))
        if binary is not None and hasattr(binary, "get_imphash"):
            try:
                imphash = binary.get_imphash()
            except Exception:
                pass
    except Exception:
        pass

    return HashResult(
        md5=md5,
        sha1=sha1,
        sha256=sha256,
        ssdeep=ssdeep_hash,
        imphash=imphash,
    )


def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0

    freq: dict[int, int] = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1

    import math

    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)

    return entropy


def hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
