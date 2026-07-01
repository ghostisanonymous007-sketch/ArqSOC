"""Tests for core hashes module."""

from __future__ import annotations

import hashlib
from pathlib import Path

from arqsoc.core.hashes import calculate_hashes, calculate_entropy, hash_bytes


def test_calculate_hashes_system_binary(system_binary: Path) -> None:
    result = calculate_hashes(system_binary)
    assert result.md5
    assert result.sha1
    assert result.sha256
    assert len(result.md5) == 32
    assert len(result.sha1) == 40
    assert len(result.sha256) == 64


def test_calculate_hashes_correctness(tmp_path: Path) -> None:
    data = b"hello world"
    f = tmp_path / "test.bin"
    f.write_bytes(data)
    result = calculate_hashes(f)
    assert result.md5 == hashlib.md5(data).hexdigest()
    assert result.sha1 == hashlib.sha1(data).hexdigest()
    assert result.sha256 == hashlib.sha256(data).hexdigest()


def test_calculate_entropy_uniform() -> None:
    data = bytes(range(256))
    entropy = calculate_entropy(data)
    assert 7.9 < entropy <= 8.0


def test_calculate_entropy_empty() -> None:
    assert calculate_entropy(b"") == 0.0


def test_calculate_entropy_low() -> None:
    data = b"\x00" * 1024
    entropy = calculate_entropy(data)
    assert entropy == 0.0


def test_hash_bytes() -> None:
    data = b"test data"
    assert hash_bytes(data) == hashlib.sha256(data).hexdigest()
