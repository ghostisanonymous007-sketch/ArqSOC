"""Tests for core diff module."""

from __future__ import annotations

from pathlib import Path

from arqsoc.core.diff import compare_binaries


def test_compare_identical_files(tmp_path: Path) -> None:
    data = b"identical content here"
    f1 = tmp_path / "a.bin"
    f2 = tmp_path / "b.bin"
    f1.write_bytes(data)
    f2.write_bytes(data)
    result = compare_binaries(f1, f2)
    assert result.hash_match is True
    assert result.byte_similarity == 1.0


def test_compare_different_files(tmp_path: Path) -> None:
    f1 = tmp_path / "a.bin"
    f2 = tmp_path / "b.bin"
    f1.write_bytes(b"file A content")
    f2.write_bytes(b"file B content")
    result = compare_binaries(f1, f2)
    assert result.hash_match is False
    assert result.byte_similarity < 1.0


def test_compare_system_binary_with_itself(system_binary: Path) -> None:
    result = compare_binaries(system_binary, system_binary)
    assert result.hash_match is True
