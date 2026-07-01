"""Tests for utils hexdump module."""

from __future__ import annotations

from arqsoc.utils.hexdump import hexdump, format_hexdump, hexdump_search


def test_hexdump_basic() -> None:
    data = b"Hello, World!"
    lines = hexdump(data)
    assert len(lines) >= 1
    assert "48656c6c" in lines[0] or "48 65 6c 6c" in lines[0]


def test_hexdump_offset() -> None:
    data = b"\x00" * 32 + b"AAAA"
    lines = hexdump(data, offset=16, length=20)
    assert len(lines) >= 1


def test_format_hexdump() -> None:
    data = b"Test data for hex dump"
    result = format_hexdump(data)
    assert isinstance(result, str)
    assert "\n" in result or len(result) > 0


def test_hexdump_search() -> None:
    data = b"\x00" * 100 + b"FINDME" + b"\x00" * 100
    results = hexdump_search(data, b"FINDME")
    assert len(results) >= 1
    assert any("Match" in r for r in results)


def test_hexdump_search_not_found() -> None:
    data = b"\x00" * 100
    results = hexdump_search(data, b"NOTHERE")
    assert len(results) == 0
