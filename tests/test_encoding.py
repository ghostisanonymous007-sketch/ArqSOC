"""Tests for utils encoding module."""

from __future__ import annotations

from arqsoc.utils.encoding import (
    rot13,
    hex_decode,
    hex_encode,
    base64_decode,
    base64_encode,
    xor_decode,
    caesar_decode,
    try_decode_multi,
)


def test_rot13() -> None:
    assert rot13("Hello") == "Uryyb"
    assert rot13("Uryyb") == "Hello"


def test_hex_roundtrip() -> None:
    data = b"test data"
    encoded = hex_encode(data)
    decoded = hex_decode(encoded)
    assert decoded == data


def test_hex_decode_with_prefix() -> None:
    result = hex_decode("\\x41\\x42\\x43")
    assert result == b"ABC"


def test_base64_roundtrip() -> None:
    data = b"hello world"
    encoded = base64_encode(data)
    decoded = base64_decode(encoded)
    assert decoded == data


def test_xor_decode_int_key() -> None:
    data = b"test"
    encoded = xor_decode(data, 0xFF)
    decoded = xor_decode(encoded, 0xFF)
    assert decoded == data


def test_xor_decode_bytes_key() -> None:
    data = b"test data here"
    key = b"KEY"
    encoded = xor_decode(data, key)
    decoded = xor_decode(encoded, key)
    assert decoded == data


def test_caesar_decode() -> None:
    assert caesar_decode("Khoor", 3) == "Hello"
    assert caesar_decode("Hello", 0) == "Hello"


def test_try_decode_multi() -> None:
    data = b"dGVzdA=="
    results = try_decode_multi(data)
    assert isinstance(results, dict)
    assert "base64" in results
    assert "rot13" in results
