"""Tests for core strings module."""

from __future__ import annotations

from pathlib import Path

from arqsoc.core.strings import analyze_strings, classify_string, try_decode_base64, try_decode_xor
from arqsoc.models.scan_result import StringClassification


def test_classify_url() -> None:
    assert classify_string("https://example.com/payload") == StringClassification.URL


def test_classify_ip() -> None:
    assert classify_string("192.168.1.1") == StringClassification.IP


def test_classify_email() -> None:
    assert classify_string("user@example.com") == StringClassification.EMAIL


def test_classify_registry() -> None:
    assert classify_string("HKEY_LOCAL_MACHINE\\Software\\Test") == StringClassification.REGISTRY


def test_classify_mutex() -> None:
    assert classify_string("Global\\{ABC12345-DEFG-6789}") == StringClassification.MUTEX


def test_classify_other() -> None:
    assert classify_string("Hello World") == StringClassification.OTHER


def test_try_decode_base64() -> None:
    import base64
    encoded = base64.b64encode(b"hello world test string here").decode()
    result = try_decode_base64(encoded)
    assert result is not None
    assert "hello" in result


def test_try_decode_base64_invalid() -> None:
    result = try_decode_base64("not_base64_at_all_!!!")
    assert result is None


def test_try_decode_xor() -> None:
    plain = "Hello World Test"
    encoded = "".join(chr(ord(c) ^ 0xFF) for c in plain)
    result = try_decode_xor(encoded, keys=[0xFF])
    assert result is not None
    assert "Hello" in result


def test_analyze_strings_system_binary(system_binary: Path) -> None:
    results = analyze_strings(system_binary)
    assert isinstance(results, list)
    for s in results:
        assert s.value
        assert isinstance(s.classification, StringClassification)


def test_analyze_strings_min_length(tmp_path: Path) -> None:
    f = tmp_path / "test.bin"
    f.write_text("ab cd ef gh ij kl mn op qr st uv wx yz", encoding="ascii")
    results = analyze_strings(f, min_length=4)
    assert len(results) >= 1
