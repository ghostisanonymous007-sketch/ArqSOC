"""Tests for core signatures (YARA) module."""

from __future__ import annotations

from pathlib import Path

from arqsoc.core.signatures import load_rules, scan_with_yara


def test_load_rules_default() -> None:
    rules = load_rules()
    rules_dir = __import__("arqsoc").core.signatures.DEFAULT_RULES_DIR
    if rules_dir.exists() and list(rules_dir.glob("*.yar")):
        assert rules is not None
    else:
        assert rules is None


def test_load_rules_nonexistent(tmp_path: Path) -> None:
    result = load_rules(tmp_path / "nonexistent")
    assert result is None


def test_load_rules_empty_dir(tmp_path: Path) -> None:
    empty = tmp_path / "empty_rules"
    empty.mkdir()
    result = load_rules(empty)
    assert result is None


def test_scan_with_yara_no_rules(tmp_path: Path) -> None:
    f = tmp_path / "test.bin"
    f.write_bytes(b"\x4d\x5a" + b"\x00" * 100)
    result = scan_with_yara(f, rules=None)
    assert isinstance(result, list)
