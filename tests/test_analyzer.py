"""Tests for core analyzer module."""

from __future__ import annotations

from pathlib import Path

from arqsoc.core.analyzer import scan_file


def test_scan_file_system_binary(system_binary: Path) -> None:
    result = scan_file(system_binary)
    assert result.file_info.name == system_binary.name
    assert result.file_info.size > 0
    assert result.hashes.sha256
    assert len(result.sections) >= 0
    assert result.threat_level is not None
    assert 0.0 <= result.overall_confidence <= 1.0


def test_scan_file_hashes(system_binary: Path) -> None:
    result = scan_file(system_binary)
    assert len(result.hashes.md5) == 32
    assert len(result.hashes.sha256) == 64


def test_scan_file_indicators(system_binary: Path) -> None:
    result = scan_file(system_binary)
    assert isinstance(result.threat_indicators, list)
    assert isinstance(result.errors, list)
