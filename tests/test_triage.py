"""Tests for core triage module."""

from __future__ import annotations

from pathlib import Path

from arqsoc.core.triage import triage_file, triage_directory


def test_triage_file_system_binary(system_binary: Path) -> None:
    result = triage_file(system_binary)
    assert result.file_path
    assert 0.0 <= result.risk_score <= 1.0
    assert result.sha256
    assert result.file_size > 0


def test_triage_file_priority(system_binary: Path) -> None:
    result = triage_file(system_binary)
    assert result.priority in ("critical", "high", "medium", "low", "normal")


def test_triage_directory(tmp_path: Path) -> None:
    binary_data = b"\x4d\x5a" + b"\x00" * 100
    (tmp_path / "a.bin").write_bytes(binary_data)
    (tmp_path / "b.bin").write_bytes(binary_data)
    results = triage_directory(tmp_path)
    assert len(results) == 2
    assert results[0].risk_score >= results[1].risk_score


def test_triage_directory_empty(tmp_path: Path) -> None:
    results = triage_directory(tmp_path)
    assert results == []
