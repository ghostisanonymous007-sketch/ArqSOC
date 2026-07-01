"""Tests for core entropy module."""

from __future__ import annotations

from pathlib import Path

from arqsoc.core.entropy import (
    analyze_file_entropy,
    compute_block_entropy,
    entropy_to_bar,
    entropy_to_color,
    compute_section_entropy,
)


def test_entropy_to_bar() -> None:
    assert entropy_to_bar(0.0) == "----------"
    assert entropy_to_bar(8.0) == "##########"
    assert entropy_to_bar(4.0) == "#####-----"


def test_entropy_to_color() -> None:
    assert entropy_to_color(0.0) == "dim"
    assert entropy_to_color(3.5) == "green"
    assert entropy_to_color(6.0) == "yellow"
    assert entropy_to_color(7.2) == "red"
    assert entropy_to_color(7.8) == "bold red"


def test_compute_section_entropy() -> None:
    data = b"\x00" * 512 + b"\xff" * 512
    sec = compute_section_entropy(data, ".test", 0, 512)
    assert sec.name == ".test"
    assert sec.entropy == 0.0
    assert not sec.is_suspicious


def test_compute_section_entropy_high() -> None:
    data = bytes(range(256)) * 4
    sec = compute_section_entropy(data, ".test", 0, len(data))
    assert sec.entropy > 7.0
    assert sec.is_suspicious


def test_compute_block_entropy() -> None:
    data = bytes(range(256)) * 4
    blocks = compute_block_entropy(data, block_size=256)
    assert len(blocks) == 4
    for e in blocks:
        assert 0.0 <= e <= 8.0


def test_analyze_file_entropy_system_binary(system_binary: Path) -> None:
    results = analyze_file_entropy(system_binary)
    assert len(results) >= 1
    assert all(s.entropy >= 0.0 for s in results)
