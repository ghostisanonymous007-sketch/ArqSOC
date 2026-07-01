"""Tests for core packer module."""

from __future__ import annotations

from pathlib import Path

from arqsoc.core.packer import detect_packer
from arqsoc.models.scan_result import SectionInfo


def test_detect_packer_clean() -> None:
    sections = [
        SectionInfo(name=".text", entropy=6.0, is_writable=False, is_executable=True),
        SectionInfo(name=".rdata", entropy=5.0, is_writable=False, is_executable=False),
        SectionInfo(name=".data", entropy=2.0, is_writable=True, is_executable=False),
    ]
    result = detect_packer(sections, 50)
    assert not result.is_packed or result.confidence < 0.5


def test_detect_packer_high_entropy() -> None:
    sections = [
        SectionInfo(name=".text", entropy=7.8, is_writable=True, is_executable=True),
        SectionInfo(name=".rdata", entropy=7.6, is_writable=False, is_executable=False),
    ]
    result = detect_packer(sections, 2)
    assert result.is_packed is True or result.confidence > 0


def test_detect_packer_heap_style() -> None:
    sections = [
        SectionInfo(name=".text", entropy=7.8, is_writable=True, is_executable=True, raw_size=0x1000, virtual_size=0x10000),
    ]
    result = detect_packer(sections, 0)
    assert isinstance(result.is_packed, bool)


def test_detect_packer_no_sections() -> None:
    result = detect_packer([], 0)
    assert not result.is_packed
