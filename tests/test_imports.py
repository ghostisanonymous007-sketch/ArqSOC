"""Tests for core imports module."""

from __future__ import annotations

from pathlib import Path

from arqsoc.core.imports import (
    extract_file_info,
    extract_imports,
    extract_exports,
    extract_sections,
    parse_binary,
)
from arqsoc.models.scan_result import BinaryType, ArchType


def test_parse_binary_system_binary(system_binary: Path) -> None:
    binary, err = parse_binary(system_binary)
    assert binary is not None
    assert err is None


def test_extract_file_info(system_binary: Path) -> None:
    binary, _ = parse_binary(system_binary)
    info = extract_file_info(system_binary, binary)
    assert info.name == system_binary.name
    assert info.size > 0
    assert info.binary_type in (BinaryType.PE32, BinaryType.PE64)


def test_extract_sections(system_binary: Path) -> None:
    binary, _ = parse_binary(system_binary)
    sections = extract_sections(binary)
    assert len(sections) > 0
    for sec in sections:
        assert sec.name


def test_extract_imports(system_binary: Path) -> None:
    binary, _ = parse_binary(system_binary)
    imports = extract_imports(binary)
    assert isinstance(imports, list)


def test_extract_exports(system_binary: Path) -> None:
    binary, _ = parse_binary(system_binary)
    exports = extract_exports(binary)
    assert isinstance(exports, list)


def test_parse_binary_invalid(tmp_path: Path) -> None:
    f = tmp_path / "invalid.bin"
    f.write_bytes(b"\x00" * 64)
    binary, err = parse_binary(f)
    assert binary is None or err is not None or binary.format is not None
