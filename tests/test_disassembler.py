"""Tests for core disassembler module."""

from __future__ import annotations

from pathlib import Path

from arqsoc.core.disassembler import disassemble_bytes, format_instruction
from arqsoc.models.scan_result import ArchType


def test_disassemble_bytes_x64() -> None:
    code = b"\x90\x90\xc3"
    result = disassemble_bytes(code, ArchType.X64, base_addr=0)
    assert len(result) >= 1
    for addr, size, mnemonic, op_str in result:
        assert isinstance(addr, int)
        assert isinstance(size, int)
        assert isinstance(mnemonic, str)


def test_disassemble_bytes_x86() -> None:
    code = b"\x90\x90\xc3"
    result = disassemble_bytes(code, ArchType.X86, base_addr=0x1000)
    assert len(result) >= 1


def test_disassemble_bytes_with_count() -> None:
    code = b"\x90" * 100
    result = disassemble_bytes(code, ArchType.X64, count=5)
    assert len(result) <= 5


def test_disassemble_bytes_invalid_arch() -> None:
    try:
        disassemble_bytes(b"\x90", ArchType.UNKNOWN)
        assert False, "Should have raised"
    except (ValueError, ImportError):
        pass


def test_format_instruction() -> None:
    line = format_instruction(0x401000, 2, "nop", "")
    assert "401000" in line
    assert "nop" in line


def test_disassemble_file_system_binary(system_binary: Path) -> None:
    from arqsoc.core.disassembler import disassemble_file
    result = disassemble_file(system_binary, count=10)
    assert isinstance(result, list)
