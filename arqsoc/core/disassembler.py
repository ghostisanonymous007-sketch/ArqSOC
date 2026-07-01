"""Multi-architecture disassembly engine using Capstone for ArqSOC."""

from __future__ import annotations

from pathlib import Path

from arqsoc.models.scan_result import ArchType


def _get_capstone_arch(arch: ArchType) -> tuple[int, int]:
    try:
        from capstone import (
            CS_ARCH_ARM,
            CS_ARCH_ARM64,
            CS_ARCH_MIPS,
            CS_ARCH_X86,
            CS_MODE_32,
            CS_MODE_64,
            CS_MODE_ARM,
            CS_MODE_LITTLE_ENDIAN,
            CS_MODE_MIPS32,
        )
    except ImportError:
        raise ImportError("capstone is required for disassembly: pip install capstone")

    mapping = {
        ArchType.X86: (CS_ARCH_X86, CS_MODE_32),
        ArchType.X64: (CS_ARCH_X86, CS_MODE_64),
        ArchType.ARM32: (CS_ARCH_ARM, CS_MODE_ARM),
        ArchType.ARM64: (CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN),
        ArchType.MIPS: (CS_ARCH_MIPS, CS_MODE_MIPS32),
    }
    if arch not in mapping:
        raise ValueError(f"Unsupported architecture: {arch}")
    return mapping[arch]


def disassemble_bytes(
    data: bytes,
    arch: ArchType = ArchType.X64,
    base_addr: int = 0,
    offset: int = 0,
    count: int = 0,
) -> list[tuple[int, int, str, str]]:
    from capstone import Cs

    cs_arch, cs_mode = _get_capstone_arch(arch)
    md = Cs(cs_arch, cs_mode)
    md.detail = False

    code = data[offset:]
    results: list[tuple[int, int, str, str]] = []

    for i, insn in enumerate(md.disasm(code, base_addr + offset)):
        results.append((insn.address, insn.size, insn.mnemonic, insn.op_str))
        if count and i + 1 >= count:
            break

    return results


def disassemble_file(
    file_path: Path,
    arch: ArchType | None = None,
    section_name: str | None = None,
    start_addr: int | None = None,
    count: int = 200,
) -> list[tuple[int, int, str, str]]:
    data = file_path.read_bytes()

    detected_arch = arch or ArchType.X64

    offset = 0
    base_addr = 0

    try:
        import lief

        binary = lief.parse(str(file_path))
        if binary is not None:
            if arch is None:
                from arqsoc.core.imports import _detect_arch

                detected_arch = _detect_arch(binary)

            if section_name:
                for s in binary.sections:
                    if s.name.strip("\x00").lower() == section_name.lower():
                        offset = s.offset if hasattr(s, "offset") else s.virtual_address
                        base_addr = s.virtual_address
                        data = file_path.read_bytes()
                        break
            elif start_addr is not None:
                for s in binary.sections:
                    sec_va = s.virtual_address
                    sec_end = sec_va + (s.virtual_size if hasattr(s, "virtual_size") else s.size)
                    if sec_va <= start_addr < sec_end:
                        offset = start_addr - sec_va + (s.offset if hasattr(s, "offset") else 0)
                        base_addr = start_addr
                        break
    except Exception:
        pass

    return disassemble_bytes(data, detected_arch, base_addr, offset, count)


def format_instruction(addr: int, size: int, mnemonic: str, op_str: str) -> str:
    return f"0x{addr:08x}  {mnemonic:<8s} {op_str}"
