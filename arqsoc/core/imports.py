"""PE/ELF import and export parsing via LIEF for ArqSOC."""

from __future__ import annotations

from pathlib import Path

import lief

from arqsoc.models.scan_result import (
    ArchType,
    BinaryType,
    ExportEntry,
    FileInfo,
    ImportEntry,
    SectionInfo,
)


def _detect_binary_type(binary: lief.Binary) -> BinaryType:
    fmt = binary.format
    if fmt == lief.Binary.FORMATS.PE:
        if binary.header.machine == lief.PE.Header.MACHINE_TYPES.AMD64:
            return BinaryType.PE64
        return BinaryType.PE32
    elif fmt == lief.Binary.FORMATS.ELF:
        if binary.header.machine_type in (
            lief.ELF.ARCH.AARCH64,
            lief.ELF.ARCH.X86_64,
        ):
            return BinaryType.ELF64
        return BinaryType.ELF32
    elif fmt == lief.Binary.FORMATS.MACHO:
        if binary.header.cpu_type == lief.MachO.Header.CPU_TYPES.X86_64:
            return BinaryType.MACHO64
        return BinaryType.MACHO32
    return BinaryType.UNKNOWN


def _detect_arch(binary: lief.Binary) -> ArchType:
    fmt = binary.format
    if fmt == lief.Binary.FORMATS.PE:
        machine = binary.header.machine
        if machine == lief.PE.Header.MACHINE_TYPES.I386:
            return ArchType.X86
        elif machine == lief.PE.Header.MACHINE_TYPES.AMD64:
            return ArchType.X64
        elif machine == lief.PE.Header.MACHINE_TYPES.ARM64:
            return ArchType.ARM64
    elif fmt == lief.Binary.FORMATS.ELF:
        machine = binary.header.machine_type
        if machine == lief.ELF.ARCH.I386:
            return ArchType.X86
        elif machine == lief.ELF.ARCH.X86_64:
            return ArchType.X64
        elif machine == lief.ELF.ARCH.ARM:
            return ArchType.ARM32
        elif machine == lief.ELF.ARCH.AARCH64:
            return ArchType.ARM64
        elif machine in (lief.ELF.ARCH.MIPS, lief.ELF.ARCH.MIPS_RS3_LE):
            return ArchType.MIPS
    elif fmt == lief.Binary.FORMATS.MACHO:
        cpu = binary.header.cpu_type
        if cpu == lief.MachO.Header.CPU_TYPES.X86:
            return ArchType.X86
        elif cpu == lief.MachO.Header.CPU_TYPES.X86_64:
            return ArchType.X64
        elif cpu == lief.MachO.Header.CPU_TYPES.ARM64:
            return ArchType.ARM64
    return ArchType.UNKNOWN


def parse_binary(file_path: Path) -> tuple[lief.Binary | None, str | None]:
    try:
        binary = lief.parse(str(file_path))
        if binary is None:
            return None, f"LIEF could not parse {file_path}"
        return binary, None
    except Exception as e:
        return None, str(e)


def extract_file_info(file_path: Path, binary: lief.Binary | None = None) -> FileInfo:
    if binary is None:
        binary, _ = parse_binary(file_path)

    stat = file_path.stat()
    binary_type = BinaryType.UNKNOWN
    arch = ArchType.UNKNOWN
    compiler = ""
    compile_time = ""
    is_dotnet = False
    subsystem = ""

    if binary is not None:
        binary_type = _detect_binary_type(binary)
        arch = _detect_arch(binary)

        if binary.format == lief.Binary.FORMATS.PE:
            pe = binary
            try:
                compile_time = str(pe.header.time_date_stamps)
            except Exception:
                pass
            try:
                subsystem_val = pe.optional_header.subsystem
                subsystem = str(subsystem_val)
            except Exception:
                pass
            try:
                is_dotnet = pe.has_configuration
            except Exception:
                pass
            try:
                if pe.has_resources:
                    compiler = _detect_compiler_pe(pe)
            except Exception:
                pass

    return FileInfo(
        path=str(file_path),
        name=file_path.name,
        size=stat.st_size,
        binary_type=binary_type,
        architecture=arch,
        compiler=compiler,
        compile_time=compile_time,
        is_dotnet=is_dotnet,
        subsystem=subsystem,
    )


def _detect_compiler_pe(pe: lief.PE.Binary) -> str:
    for func in pe.imported_functions:
        name = func.name.lower() if func.name else ""
        if "msvcr" in name:
            return "MSVC"
        if "libstdc" in name or "libgcc" in name:
            return "GCC/MinGW"

    for s in pe.sections:
        sec_name = s.name.strip("\x00").lower()
        if ".rdata" in sec_name:
            return "MSVC"
        if ".gnu" in sec_name:
            return "GCC/MinGW"

    return "Unknown"


def extract_sections(binary: lief.Binary) -> list[SectionInfo]:
    sections: list[SectionInfo] = []

    if binary.format == lief.Binary.FORMATS.PE:
        for s in binary.sections:
            characteristics = int(s.characteristics)
            sections.append(
                SectionInfo(
                    name=s.name.strip("\x00"),
                    virtual_address=s.virtual_address,
                    virtual_size=s.virtual_size,
                    raw_size=s.sizeof_raw_data,
                    is_readable=True,
                    is_writable=bool(
                        characteristics & int(
                            lief.PE.Section.CHARACTERISTICS.MEM_WRITE
                        )
                    ),
                    is_executable=bool(
                        characteristics & int(
                            lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE
                        )
                    ),
                )
            )
    elif binary.format == lief.Binary.FORMATS.ELF:
        for s in binary.sections:
            sections.append(
                SectionInfo(
                    name=s.name,
                    virtual_address=s.virtual_address,
                    virtual_size=s.size,
                    raw_size=s.size,
                    is_readable=True,
                    is_writable=s.has(lief.ELF.Section.FLAGS.WRITE),
                    is_executable=s.has(lief.ELF.Section.FLAGS.EXECINSTR),
                )
            )
    elif binary.format == lief.Binary.FORMATS.MACHO:
        for s in binary.sections:
            sections.append(
                SectionInfo(
                    name=s.name,
                    virtual_address=s.virtual_address,
                    virtual_size=s.size,
                    raw_size=s.size,
                    is_readable=True,
                )
            )

    return sections


def extract_imports(binary: lief.Binary) -> list[ImportEntry]:
    imports: list[ImportEntry] = []

    if binary.format == lief.Binary.FORMATS.PE:
        for func in binary.imported_functions:
            dll_name = ""
            if hasattr(func, "library") and func.library:
                dll_name = func.library.name.strip("\x00")
            imports.append(
                ImportEntry(
                    name=func.name or f"ord_{func.ordinal}",
                    dll=dll_name,
                    address=func.address if hasattr(func, "address") else 0,
                )
            )
    elif binary.format == lief.Binary.FORMATS.ELF:
        for sym in binary.imported_symbols:
            imports.append(
                ImportEntry(
                    name=sym.name,
                    dll="",
                    address=sym.value if hasattr(sym, "value") else 0,
                )
            )

    return imports


def extract_exports(binary: lief.Binary) -> list[ExportEntry]:
    exports: list[ExportEntry] = []

    if binary.format == lief.Binary.FORMATS.PE:
        for func in binary.exported_functions:
            exports.append(ExportEntry(name=func.name, address=func.address))
    elif binary.format == lief.Binary.FORMATS.ELF:
        for sym in binary.exported_symbols:
            exports.append(ExportEntry(name=sym.name, address=sym.value))

    return exports
