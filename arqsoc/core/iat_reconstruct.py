"""IAT reconstruction - detect dynamic API resolution via GetProcAddress/LoadLibrary."""

from __future__ import annotations

import re
from pathlib import Path

from arqsoc.models.scan_result import IATEntry

DYNAMIC_RESOLVE_APIS = {
    "getprocaddress": "GetProcAddress",
    "loadlibrarya": "LoadLibraryA",
    "loadlibraryw": "LoadLibraryW",
    "loadlibraryexa": "LoadLibraryExA",
    "loadlibraryexw": "LoadLibraryExW",
    "getmodulehandlea": "GetModuleHandleA",
    "getmodulehandlew": "GetModuleHandleW",
    "ldrgetprocedureaddress": "LdrGetProcedureAddress",
    "ldrloaddll": "LdrLoadDll",
}

KNOWN_DLLS = {
    "kernel32", "ntdll", "user32", "advapi32", "gdi32",
    "ws2_32", "wininet", "winhttp", "crypt32", "ole32",
    "oleaut32", "shell32", "shlwapi", "urlmon", "msvcrt",
    "msvcp", "mpr", "wintrust", "psapi", "dbghelp",
}

HIGH_RISK_APIS = {
    "virtualalloc": "VirtualAlloc",
    "virtualallocex": "VirtualAllocEx",
    "virtualprotect": "VirtualProtect",
    "virtualprotectex": "VirtualProtectEx",
    "writeprocessmemory": "WriteProcessMemory",
    "createremotethread": "CreateRemoteThread",
    "createremotethreadex": "CreateRemoteThreadEx",
    "ntcreatefile": "NtCreateFile",
    "ntwritefile": "NtWriteFile",
    "ntcreatethread": "NtCreateThread",
    "ntcreatethreadex": "NtCreateThreadEx",
    "ntunmapviewofsection": "NtUnmapViewOfSection",
    "ntmapviewofsection": "NtMapViewOfSection",
    "rtlinitializestream": "RtlInitializeStream",
}


def detect_dynamic_imports(file_path: Path) -> list[IATEntry]:
    try:
        data = file_path.read_bytes()
    except OSError:
        return []

    entries: list[IATEntry] = []
    seen: set[str] = set()
    text = data.decode("ascii", errors="ignore")

    for dll_name in KNOWN_DLLS:
        pattern = re.compile(re.escape(dll_name) + r"\.(?:dll|DLL)", re.IGNORECASE)
        for m in pattern.finditer(text):
            matched_dll = m.group(0)
            key = f"dll:{matched_dll.lower()}"
            if key not in seen:
                seen.add(key)
                entries.append(
                    IATEntry(
                        api_name=matched_dll,
                        dll_name=matched_dll,
                        confidence=0.4,
                        source="string_ref",
                    )
                )

    for api_lower, api_proper in HIGH_RISK_APIS.items():
        for m in re.finditer(re.escape(api_lower), text, re.IGNORECASE):
            key = f"api:{api_lower}"
            if key not in seen:
                seen.add(key)
                entries.append(
                    IATEntry(
                        api_name=api_proper,
                        dll_name="",
                        confidence=0.8,
                        source="dynamic_string",
                    )
                )

    _detect_getprocaddress_patterns(text, entries, seen)

    return entries


def _detect_getprocaddress_patterns(
    text: str, entries: list[IATEntry], seen: set[str],
) -> None:
    gpa_positions: list[int] = []
    for m in re.finditer(r"getprocaddress", text, re.IGNORECASE):
        gpa_positions.append(m.start())

    if not gpa_positions:
        return

    for pos in gpa_positions:
        window = text[max(0, pos - 200) : pos + 200]
        for dll_name in KNOWN_DLLS:
            if dll_name.lower() in window.lower():
                key = f"gpa_ctx:{dll_name}"
                if key not in seen:
                    seen.add(key)
                    entries.append(
                        IATEntry(
                            api_name=f"GetProcAddress->{dll_name}",
                            dll_name=f"{dll_name}.dll",
                            confidence=0.6,
                            source="gpa_context",
                        )
                    )
