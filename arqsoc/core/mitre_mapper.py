"""MITRE ATT&CK mapping - map findings to TTPs for ArqSOC."""

from __future__ import annotations

from arqsoc.models.incident import MitreMapping
from arqsoc.models.scan_result import ImportEntry, StringClassification

API_TECHNIQUE_MAP: dict[str, tuple[str, str, str]] = {
    "virtualallocex": ("T1055.012", "Process Injection", "VirtualAllocEx - allocate memory in remote process"),
    "writeprocessmemory": ("T1055.012", "Process Injection", "WriteProcessMemory - write to remote process memory"),
    "createremotethread": ("T1055.012", "Process Injection", "CreateRemoteThread - execute code in remote process"),
    "virtualprotectex": ("T1055.012", "Process Injection", "VirtualProtectEx - change memory protection in remote process"),
    "virturalloc": ("T1055.012", "Process Injection", "VirtualAlloc - allocate executable memory"),
    "virtualprotect": ("T1055.012", "Process Injection", "VirtualProtect - change memory protection"),
    "openprocess": ("T1057", "Process Discovery", "OpenProcess - open handle to another process"),
    "createremotethreadex": ("T1055.012", "Process Injection", "CreateRemoteThreadEx - execute code in remote process"),
    "ntmapviewofsection": ("T1055.012", "Process Injection", "NtMapViewOfSection - inject section into remote process"),
    "ntunmapviewofsection": ("T1055.012", "Process Injection", "NtUnmapViewOfSection - unmap section in remote process"),
    "getprocaddress": ("T1106", "Native API", "GetProcAddress - dynamically resolve API address"),
    "loadlibrarya": ("T1106", "Native API", "LoadLibraryA - dynamically load DLL"),
    "loadlibraryw": ("T1106", "Native API", "LoadLibraryW - dynamically load DLL (wide)"),
    "regsetvalueexa": ("T1112", "Modify Registry", "RegSetValueExA - modify registry value"),
    "regcreatekeyexa": ("T1112", "Modify Registry", "RegCreateKeyExA - create registry key"),
    "internetopena": ("T1071.001", "Application Layer Protocol: Web", "InternetOpenA - initialize internet connection"),
    "httpopenrequesta": ("T1071.001", "Application Layer Protocol: Web", "HttpOpenRequestA - open HTTP request"),
    "internetconnecta": ("T1071.001", "Application Layer Protocol: Web", "InternetConnectA - connect to remote server"),
    "socket": ("T1071", "Application Layer Protocol", "socket - create network socket"),
    "connect": ("T1071", "Application Layer Protocol", "connect - establish network connection"),
    "wsastartup": ("T1071", "Application Layer Protocol", "WSAStartup - initialize Winsock"),
    "createprocessa": ("T1106", "Native API", "CreateProcessA - create new process"),
    "createprocessw": ("T1106", "Native API", "CreateProcessW - create new process (wide)"),
}

STRING_TECHNIQUE_MAP: dict[StringClassification, tuple[str, str, str]] = {
    StringClassification.URL: ("T1071.001", "Application Layer Protocol: Web", "URL found - HTTP/HTTPS communication"),
    StringClassification.IP: ("T1071", "Application Layer Protocol", "IP address - network communication"),
    StringClassification.EMAIL: ("T1566", "Phishing", "Email address - potential phishing vector"),
    StringClassification.REGISTRY: ("T1112", "Modify Registry", "Registry key - registry manipulation"),
    StringClassification.MUTEX: ("T1055", "Process Injection", "Mutex - process synchronization/injection marker"),
    StringClassification.C2: ("T1071", "Application Layer Protocol", "C2 indicator - command and control communication"),
    StringClassification.CRYPTO: ("T1027", "Obfuscated Files", "Crypto reference - encryption/decryption"),
}

KEYWORD_TECHNIQUE_MAP: dict[str, tuple[str, str, str]] = {
    "scheduled task": ("T1053.005", "Scheduled Task/Job: Scheduled Task", "Scheduled task reference"),
    "startup": ("T1547.001", "Boot or Logon Autostart: Registry Run Keys", "Startup reference - persistence"),
    "autorun": ("T1547.001", "Boot or Logon Autostart: Registry Run Keys", "Autorun reference - persistence"),
    "service": ("T1543.003", "Create or Modify System Process: Windows Service", "Service reference - persistence"),
    "persistence": ("T1053", "Scheduled Task/Job", "Persistence keyword detected"),
    "exfil": ("T1041", "Exfiltration Over C2 Channel", "Exfiltration reference"),
    "screenshot": ("T1113", "Screen Capture", "Screenshot capability"),
    "keylog": ("T1056.001", "Input Capture: Keylogging", "Keylogging capability"),
    "credential": ("T1003", "OS Credential Dumping", "Credential access reference"),
    "password": ("T1110", "Brute Force", "Password reference"),
    "lateral": ("T1021", "Remote Services", "Lateral movement reference"),
    "dump": ("T1003", "OS Credential Dumping", "Memory dump reference"),
    "inject": ("T1055", "Process Injection", "Injection reference"),
    "hook": ("T1056", "Input Capture", "API hooking reference"),
    "rootkit": ("T1014", "Rootkit", "Rootkit reference"),
    "backdoor": ("T1133", "External Remote Services", "Backdoor reference"),
}

SECTION_TECHNIQUE_MAP: dict[str, tuple[str, str, str]] = {
    "rwx_section": ("T1055", "Process Injection", "RWX memory section - shellcode execution"),
    "overlay": ("T1027", "Obfuscated Files", "PE overlay - appended payload"),
    "tls_callback": ("T1055", "Process Injection", "TLS callback - code before entry point"),
}


def map_imports_to_mitre(imports: list[ImportEntry]) -> list[MitreMapping]:
    mappings: list[MitreMapping] = []
    seen_techniques: set[str] = set()

    for imp in imports:
        lower = imp.name.lower().replace("_", "").replace(".", "")
        for api_key, (tid, tactic, desc) in API_TECHNIQUE_MAP.items():
            if lower == api_key or api_key in lower:
                if tid not in seen_techniques:
                    seen_techniques.add(tid)
                    mappings.append(MitreMapping(
                        technique_id=tid, tactic=tactic,
                        name=_technique_name(tid),
                        description=desc,
                        evidence=f"{imp.name} ({imp.dll})",
                    ))
                break

    return mappings


def map_strings_to_mitre(strings: list) -> list[MitreMapping]:
    mappings: list[MitreMapping] = []
    seen_techniques: set[str] = set()

    for s in strings:
        cls = s.classification if hasattr(s, "classification") else None
        if cls and cls in STRING_TECHNIQUE_MAP:
            tid, tactic, desc = STRING_TECHNIQUE_MAP[cls]
            if tid not in seen_techniques:
                seen_techniques.add(tid)
                mappings.append(MitreMapping(
                    technique_id=tid, tactic=tactic,
                    name=_technique_name(tid),
                    description=desc,
                    evidence=s.value[:80],
                ))

        lower = s.value.lower() if hasattr(s, "value") else ""
        for kw, (tid, tactic, desc) in KEYWORD_TECHNIQUE_MAP.items():
            if kw in lower and tid not in seen_techniques:
                seen_techniques.add(tid)
                mappings.append(MitreMapping(
                    technique_id=tid, tactic=tactic,
                    name=_technique_name(tid),
                    description=desc,
                    evidence=s.value[:80] if hasattr(s, "value") else kw,
                ))

    return mappings


def map_indicators_to_mitre(indicators: list) -> list[MitreMapping]:
    mappings: list[MitreMapping] = []
    seen_techniques: set[str] = set()

    for ind in indicators:
        ind_type = ind.type if hasattr(ind, "type") else ""
        for sec_key, (tid, tactic, desc) in SECTION_TECHNIQUE_MAP.items():
            if ind_type == sec_key and tid not in seen_techniques:
                seen_techniques.add(tid)
                mappings.append(MitreMapping(
                    technique_id=tid, tactic=tactic,
                    name=_technique_name(tid),
                    description=desc,
                    evidence=ind.value[:80] if hasattr(ind, "value") else "",
                ))

    return mappings


def _technique_name(tid: str) -> str:
    names: dict[str, str] = {
        "T1055": "Process Injection",
        "T1055.012": "Process Injection: Process Hollowing",
        "T1057": "Process Discovery",
        "T1106": "Native API",
        "T1112": "Modify Registry",
        "T1071": "Application Layer Protocol",
        "T1071.001": "Application Layer Protocol: Web",
        "T1566": "Phishing",
        "T1027": "Obfuscated Files or Information",
        "T1053": "Scheduled Task/Job",
        "T1053.005": "Scheduled Task/Job: Scheduled Task",
        "T1547.001": "Boot or Logon Autostart: Registry Run Keys",
        "T1543.003": "Create or Modify System Process: Windows Service",
        "T1041": "Exfiltration Over C2 Channel",
        "T1113": "Screen Capture",
        "T1056.001": "Input Capture: Keylogging",
        "T1003": "OS Credential Dumping",
        "T1110": "Brute Force",
        "T1021": "Remote Services",
        "T1014": "Rootkit",
        "T1133": "External Remote Services",
        "T1056": "Input Capture",
    }
    return names.get(tid, tid)


def build_mitre_report(
    imports: list[ImportEntry],
    strings: list,
    indicators: list,
) -> list[MitreMapping]:
    all_mappings: list[MitreMapping] = []
    seen: set[str] = set()

    for mapping in (
        map_imports_to_mitre(imports)
        + map_strings_to_mitre(strings)
        + map_indicators_to_mitre(indicators)
    ):
        if mapping.technique_id not in seen:
            seen.add(mapping.technique_id)
            all_mappings.append(mapping)

    return sorted(all_mappings, key=lambda m: m.technique_id)
