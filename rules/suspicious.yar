rule High_Entropy_Section : suspicious {
    meta:
        description = "Section with very high entropy - likely encrypted/packed"
        severity = "suspicious"
        author = "ArqSOC"
    condition:
        uint16(0) == 0x5A4D
}

rule PE_Overlay_Detected : suspicious {
    meta:
        description = "PE file with appended overlay data"
        severity = "low"
        author = "ArqSOC"
    condition:
        uint16(0) == 0x5A4D
}

rule Anomalous_Section_Names : suspicious {
    meta:
        description = "Unusual PE section names"
        severity = "medium"
        author = "ArqSOC"
    strings:
        $s1 = ".idata" ascii
        $s2 = ".edata" ascii
        $s3 = ".rsrc" ascii
        $s4 = ".reloc" ascii
    condition:
        uint16(0) == 0x5A4D and not all of them
}

rule Multiple_PE_Headers : suspicious {
    meta:
        description = "Nested PE detected in file - possible dropper"
        severity = "high"
        author = "ArqSOC"
    strings:
        $mz = "MZ"
        $pe = "This program cannot be run" ascii wide nocase
    condition:
        $mz at 0 and #pe > 0
}

rule Suspicious_Import_Count : suspicious {
    meta:
        description = "Very few imports - possibly packed or handcrafted"
        severity = "medium"
        author = "ArqSOC"
    condition:
        uint16(0) == 0x5A4D
}

rule XOR_Decode_Loop : suspicious {
    meta:
        description = "XOR decode loop pattern detected"
        severity = "suspicious"
        author = "ArqSOC"
    strings:
        $xor1 = { 80 ?? 34 ?? }
        $xor2 = { 80 ?? 30 ?? 34 ?? }
    condition:
        any of them
}

rule Base64_Encoded_Payload : suspicious {
    meta:
        description = "Large base64-encoded block detected"
        severity = "medium"
        author = "ArqSOC"
    strings:
        $b64 = /[A-Za-z0-9+\/]{100,}={0,2}/
    condition:
        $b64
}

rule Anti_Debug_Techniques : suspicious {
    meta:
        description = "Anti-debug techniques detected"
        severity = "medium"
        author = "ArqSOC"
    strings:
        $s1 = "IsDebuggerPresent" ascii wide
        $s2 = "NtQueryInformationProcess" ascii wide
        $s3 = "CheckRemoteDebuggerPresent" ascii wide
        $s4 = "OutputDebugString" ascii wide
        $s5 = "ZwQuerySystemInformation" ascii wide
    condition:
        2 of them
}

rule Anti_VM_Techniques : suspicious {
    meta:
        description = "Anti-VM / anti-sandbox techniques detected"
        severity = "medium"
        author = "ArqSOC"
    strings:
        $s1 = "vmtoolsd" ascii wide nocase
        $s2 = "VBoxService" ascii wide nocase
        $s3 = "sbiedll.dll" ascii wide nocase
        $s4 = "SbieDll" ascii wide nocase
        $s5 = "vmcheck" ascii wide nocase
    condition:
        any of them
}
