rule UPX_v0_7x : packer {
    meta:
        description = "UPX 0.7x packed file"
        severity = "low"
        author = "ArqSOC"
    strings:
        $s1 = "UPX!" ascii
        $s2 = "UPX0" ascii
        $s3 = "UPX1" ascii
    condition:
        any of them
}

rule UPX_v1_2x : packer {
    meta:
        description = "UPX 1.2x packed file"
        severity = "low"
        author = "ArqSOC"
    strings:
        $s1 = "UPX!" ascii wide
        $s2 = "UPX0" ascii wide
        $s3 = "UPX1" ascii wide
        $s4 = ".rsrc" ascii
    condition:
        2 of them
}

rule ASPack : packer {
    meta:
        description = "ASPack packed file"
        severity = "medium"
        author = "ArqSOC"
    strings:
        $s1 = ".aspack" ascii
        $s2 = ".adata" ascii
    condition:
        any of them
}

rule PECompact : packer {
    meta:
        description = "PECompact packed file"
        severity = "medium"
        author = "ArqSOC"
    strings:
        $s1 = "PECompact2" ascii
        $s2 = "PEC2" ascii
    condition:
        any of them
}

rule Themida : packer {
    meta:
        description = "Themida/WinLicense packed file"
        severity = "high"
        author = "ArqSOC"
    strings:
        $s1 = "Themida" ascii wide
        $s2 = "WinLicense" ascii wide
    condition:
        any of them
}

rule VMProtect : packer {
    meta:
        description = "VMProtect packed file"
        severity = "high"
        author = "ArqSOC"
    strings:
        $s1 = ".vmp0" ascii
        $s2 = ".vmp1" ascii
        $s3 = "VMProtect" ascii wide
    condition:
        any of them
}

rule MPRESS : packer {
    meta:
        description = "MPRESS packed file"
        severity = "medium"
        author = "ArqSOC"
    strings:
        $s1 = ".MPRESS1" ascii
        $s2 = ".MPRESS2" ascii
    condition:
        any of them
}

rule NsPack : packer {
    meta:
        description = "NsPack packed file"
        severity = "medium"
        author = "ArqSOC"
    strings:
        $s1 = ".nsp0" ascii
        $s2 = ".nsp1" ascii
        $s3 = ".nsp2" ascii
    condition:
        any of them
}

rule Enigma_Protector : packer {
    meta:
        description = "Enigma Protector packed file"
        severity = "high"
        author = "ArqSOC"
    strings:
        $s1 = "Enigma protector" ascii wide
        $s2 = ".enigma1" ascii
        $s3 = ".enigma2" ascii
    condition:
        any of them
}

rule PELock : packer {
    meta:
        description = "PELock packed file"
        severity = "medium"
        author = "ArqSOC"
    strings:
        $s1 = "PELock" ascii wide
    condition:
        $s1
}
