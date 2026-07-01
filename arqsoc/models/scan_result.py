"""Pydantic models for ArqSOC scan results."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class ThreatLevel(StrEnum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


class StringClassification(StrEnum):
    URL = "url"
    IP = "ip"
    EMAIL = "email"
    REGISTRY = "registry"
    FILE_PATH = "file_path"
    API = "api"
    CRYPTO = "crypto"
    BASE64 = "base64"
    MUTEX = "mutex"
    C2 = "c2"
    KEY = "key"
    OTHER = "other"


class BinaryType(StrEnum):
    PE32 = "pe32"
    PE64 = "pe64"
    ELF32 = "elf32"
    ELF64 = "elf64"
    MACHO32 = "macho32"
    MACHO64 = "macho64"
    UNKNOWN = "unknown"


class ArchType(StrEnum):
    X86 = "x86"
    X64 = "x64"
    ARM32 = "arm32"
    ARM64 = "arm64"
    MIPS = "mips"
    UNKNOWN = "unknown"


class HashResult(BaseModel):
    md5: str = ""
    sha1: str = ""
    sha256: str = ""
    ssdeep: str | None = None
    imphash: str | None = None


class SectionInfo(BaseModel):
    name: str
    virtual_address: int = 0
    virtual_size: int = 0
    raw_size: int = 0
    entropy: float = 0.0
    is_readable: bool = False
    is_writable: bool = False
    is_executable: bool = False
    is_suspicious: bool = False
    anomaly_reason: str = ""


class ImportEntry(BaseModel):
    name: str
    dll: str = ""
    address: int = 0


class ExportEntry(BaseModel):
    name: str
    address: int = 0


class ClassifiedString(BaseModel):
    value: str
    classification: StringClassification = StringClassification.OTHER
    offset: int = 0
    is_obfuscated: bool = False
    decoded_value: str | None = None


class PackerResult(BaseModel):
    is_packed: bool = False
    packer_name: str = ""
    confidence: float = 0.0
    indicators: list[str] = Field(default_factory=list)


class YARAMatch(BaseModel):
    rule_name: str
    namespace: str = ""
    tags: list[str] = Field(default_factory=list)
    meta: dict[str, str] = Field(default_factory=dict)
    strings_matched: list[str] = Field(default_factory=list)


class ThreatIndicator(BaseModel):
    type: str
    value: str
    confidence: float = 0.0
    source: str = ""


class ThreatTimelineEntry(BaseModel):
    step: int
    description: str
    indicators: list[str] = Field(default_factory=list)
    confidence: float = 0.0


class FileInfo(BaseModel):
    path: str
    name: str
    size: int
    binary_type: BinaryType = BinaryType.UNKNOWN
    architecture: ArchType = ArchType.UNKNOWN
    compiler: str = ""
    compile_time: str = ""
    is_dotnet: bool = False
    subsystem: str = ""


class RichHeaderEntry(BaseModel):
    product_id: int = 0
    build_id: int = 0
    count: int = 0
    name: str = ""


class RichHeaderInfo(BaseModel):
    is_present: bool = False
    XOR_key: int = 0
    entries: list[RichHeaderEntry] = Field(default_factory=list)
    decoded_signature: str = ""


class OverlayInfo(BaseModel):
    has_overlay: bool = False
    offset: int = 0
    size: int = 0
    entropy: float = 0.0
    magic: str = ""


class TLSCallback(BaseModel):
    address: int = 0
    callback_hex: str = ""


class TLSInfo(BaseModel):
    has_tls: bool = False
    callbacks: list[TLSCallback] = Field(default_factory=list)
    data_address: int = 0


class SignatureInfo(BaseModel):
    is_signed: bool = False
    is_valid: bool = False
    signer: str = ""
    issuer: str = ""
    serial: str = ""


class IATEntry(BaseModel):
    api_name: str
    dll_name: str = ""
    confidence: float = 0.0
    source: str = ""


class ScanResult(BaseModel):
    file_info: FileInfo
    hashes: HashResult = Field(default_factory=HashResult)
    sections: list[SectionInfo] = Field(default_factory=list)
    imports: list[ImportEntry] = Field(default_factory=list)
    exports: list[ExportEntry] = Field(default_factory=list)
    strings: list[ClassifiedString] = Field(default_factory=list)
    packer: PackerResult = Field(default_factory=PackerResult)
    yara_matches: list[YARAMatch] = Field(default_factory=list)
    threat_level: ThreatLevel = ThreatLevel.UNKNOWN
    overall_confidence: float = 0.0
    threat_indicators: list[ThreatIndicator] = Field(default_factory=list)
    threat_timeline: list[ThreatTimelineEntry] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    rich_header: RichHeaderInfo = Field(default_factory=RichHeaderInfo)
    overlay: OverlayInfo = Field(default_factory=OverlayInfo)
    tls: TLSInfo = Field(default_factory=TLSInfo)
    signature: SignatureInfo = Field(default_factory=SignatureInfo)
    dynamic_imports: list[IATEntry] = Field(default_factory=list)
