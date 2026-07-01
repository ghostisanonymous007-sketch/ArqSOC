"""IOC (Indicator of Compromise) models for ArqSOC."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class IOCType(StrEnum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    HASH_MD5 = "hash_md5"
    HASH_SHA256 = "hash_sha256"
    FILEPATH = "filepath"
    MUTEX = "mutex"
    REGISTRY = "registry"
    JA3 = "ja3"
    FILENAME = "filename"


class RiskLevel(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IOC(BaseModel):
    ioc_type: IOCType
    value: str
    context: str = ""
    risk_level: RiskLevel = RiskLevel.INFO
    threat_intel: dict[str, str] = Field(default_factory=dict)
    first_seen: str = ""
    last_seen: str = ""
    source: str = ""
    tags: list[str] = Field(default_factory=list)
