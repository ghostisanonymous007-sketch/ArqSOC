"""Log event models for ArqSOC."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class LogSeverity(StrEnum):
    DEBUG = "debug"
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class LogFormat(StrEnum):
    SYSLOG = "syslog"
    AUTH_LOG = "auth_log"
    EVTX_XML = "evtx_xml"
    SURICATA = "suricata"
    ZEEK = "zeek"
    JSON = "json"
    PLAIN = "plain"


class LogEvent(BaseModel):
    timestamp: str = ""
    source: str = ""
    severity: LogSeverity = LogSeverity.INFO
    raw_line: str = ""
    parsed_fields: dict[str, str] = Field(default_factory=dict)
    normalized_type: str = ""
    log_format: LogFormat = LogFormat.PLAIN
