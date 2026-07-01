"""Correlated alert models for ArqSOC."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field

from arqsoc.models.ioc import IOC


class AlertSeverity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Alert(BaseModel):
    alert_id: str = ""
    severity: AlertSeverity = AlertSeverity.INFO
    confidence: float = 0.0
    title: str = ""
    description: str = ""
    related_iocs: list[IOC] = Field(default_factory=list)
    related_event_indices: list[int] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    timestamp: str = ""
    source: str = ""
