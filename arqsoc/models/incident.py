"""Incident report models with MITRE ATT&CK mapping for ArqSOC."""

from __future__ import annotations

from pydantic import BaseModel, Field

from arqsoc.models.alert import Alert
from arqsoc.models.ioc import IOC


class MitreMapping(BaseModel):
    technique_id: str = ""
    tactic: str = ""
    name: str = ""
    description: str = ""
    evidence: str = ""
    subtechnique: str = ""


class TimelineEntry(BaseModel):
    timestamp: str = ""
    event_type: str = ""
    description: str = ""
    source: str = ""
    severity: str = "info"


class RiskAssessment(BaseModel):
    risk_score: float = 0.0
    impact: str = ""
    likelihood: str = ""
    affected_assets: list[str] = Field(default_factory=list)


class IncidentReport(BaseModel):
    title: str = ""
    date: str = ""
    summary: str = ""
    scope: str = ""
    iocs: list[IOC] = Field(default_factory=list)
    alerts: list[Alert] = Field(default_factory=list)
    mitre_mappings: list[MitreMapping] = Field(default_factory=list)
    timeline: list[TimelineEntry] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    risk_assessment: RiskAssessment = Field(default_factory=RiskAssessment)
