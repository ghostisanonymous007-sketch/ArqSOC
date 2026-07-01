"""Tests for models."""

from __future__ import annotations

from arqsoc.models.scan_result import (
    ScanResult,
    FileInfo,
    HashResult,
    ThreatLevel,
    BinaryType,
    ArchType,
    StringClassification,
)
from arqsoc.models.ioc import IOC, IOCType, RiskLevel
from arqsoc.models.log_event import LogEvent, LogFormat, LogSeverity
from arqsoc.models.alert import Alert, AlertSeverity
from arqsoc.models.incident import IncidentReport, MitreMapping, TimelineEntry, RiskAssessment
from arqsoc.models.batch import TriageResult


def test_scan_result_construction() -> None:
    fi = FileInfo(path="/test", name="test.exe", size=1024, binary_type=BinaryType.PE64, architecture=ArchType.X64)
    sr = ScanResult(file_info=fi)
    assert sr.file_info.name == "test.exe"
    assert sr.threat_level == ThreatLevel.UNKNOWN


def test_ioc_construction() -> None:
    ioc = IOC(ioc_type=IOCType.IPV4, value="1.2.3.4", risk_level=RiskLevel.HIGH)
    assert ioc.value == "1.2.3.4"
    assert ioc.risk_level == RiskLevel.HIGH


def test_log_event_construction() -> None:
    event = LogEvent(raw_line="test", severity=LogSeverity.INFO, log_format=LogFormat.SYSLOG)
    assert event.severity == LogSeverity.INFO


def test_alert_construction() -> None:
    alert = Alert(severity=AlertSeverity.HIGH, confidence=0.8, title="Test Alert")
    assert alert.severity == AlertSeverity.HIGH


def test_incident_report_construction() -> None:
    report = IncidentReport(title="Test Incident", risk_assessment=RiskAssessment(risk_score=0.5))
    assert report.title == "Test Incident"
    assert report.risk_assessment.risk_score == 0.5


def test_triage_result_construction() -> None:
    result = TriageResult(file_path="/test.bin", priority="high", risk_score=0.8)
    assert result.priority == "high"


def test_enum_values() -> None:
    assert ThreatLevel.BENIGN.value == "benign"
    assert BinaryType.PE64.value == "pe64"
    assert IOCType.IPV4.value == "ipv4"
    assert RiskLevel.CRITICAL.value == "critical"
    assert LogFormat.SYSLOG.value == "syslog"
    assert AlertSeverity.HIGH.value == "high"
    assert StringClassification.URL.value == "url"
