"""Tests for formatters CEF module."""

from __future__ import annotations

from arqsoc.formatters.cef import format_cef_alert, format_cef_ioc, alerts_to_cef, iocs_to_cef
from arqsoc.models.alert import Alert, AlertSeverity
from arqsoc.models.ioc import IOC, IOCType, RiskLevel


def test_format_cef_alert() -> None:
    alert = Alert(
        alert_id="test_alert",
        severity=AlertSeverity.HIGH,
        confidence=0.85,
        title="Test Alert",
        description="Test alert description",
        source="correlation",
    )
    cef = format_cef_alert(alert)
    assert cef.startswith("CEF:")
    assert "ArqSOC" in cef
    assert "Test Alert" in cef


def test_format_cef_ioc() -> None:
    ioc = IOC(
        ioc_type=IOCType.IPV4,
        value="10.0.0.1",
        risk_level=RiskLevel.HIGH,
        context="known C2",
    )
    cef = format_cef_ioc(ioc)
    assert cef.startswith("CEF:")
    assert "10.0.0.1" in cef


def test_alerts_to_cef() -> None:
    alerts = [
        Alert(alert_id="1", severity=AlertSeverity.LOW, confidence=0.5, title="Low Alert"),
        Alert(alert_id="2", severity=AlertSeverity.CRITICAL, confidence=0.95, title="Critical Alert"),
    ]
    cef_list = alerts_to_cef(alerts)
    assert len(cef_list) == 2
    assert all(s.startswith("CEF:") for s in cef_list)


def test_iocs_to_cef() -> None:
    iocs = [
        IOC(ioc_type=IOCType.DOMAIN, value="evil.com", risk_level=RiskLevel.HIGH),
        IOC(ioc_type=IOCType.IPV4, value="1.2.3.4", risk_level=RiskLevel.MEDIUM),
    ]
    cef_list = iocs_to_cef(iocs)
    assert len(cef_list) == 2
