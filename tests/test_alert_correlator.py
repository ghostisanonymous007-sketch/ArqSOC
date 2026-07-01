"""Tests for core alert correlator module."""

from __future__ import annotations

from arqsoc.core.alert_correlator import correlate_iocs_events
from arqsoc.models.ioc import IOC, IOCType, RiskLevel
from arqsoc.models.log_event import LogEvent, LogSeverity, LogFormat


def test_correlate_ip_ioc_with_log() -> None:
    iocs = [
        IOC(ioc_type=IOCType.IPV4, value="10.0.0.1", risk_level=RiskLevel.HIGH),
    ]
    events = [
        LogEvent(raw_line="Connection from 10.0.0.1 to server", severity=LogSeverity.HIGH, normalized_type="network_connection"),
    ]
    alerts = correlate_iocs_events(iocs, events)
    assert len(alerts) >= 1
    assert "10.0.0.1" in alerts[0].title


def test_correlate_domain_ioc() -> None:
    iocs = [
        IOC(ioc_type=IOCType.DOMAIN, value="evil.com", risk_level=RiskLevel.HIGH),
    ]
    events = [
        LogEvent(raw_line="DNS query for evil.com from host", severity=LogSeverity.MEDIUM, normalized_type="dns_query"),
    ]
    alerts = correlate_iocs_events(iocs, events)
    assert len(alerts) >= 1


def test_correlate_no_match() -> None:
    iocs = [
        IOC(ioc_type=IOCType.IPV4, value="99.99.99.99", risk_level=RiskLevel.HIGH),
    ]
    events = [
        LogEvent(raw_line="Normal traffic from 10.0.0.1", severity=LogSeverity.INFO, normalized_type="network_connection"),
    ]
    alerts = correlate_iocs_events(iocs, events)
    assert len(alerts) == 0


def test_correlate_severity_escalation() -> None:
    iocs = [
        IOC(ioc_type=IOCType.IPV4, value="10.0.0.1", risk_level=RiskLevel.LOW),
    ]
    events = [
        LogEvent(raw_line=f"Connection from 10.0.0.1 attempt {i}", severity=LogSeverity.MEDIUM, normalized_type="network_connection")
        for i in range(25)
    ]
    alerts = correlate_iocs_events(iocs, events)
    assert len(alerts) >= 1
