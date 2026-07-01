"""Tests for core timeline module."""

from __future__ import annotations

from arqsoc.core.timeline import build_timeline, detect_timeline_gaps
from arqsoc.models.incident import TimelineEntry
from arqsoc.models.log_event import LogEvent, LogSeverity, LogFormat
from arqsoc.models.ioc import IOC, IOCType, RiskLevel


def test_build_timeline_from_events() -> None:
    events = [
        LogEvent(timestamp="2024-01-01T10:00:00", raw_line="Event A", severity=LogSeverity.INFO, normalized_type="login", source="syslog"),
        LogEvent(timestamp="2024-01-01T10:05:00", raw_line="Event B", severity=LogSeverity.HIGH, normalized_type="failed_login", source="syslog"),
    ]
    entries = build_timeline(events)
    assert len(entries) == 2
    assert entries[0].event_type == "login"


def test_build_timeline_with_iocs() -> None:
    events = [
        LogEvent(timestamp="2024-01-01T10:00:00", raw_line="Event A", severity=LogSeverity.INFO, normalized_type="login"),
    ]
    iocs = [
        IOC(ioc_type=IOCType.IPV4, value="10.0.0.1", first_seen="2024-01-01T09:00:00", risk_level=RiskLevel.HIGH),
    ]
    entries = build_timeline(events, iocs=iocs)
    assert len(entries) >= 2


def test_build_timeline_empty() -> None:
    entries = build_timeline([])
    assert entries == []


def test_detect_timeline_gaps() -> None:
    entries = [
        TimelineEntry(timestamp="2024-01-01T10:00:00", event_type="start", description="Start"),
        TimelineEntry(timestamp="2024-01-01T10:01:00", event_type="middle", description="Middle"),
        TimelineEntry(timestamp="2024-01-01T12:00:00", event_type="end", description="End (2h gap)"),
    ]
    gaps = detect_timeline_gaps(entries, gap_threshold=3600.0)
    assert len(gaps) >= 1


def test_detect_timeline_gaps_none() -> None:
    entries = [
        TimelineEntry(timestamp="2024-01-01T10:00:00", event_type="a", description="A"),
        TimelineEntry(timestamp="2024-01-01T10:00:30", event_type="b", description="B"),
    ]
    gaps = detect_timeline_gaps(entries, gap_threshold=3600.0)
    assert len(gaps) == 0
