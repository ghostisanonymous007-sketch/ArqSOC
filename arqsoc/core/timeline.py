"""Incident timeline reconstruction for ArqSOC."""

from __future__ import annotations

from arqsoc.models.incident import TimelineEntry
from arqsoc.models.log_event import LogEvent, LogSeverity
from arqsoc.models.ioc import IOC


def _severity_str(sev: LogSeverity) -> str:
    mapping = {
        LogSeverity.DEBUG: "debug",
        LogSeverity.INFO: "info",
        LogSeverity.LOW: "low",
        LogSeverity.MEDIUM: "medium",
        LogSeverity.HIGH: "high",
        LogSeverity.CRITICAL: "critical",
    }
    return mapping.get(sev, "info")


def build_timeline(
    events: list[LogEvent],
    iocs: list[IOC] | None = None,
    file_timestamps: dict[str, str] | None = None,
) -> list[TimelineEntry]:
    entries: list[TimelineEntry] = []
    seen: set[str] = set()

    if file_timestamps:
        for fname, ts in sorted(file_timestamps.items()):
            key = f"file:{fname}:{ts}"
            if key not in seen:
                seen.add(key)
                entries.append(TimelineEntry(
                    timestamp=ts,
                    event_type="file_observation",
                    description=f"File observed: {fname}",
                    source="filesystem",
                    severity="info",
                ))

    for event in events:
        if not event.timestamp and not event.raw_line:
            continue

        key = f"event:{event.timestamp}:{event.raw_line[:100]}"
        if key in seen:
            continue
        seen.add(key)

        desc = event.raw_line[:120] if event.raw_line else event.normalized_type
        entries.append(TimelineEntry(
            timestamp=event.timestamp,
            event_type=event.normalized_type or "log_event",
            description=desc,
            source=event.source or "log",
            severity=_severity_str(event.severity),
        ))

    if iocs:
        for ioc in iocs:
            ts = ioc.first_seen or ioc.last_seen or ""
            if ts:
                key = f"ioc:{ioc.value}:{ts}"
                if key not in seen:
                    seen.add(key)
                    entries.append(TimelineEntry(
                        timestamp=ts,
                        event_type="ioc_detected",
                        description=f"IOC detected: {ioc.ioc_type.value} - {ioc.value}",
                        source=ioc.source or "ioc_extractor",
                        severity=ioc.risk_level.value if hasattr(ioc.risk_level, "value") else str(ioc.risk_level),
                    ))

    def _sort_key(entry: TimelineEntry) -> str:
        return entry.timestamp if entry.timestamp else "zzz"

    entries.sort(key=_sort_key)

    return entries


def detect_timeline_gaps(
    entries: list[TimelineEntry],
    gap_threshold: float = 3600.0,
) -> list[tuple[str, str, float]]:
    from dateutil import parser as dateutil_parser

    gaps: list[tuple[str, str, float]] = []
    parsed: list[tuple[str, float | None]] = []

    for entry in entries:
        if not entry.timestamp:
            parsed.append((entry.timestamp, None))
            continue
        try:
            dt = dateutil_parser.parse(entry.timestamp)
            parsed.append((entry.timestamp, dt.timestamp()))
        except (ValueError, TypeError, OSError):
            parsed.append((entry.timestamp, None))

    for i in range(1, len(parsed)):
        prev_ts = parsed[i - 1][1]
        curr_ts = parsed[i][1]
        if prev_ts is not None and curr_ts is not None:
            diff = curr_ts - prev_ts
            if diff >= gap_threshold:
                gaps.append((parsed[i - 1][0], parsed[i][0], diff))

    return gaps
