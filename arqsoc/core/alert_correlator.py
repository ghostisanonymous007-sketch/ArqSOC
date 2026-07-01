"""Alert correlator - cross-reference IOCs with log events for ArqSOC."""

from __future__ import annotations

import re

from arqsoc.models.alert import Alert, AlertSeverity
from arqsoc.models.ioc import IOC, IOCType, RiskLevel
from arqsoc.models.log_event import LogEvent

IP_IN_TEXT = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_IN_TEXT = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
HASH_IN_TEXT = re.compile(r"\b[a-fA-F0-9]{32,64}\b")


def _risk_to_severity(risk: RiskLevel) -> AlertSeverity:
    mapping = {
        RiskLevel.INFO: AlertSeverity.INFO,
        RiskLevel.LOW: AlertSeverity.LOW,
        RiskLevel.MEDIUM: AlertSeverity.MEDIUM,
        RiskLevel.HIGH: AlertSeverity.HIGH,
        RiskLevel.CRITICAL: AlertSeverity.CRITICAL,
    }
    return mapping.get(risk, AlertSeverity.INFO)


def correlate_iocs_events(
    iocs: list[IOC],
    events: list[LogEvent],
    time_window: int = 300,
) -> list[Alert]:
    alerts: list[Alert] = []
    seen_alerts: set[str] = set()

    for ioc in iocs:
        matched_events: list[int] = []

        for idx, event in enumerate(events):
            text = event.raw_line + " " + " ".join(event.parsed_fields.values())

            if ioc.ioc_type in (IOCType.IPV4, IOCType.IPV6):
                if ioc.value in text or ioc.value in event.parsed_fields.get("src_ip", "") or ioc.value in event.parsed_fields.get("dest_ip", ""):
                    matched_events.append(idx)

            elif ioc.ioc_type == IOCType.DOMAIN:
                if ioc.value.lower() in text.lower():
                    matched_events.append(idx)

            elif ioc.ioc_type == IOCType.URL:
                if ioc.value.lower() in text.lower():
                    matched_events.append(idx)

            elif ioc.ioc_type == IOCType.EMAIL:
                if ioc.value.lower() in text.lower():
                    matched_events.append(idx)

            elif ioc.ioc_type in (IOCType.HASH_MD5, IOCType.HASH_SHA256):
                if ioc.value.lower() in text.lower():
                    matched_events.append(idx)

            elif ioc.ioc_type == IOCType.REGISTRY:
                if ioc.value.lower() in text.lower():
                    matched_events.append(idx)

            elif ioc.ioc_type == IOCType.MUTEX:
                if ioc.value in text:
                    matched_events.append(idx)

        if matched_events:
            alert_key = f"{ioc.ioc_type.value}:{ioc.value}"
            if alert_key in seen_alerts:
                continue
            seen_alerts.add(alert_key)

            severity = _risk_to_severity(ioc.risk_level)
            if len(matched_events) > 5:
                if severity.value < AlertSeverity.HIGH.value:
                    severity = AlertSeverity.HIGH
            if len(matched_events) > 20:
                severity = AlertSeverity.CRITICAL

            confidence = min(0.5 + 0.1 * min(len(matched_events), 5), 1.0)

            event_types: list[str] = []
            for ei in matched_events[:10]:
                if events[ei].normalized_type:
                    event_types.append(events[ei].normalized_type)

            title = f"IOC '{ioc.value}' found in {len(matched_events)} log event(s)"
            description = (
                f"{ioc.ioc_type.value} indicator '{ioc.value}' "
                f"(risk: {ioc.risk_level.value}) matched {len(matched_events)} log events. "
                f"Event types: {', '.join(set(event_types)) if event_types else 'various'}"
            )

            alerts.append(Alert(
                alert_id=alert_key,
                severity=severity,
                confidence=round(confidence, 2),
                title=title,
                description=description,
                related_iocs=[ioc],
                related_event_indices=matched_events,
                timestamp=events[matched_events[0]].timestamp if matched_events else "",
                source="ioc_log_correlation",
            ))

    return sorted(alerts, key=lambda a: a.severity.value, reverse=True)
