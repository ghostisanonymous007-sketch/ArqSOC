"""Log parser - parse and normalize security log formats for ArqSOC."""

from __future__ import annotations

import json
import re
from pathlib import Path

from arqsoc.models.log_event import LogEvent, LogFormat, LogSeverity

SYSLOG_PATTERN = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)$"
)

AUTH_LOG_PATTERN = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)$"
)

SURICATA_TIMESTAMP = re.compile(r"^\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+")


def _detect_log_format(file_path: Path) -> LogFormat:
    try:
        data = file_path.read_bytes()[:8192]
        text = data.decode("utf-8", errors="ignore")
    except OSError:
        return LogFormat.PLAIN

    lines = text.split("\n")[:10]

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue

        if stripped.startswith("<") and ">" in stripped:
            try:
                content = stripped[stripped.index(">") + 1:]
                if SYSLOG_PATTERN.match(content.strip()):
                    return LogFormat.SYSLOG
            except (ValueError, IndexError):
                pass

        if SYSLOG_PATTERN.match(stripped):
            lower = stripped.lower()
            if "sshd" in lower or "pam" in lower or "su:" in lower or "sudo" in lower:
                return LogFormat.AUTH_LOG
            return LogFormat.SYSLOG

        try:
            obj = json.loads(stripped)
            if isinstance(obj, dict):
                if "event_type" in obj and ("src_ip" in obj or "dest_ip" in obj):
                    return LogFormat.SURICATA
                if "ts" in obj and ("id.orig_h" in obj or "uid" in obj):
                    return LogFormat.ZEEK
                return LogFormat.JSON
        except (json.JSONDecodeError, ValueError):
            pass

        if stripped.startswith("<Event"):
            return LogFormat.EVTX_XML

    return LogFormat.PLAIN


def _severity_from_syslog(text: str) -> LogSeverity:
    lower = text.lower()
    if any(kw in lower for kw in ("error", "err", "crit", "alert", "emerg", "fatal")):
        return LogSeverity.HIGH
    if any(kw in lower for kw in ("warn", "warning")):
        return LogSeverity.MEDIUM
    if any(kw in lower for kw in ("info", "notice")):
        return LogSeverity.INFO
    if any(kw in lower for kw in ("failed", "failure", "denied", "invalid", "refused")):
        return LogSeverity.HIGH
    if any(kw in lower for kw in ("accepted", "success", "opened", "started")):
        return LogSeverity.INFO
    return LogSeverity.LOW


def _normalize_syslog_type(text: str) -> str:
    lower = text.lower()
    if "sshd" in lower:
        if "failed" in lower or "invalid" in lower:
            return "ssh_bruteforce"
        if "accepted" in lower:
            return "ssh_login"
        return "ssh_event"
    if "su:" in lower:
        return "privilege_escalation"
    if "sudo" in lower:
        return "sudo_usage"
    if "pam" in lower:
        return "auth_event"
    return "system_event"


def _parse_syslog_line(line: str) -> LogEvent | None:
    m = SYSLOG_PATTERN.match(line.strip())
    if not m:
        return None

    timestamp, host, process, pid, message = m.groups()
    severity = _severity_from_syslog(message)
    full_text = f"{process}: {message}"
    normalized = _normalize_syslog_type(full_text)

    fields: dict[str, str] = {"host": host, "process": process}
    if pid:
        fields["pid"] = pid

    return LogEvent(
        timestamp=timestamp,
        source=host,
        severity=severity,
        raw_line=line.strip(),
        parsed_fields=fields,
        normalized_type=normalized,
        log_format=LogFormat.SYSLOG,
    )


def _parse_suricata_line(line: str) -> LogEvent | None:
    try:
        obj = json.loads(line.strip())
    except (json.JSONDecodeError, ValueError):
        return None

    if not isinstance(obj, dict):
        return None

    timestamp = obj.get("timestamp", "")
    src_ip = obj.get("src_ip", "")
    dest_ip = obj.get("dest_ip", "")
    alert = obj.get("alert", {})
    severity_str = alert.get("severity", 3)

    sev_map = {1: LogSeverity.HIGH, 2: LogSeverity.HIGH, 3: LogSeverity.MEDIUM, 4: LogSeverity.LOW}
    severity = sev_map.get(severity_str, LogSeverity.MEDIUM) if isinstance(severity_str, int) else LogSeverity.MEDIUM

    fields: dict[str, str] = {}
    if src_ip:
        fields["src_ip"] = src_ip
    if dest_ip:
        fields["dest_ip"] = dest_ip
    if alert:
        fields["alert_signature"] = alert.get("signature", "")
        fields["alert_category"] = alert.get("category", "")

    return LogEvent(
        timestamp=timestamp,
        source=src_ip,
        severity=severity,
        raw_line=line.strip(),
        parsed_fields=fields,
        normalized_type="ids_alert",
        log_format=LogFormat.SURICATA,
    )


def _parse_zeek_line(line: str) -> LogEvent | None:
    if line.startswith("#"):
        return None
    parts = line.strip().split("\t")
    if len(parts) < 2:
        return None

    ts = parts[0] if parts else ""

    fields: dict[str, str] = {}
    zeek_headers = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p"]
    for i, h in enumerate(zeek_headers):
        if i < len(parts):
            fields[h] = parts[i]

    src_ip = fields.get("id.orig_h", "")

    return LogEvent(
        timestamp=ts,
        source=src_ip,
        severity=LogSeverity.MEDIUM,
        raw_line=line.strip(),
        parsed_fields=fields,
        normalized_type="network_connection",
        log_format=LogFormat.ZEEK,
    )


def _parse_json_line(line: str) -> LogEvent | None:
    try:
        obj = json.loads(line.strip())
    except (json.JSONDecodeError, ValueError):
        return None

    if not isinstance(obj, dict):
        return None

    timestamp = str(obj.get("timestamp", obj.get("time", obj.get("@timestamp", ""))))
    source = str(obj.get("source", obj.get("host", obj.get("src", ""))))
    message = str(obj.get("message", obj.get("msg", "")))
    level = str(obj.get("level", obj.get("severity", ""))).lower()

    sev_map = {"error": LogSeverity.HIGH, "warn": LogSeverity.MEDIUM, "warning": LogSeverity.MEDIUM, "info": LogSeverity.INFO, "debug": LogSeverity.DEBUG, "critical": LogSeverity.CRITICAL}
    severity = sev_map.get(level, LogSeverity.INFO)

    fields: dict[str, str] = {}
    for k, v in obj.items():
        if k not in ("timestamp", "time", "@timestamp", "message", "msg", "level", "severity"):
            fields[k] = str(v)

    return LogEvent(
        timestamp=timestamp,
        source=source,
        severity=severity,
        raw_line=line.strip(),
        parsed_fields=fields,
        normalized_type="json_log",
        log_format=LogFormat.JSON,
    )


def _parse_plain_line(line: str, line_num: int) -> LogEvent:
    lower = line.lower()
    if any(kw in lower for kw in ("error", "fail", "crit", "fatal", "denied", "refused")):
        severity = LogSeverity.HIGH
    elif any(kw in lower for kw in ("warn", "suspicious", "alert")):
        severity = LogSeverity.MEDIUM
    else:
        severity = LogSeverity.INFO

    return LogEvent(
        timestamp="",
        source="",
        severity=severity,
        raw_line=line.strip(),
        parsed_fields={"line": str(line_num)},
        normalized_type="plain_text",
        log_format=LogFormat.PLAIN,
    )


def parse_log_file(file_path: Path, fmt: LogFormat | None = None) -> list[LogEvent]:
    try:
        text = file_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []

    if fmt is None:
        fmt = _detect_log_format(file_path)

    events: list[LogEvent] = []
    lines = text.split("\n")

    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            continue

        event: LogEvent | None = None
        if fmt == LogFormat.SYSLOG or fmt == LogFormat.AUTH_LOG:
            event = _parse_syslog_line(stripped)
        elif fmt == LogFormat.SURICATA:
            event = _parse_suricata_line(stripped)
        elif fmt == LogFormat.ZEEK:
            event = _parse_zeek_line(stripped)
        elif fmt == LogFormat.JSON:
            event = _parse_json_line(stripped)
        elif fmt == LogFormat.EVTX_XML:
            event = _parse_plain_line(stripped, i + 1)
        else:
            event = _parse_plain_line(stripped, i + 1)

        if event is not None:
            events.append(event)

    return events


def parse_log_directory(dir_path: Path, fmt: LogFormat | None = None) -> dict[str, list[LogEvent]]:
    results: dict[str, list[LogEvent]] = {}
    if not dir_path.is_dir():
        return results

    for f in sorted(dir_path.rglob("*")):
        if f.is_file() and not f.name.startswith("."):
            results[f.name] = parse_log_file(f, fmt)

    return results
