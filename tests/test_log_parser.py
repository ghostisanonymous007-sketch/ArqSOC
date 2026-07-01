"""Tests for core log parser module."""

from __future__ import annotations

from pathlib import Path

from arqsoc.core.log_parser import parse_log_file, parse_log_directory, _detect_log_format
from arqsoc.models.log_event import LogFormat, LogSeverity


def test_detect_syslog(tmp_path: Path) -> None:
    f = tmp_path / "syslog"
    f.write_text("Jan 01 12:00:00 server kernel: USB device connected\n", encoding="utf-8")
    fmt = _detect_log_format(f)
    assert fmt == LogFormat.SYSLOG


def test_detect_auth_log(tmp_path: Path) -> None:
    f = tmp_path / "auth.log"
    f.write_text("Jan 01 12:00:00 server sshd[1234]: Failed password for root\n", encoding="utf-8")
    fmt = _detect_log_format(f)
    assert fmt in (LogFormat.AUTH_LOG, LogFormat.SYSLOG)


def test_detect_suricata(tmp_path: Path) -> None:
    f = tmp_path / "eve.json"
    f.write_text('{"event_type":"alert","src_ip":"10.0.0.1","dest_ip":"192.168.1.1"}\n', encoding="utf-8")
    fmt = _detect_log_format(f)
    assert fmt == LogFormat.SURICATA


def test_detect_json(tmp_path: Path) -> None:
    f = tmp_path / "app.log"
    f.write_text('{"timestamp":"2024-01-01","message":"test","level":"info"}\n', encoding="utf-8")
    fmt = _detect_log_format(f)
    assert fmt == LogFormat.JSON


def test_detect_plain(tmp_path: Path) -> None:
    f = tmp_path / "plain.log"
    f.write_text("something went wrong error code 500\n", encoding="utf-8")
    fmt = _detect_log_format(f)
    assert fmt == LogFormat.PLAIN


def test_parse_syslog(tmp_path: Path) -> None:
    f = tmp_path / "syslog"
    f.write_text(
        "Jan 01 12:00:00 server sshd[1234]: Failed password for root from 10.0.0.1\n"
        "Jan 01 12:00:05 server sshd[1234]: Accepted password for user from 10.0.0.2\n",
        encoding="utf-8",
    )
    events = parse_log_file(f, fmt=LogFormat.AUTH_LOG)
    assert len(events) == 2
    assert events[0].normalized_type == "ssh_bruteforce"
    assert events[1].normalized_type == "ssh_login"


def test_parse_suricata(tmp_path: Path) -> None:
    f = tmp_path / "eve.json"
    f.write_text(
        '{"timestamp":"2024-01-01T12:00:00","event_type":"alert","src_ip":"10.0.0.1","dest_ip":"192.168.1.1","alert":{"severity":2,"signature":"ET MALWARE"}}\n',
        encoding="utf-8",
    )
    events = parse_log_file(f, fmt=LogFormat.SURICATA)
    assert len(events) == 1
    assert events[0].normalized_type == "ids_alert"


def test_parse_json(tmp_path: Path) -> None:
    f = tmp_path / "app.log"
    f.write_text(
        '{"timestamp":"2024-01-01T12:00:00","message":"test error","level":"error"}\n',
        encoding="utf-8",
    )
    events = parse_log_file(f, fmt=LogFormat.JSON)
    assert len(events) == 1
    assert events[0].severity == LogSeverity.HIGH


def test_parse_directory(sample_log_dir: Path) -> None:
    results = parse_log_directory(sample_log_dir)
    assert len(results) > 0
    for name, events in results.items():
        assert isinstance(events, list)
