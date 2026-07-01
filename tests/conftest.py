"""Shared test fixtures for ArqSOC."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest


def _system_binary() -> Path:
    if sys.platform == "win32":
        return Path(os.environ.get("SystemRoot", r"C:\Windows")) / "notepad.exe"
    return Path("/bin/ls")


SYSTEM_BINARY = _system_binary()


@pytest.fixture
def system_binary() -> Path:
    return SYSTEM_BINARY


@pytest.fixture
def sample_dir(tmp_path: Path) -> Path:
    binary_data = b"\x4d\x5a\x90\x00" + b"\x00" * 60 + b"\x0e\x1f\xba\x0e" + b"\x00" * 100
    sample = tmp_path / "sample.bin"
    sample.write_bytes(binary_data)
    return tmp_path


@pytest.fixture
def sample_log_dir(tmp_path: Path) -> Path:
    syslog_file = tmp_path / "syslog.txt"
    syslog_file.write_text(
        "Jan 01 12:00:00 server sshd[1234]: Failed password for root from 10.0.0.1\n"
        "Jan 01 12:00:05 server sshd[1234]: Accepted password for user from 10.0.0.1\n"
        "Jan 01 12:01:00 server sudo: user : TTY=pts/0 ; PWD=/home ; USER=root ; COMMAND=/bin/bash\n",
        encoding="utf-8",
    )

    suricata_file = tmp_path / "eve.json"
    suricata_file.write_text(
        '{"timestamp":"2024-01-01T12:00:00.000000+0000","event_type":"alert","src_ip":"10.0.0.1","dest_ip":"192.168.1.1","alert":{"severity":2,"signature":"ET MALWARE C2","category":"Trojan"}}\n',
        encoding="utf-8",
    )

    json_log_file = tmp_path / "app.json"
    json_log_file.write_text(
        '{"timestamp":"2024-01-01T12:00:00","source":"web","message":"login failed","level":"error"}\n'
        '{"timestamp":"2024-01-01T12:00:01","source":"web","message":"login success","level":"info"}\n',
        encoding="utf-8",
    )

    return tmp_path


@pytest.fixture
def temp_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    config_dir = tmp_path / ".arqsoc"
    config_dir.mkdir()
    config_file = config_dir / "config.json"
    monkeypatch.setattr("arqsoc.config.CONFIG_DIR", config_dir)
    monkeypatch.setattr("arqsoc.config.CONFIG_FILE", config_file)
    return config_file
