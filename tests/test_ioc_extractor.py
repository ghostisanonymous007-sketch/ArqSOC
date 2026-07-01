"""Tests for core IOC extractor module."""

from __future__ import annotations

from pathlib import Path

from arqsoc.core.ioc_extractor import extract_iocs
from arqsoc.models.ioc import IOCType, RiskLevel


def test_extract_iocs_from_text(tmp_path: Path) -> None:
    f = tmp_path / "sample.bin"
    f.write_text(
        "Connect to 192.168.1.100 for C2 beacon at https://evil.com/payload "
        "email: attacker@malware.org mutex: Global\\{ABC-123} "
        "registry: HKEY_LOCAL_MACHINE\\Software\\Evil",
        encoding="utf-8",
    )
    iocs = extract_iocs(f)
    types = {ioc.ioc_type for ioc in iocs}
    assert IOCType.IPV4 in types
    assert IOCType.URL in types
    assert IOCType.EMAIL in types


def test_extract_iocs_private_ip(tmp_path: Path) -> None:
    f = tmp_path / "sample.bin"
    f.write_text("server at 192.168.1.1", encoding="utf-8")
    iocs = extract_iocs(f)
    ip_iocs = [i for i in iocs if i.ioc_type == IOCType.IPV4]
    assert len(ip_iocs) >= 1
    assert ip_iocs[0].risk_level in (RiskLevel.INFO, RiskLevel.LOW)


def test_extract_iocs_no_duplicates(tmp_path: Path) -> None:
    f = tmp_path / "sample.bin"
    f.write_text("10.0.0.1 and 10.0.0.1 again", encoding="utf-8")
    iocs = extract_iocs(f)
    ip_iocs = [i for i in iocs if i.ioc_type == IOCType.IPV4]
    assert len(ip_iocs) == 1


def test_extract_iocs_empty_file(tmp_path: Path) -> None:
    f = tmp_path / "empty.bin"
    f.write_bytes(b"")
    iocs = extract_iocs(f)
    assert iocs == []


def test_extract_iocs_system_binary(system_binary: Path) -> None:
    iocs = extract_iocs(system_binary)
    assert isinstance(iocs, list)
