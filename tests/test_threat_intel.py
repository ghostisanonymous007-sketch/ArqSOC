"""Tests for core threat intel module."""

from __future__ import annotations

from unittest.mock import patch, MagicMock

from arqsoc.core.threat_intel import enrich_vt_hash, enrich_vt_ip, enrich_abuseipdb, enrich_shodan, enrich_ioc
from arqsoc.models.ioc import IOC, IOCType, RiskLevel


def test_enrich_vt_hash_no_key() -> None:
    with patch("arqsoc.core.threat_intel.get_api_key", return_value=None):
        result = enrich_vt_hash("abc123", api_key=None)
        assert "error" in result


def test_enrich_vt_ip_no_key() -> None:
    with patch("arqsoc.core.threat_intel.get_api_key", return_value=None):
        result = enrich_vt_ip("1.2.3.4", api_key=None)
        assert "error" in result


def test_enrich_abuseipdb_no_key() -> None:
    with patch("arqsoc.core.threat_intel.get_api_key", return_value=None):
        result = enrich_abuseipdb("1.2.3.4", api_key=None)
        assert "error" in result


def test_enrich_shodan_no_key() -> None:
    with patch("arqsoc.core.threat_intel.get_api_key", return_value=None):
        result = enrich_shodan("1.2.3.4", api_key=None)
        assert "error" in result


def test_enrich_ioc_ip_no_key() -> None:
    ioc = IOC(ioc_type=IOCType.IPV4, value="1.2.3.4", risk_level=RiskLevel.MEDIUM)
    with patch("arqsoc.core.threat_intel.get_api_key", return_value=None):
        enriched = enrich_ioc(ioc)
        assert enriched.value == "1.2.3.4"


def test_enrich_ioc_hash_no_key() -> None:
    ioc = IOC(ioc_type=IOCType.HASH_SHA256, value="a" * 64, risk_level=RiskLevel.MEDIUM)
    with patch("arqsoc.core.threat_intel.get_api_key", return_value=None):
        enriched = enrich_ioc(ioc)
        assert enriched.value == "a" * 64


def test_enrich_ioc_domain_no_key() -> None:
    ioc = IOC(ioc_type=IOCType.DOMAIN, value="evil.com", risk_level=RiskLevel.MEDIUM)
    with patch("arqsoc.core.threat_intel.get_api_key", return_value=None):
        enriched = enrich_ioc(ioc)
        assert enriched.value == "evil.com"
