"""AbuseIPDB API client wrapper for ArqSOC."""

from __future__ import annotations

from arqsoc.core.threat_intel import enrich_abuseipdb
from arqsoc.config import get_api_key


def abuseipdb_lookup(ip: str, api_key: str | None = None) -> dict[str, str]:
    return enrich_abuseipdb(ip, api_key=api_key)
