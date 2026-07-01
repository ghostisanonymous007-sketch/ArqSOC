"""Shodan API client wrapper for ArqSOC."""

from __future__ import annotations

from arqsoc.core.threat_intel import enrich_shodan
from arqsoc.config import get_api_key


def shodan_lookup(ip: str, api_key: str | None = None) -> dict[str, str]:
    return enrich_shodan(ip, api_key=api_key)
