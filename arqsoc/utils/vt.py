"""VirusTotal API client wrapper for ArqSOC."""

from __future__ import annotations

from arqsoc.core.threat_intel import enrich_vt_hash, enrich_vt_ip, enrich_vt_domain
from arqsoc.config import get_api_key


def vt_lookup_hash(hash_value: str, api_key: str | None = None) -> dict[str, str]:
    return enrich_vt_hash(hash_value, api_key=api_key)


def vt_lookup_ip(ip: str, api_key: str | None = None) -> dict[str, str]:
    return enrich_vt_ip(ip, api_key=api_key)


def vt_lookup_domain(domain: str, api_key: str | None = None) -> dict[str, str]:
    return enrich_vt_domain(domain, api_key=api_key)


def vt_auto_lookup(value: str, api_key: str | None = None) -> dict[str, str]:
    if api_key is None:
        api_key = get_api_key("vt")
    if not api_key:
        return {"error": "No VT API key configured"}

    if "." in value and not any(c.isalpha() and c not in "abcdefABCDEF" for c in value.replace(".", "")):
        if len(value.split(".")) == 4:
            return vt_lookup_ip(value, api_key)

    if len(value) in (32, 40, 64) and all(c in "0123456789abcdefABCDEF" for c in value):
        return vt_lookup_hash(value, api_key)

    if "." in value and any(c.isalpha() for c in value):
        return vt_lookup_domain(value, api_key)

    return {"error": f"Cannot determine lookup type for: {value}"}
