"""Threat intelligence enrichment - VT, AbuseIPDB, Shodan for ArqSOC."""

from __future__ import annotations

import json
import time
from pathlib import Path

import httpx

from arqsoc.config import get_api_key
from arqsoc.models.ioc import IOC, IOCType, RiskLevel

VT_API_URL = "https://www.virustotal.com/api/v3"
ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2"
SHODAN_API_URL = "https://api.shodan.io"

_cache: dict[str, tuple[float, dict[str, str]]] = {}
CACHE_TTL = 86400
VT_RATE_LIMIT = 15.0
_last_vt_request: list[float] = []


def _rate_limit_vt() -> None:
    global _last_vt_request
    now = time.time()
    _last_vt_request = [t for t in _last_vt_request if now - t < 60]
    if len(_last_vt_request) >= 4:
        oldest = _last_vt_request[0]
        wait = 60 - (now - oldest) + 1
        if wait > 0:
            time.sleep(wait)
    _last_vt_request.append(time.time())


def _cache_get(key: str) -> dict[str, str] | None:
    if key in _cache:
        ts, data = _cache[key]
        if time.time() - ts < CACHE_TTL:
            return data
    return None


def _cache_set(key: str, data: dict[str, str]) -> None:
    _cache[key] = (time.time(), data)


def enrich_vt_hash(hash_value: str, api_key: str | None = None) -> dict[str, str]:
    cache_key = f"vt_hash:{hash_value}"
    cached = _cache_get(cache_key)
    if cached:
        return cached

    if api_key is None:
        api_key = get_api_key("vt")
    if not api_key:
        return {"error": "No VT API key configured"}

    _rate_limit_vt()

    try:
        response = httpx.get(
            f"{VT_API_URL}/files/{hash_value}",
            headers={"x-apikey": api_key},
            timeout=30.0,
        )
        if response.status_code == 404:
            result: dict[str, str] = {"status": "not_found"}
            _cache_set(cache_key, result)
            return result
        if response.status_code != 200:
            return {"error": f"VT API returned {response.status_code}"}

        data = response.json()
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        positives = stats.get("malicious", 0)
        total = sum(stats.values())

        result = {
            "status": "found",
            "detection_ratio": f"{positives}/{total}",
            "positives": str(positives),
            "file_type": attrs.get("file_type", ""),
            "file_name": attrs.get("meaningful_name", ""),
            "threat_label": attrs.get("popular_threat_classification", {}).get("suggested_threat_label", ""),
        }
        _cache_set(cache_key, result)
        return result
    except Exception as e:
        return {"error": str(e)}


def enrich_vt_ip(ip: str, api_key: str | None = None) -> dict[str, str]:
    cache_key = f"vt_ip:{ip}"
    cached = _cache_get(cache_key)
    if cached:
        return cached

    if api_key is None:
        api_key = get_api_key("vt")
    if not api_key:
        return {"error": "No VT API key configured"}

    _rate_limit_vt()

    try:
        response = httpx.get(
            f"{VT_API_URL}/ip_addresses/{ip}",
            headers={"x-apikey": api_key},
            timeout=30.0,
        )
        if response.status_code == 404:
            result: dict[str, str] = {"status": "not_found"}
            _cache_set(cache_key, result)
            return result
        if response.status_code != 200:
            return {"error": f"VT API returned {response.status_code}"}

        data = response.json()
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        positives = stats.get("malicious", 0)
        total = sum(stats.values())

        result = {
            "status": "found",
            "detection_ratio": f"{positives}/{total}",
            "positives": str(positives),
            "country": attrs.get("country", ""),
            "asn": str(attrs.get("asn", "")),
            "as_owner": attrs.get("as_owner", ""),
            "reputation": str(attrs.get("reputation", 0)),
        }
        _cache_set(cache_key, result)
        return result
    except Exception as e:
        return {"error": str(e)}


def enrich_vt_domain(domain: str, api_key: str | None = None) -> dict[str, str]:
    cache_key = f"vt_domain:{domain}"
    cached = _cache_get(cache_key)
    if cached:
        return cached

    if api_key is None:
        api_key = get_api_key("vt")
    if not api_key:
        return {"error": "No VT API key configured"}

    _rate_limit_vt()

    try:
        response = httpx.get(
            f"{VT_API_URL}/domains/{domain}",
            headers={"x-apikey": api_key},
            timeout=30.0,
        )
        if response.status_code == 404:
            result: dict[str, str] = {"status": "not_found"}
            _cache_set(cache_key, result)
            return result
        if response.status_code != 200:
            return {"error": f"VT API returned {response.status_code}"}

        data = response.json()
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        positives = stats.get("malicious", 0)
        total = sum(stats.values())

        result = {
            "status": "found",
            "detection_ratio": f"{positives}/{total}",
            "positives": str(positives),
            "reputation": str(attrs.get("reputation", 0)),
        }
        _cache_set(cache_key, result)
        return result
    except Exception as e:
        return {"error": str(e)}


def enrich_abuseipdb(ip: str, api_key: str | None = None) -> dict[str, str]:
    cache_key = f"abuseipdb:{ip}"
    cached = _cache_get(cache_key)
    if cached:
        return cached

    if api_key is None:
        api_key = get_api_key("abuseipdb")
    if not api_key:
        return {"error": "No AbuseIPDB API key configured"}

    try:
        response = httpx.get(
            f"{ABUSEIPDB_API_URL}/check",
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
            headers={"Key": api_key, "Accept": "application/json"},
            timeout=30.0,
        )
        if response.status_code != 200:
            return {"error": f"AbuseIPDB API returned {response.status_code}"}

        data = response.json()
        result_data = data.get("data", {})

        result = {
            "status": "found",
            "abuse_confidence": str(result_data.get("abuseConfidenceScore", 0)),
            "total_reports": str(result_data.get("totalReports", 0)),
            "country": result_data.get("countryCode", ""),
            "isp": result_data.get("isp", ""),
            "domain": result_data.get("domain", ""),
        }
        _cache_set(cache_key, result)
        return result
    except Exception as e:
        return {"error": str(e)}


def enrich_shodan(ip: str, api_key: str | None = None) -> dict[str, str]:
    cache_key = f"shodan:{ip}"
    cached = _cache_get(cache_key)
    if cached:
        return cached

    if api_key is None:
        api_key = get_api_key("shodan")
    if not api_key:
        return {"error": "No Shodan API key configured"}

    try:
        response = httpx.get(
            f"{SHODAN_API_URL}/shodan/host/{ip}",
            params={"key": api_key},
            timeout=30.0,
        )
        if response.status_code == 404:
            result: dict[str, str] = {"status": "not_found"}
            _cache_set(cache_key, result)
            return result
        if response.status_code != 200:
            return {"error": f"Shodan API returned {response.status_code}"}

        data = response.json()
        ports = [str(p) for p in data.get("ports", [])]
        vulns = data.get("vulns", [])

        result = {
            "status": "found",
            "country": data.get("country_name", ""),
            "city": data.get("city", ""),
            "isp": data.get("isp", ""),
            "org": data.get("org", ""),
            "open_ports": ", ".join(ports[:10]),
            "vulns": ", ".join(str(v) for v in vulns[:5]),
            "total_vulns": str(len(vulns)),
        }
        _cache_set(cache_key, result)
        return result
    except Exception as e:
        return {"error": str(e)}


def enrich_ioc(ioc: IOC) -> IOC:
    enriched = ioc.model_copy()

    if enriched.ioc_type == IOCType.IPV4:
        intel: dict[str, str] = {}
        vt_result = enrich_vt_ip(enriched.value)
        if "error" not in vt_result:
            intel.update({f"vt_{k}": v for k, v in vt_result.items() if v})
            if int(vt_result.get("positives", "0")) > 5:
                enriched.risk_level = RiskLevel.HIGH

        abuse_result = enrich_abuseipdb(enriched.value)
        if "error" not in abuse_result:
            intel.update({f"abuse_{k}": v for k, v in abuse_result.items() if v})
            if int(abuse_result.get("abuse_confidence", "0")) > 50:
                enriched.risk_level = RiskLevel.CRITICAL

        shodan_result = enrich_shodan(enriched.value)
        if "error" not in shodan_result:
            intel.update({f"shodan_{k}": v for k, v in shodan_result.items() if v})

        enriched.threat_intel = intel

    elif enriched.ioc_type == IOCType.DOMAIN:
        intel = {}
        vt_result = enrich_vt_domain(enriched.value)
        if "error" not in vt_result:
            intel.update({f"vt_{k}": v for k, v in vt_result.items() if v})
            if int(vt_result.get("positives", "0")) > 5:
                enriched.risk_level = RiskLevel.HIGH

        enriched.threat_intel = intel

    elif enriched.ioc_type in (IOCType.HASH_MD5, IOCType.HASH_SHA256):
        intel = {}
        vt_result = enrich_vt_hash(enriched.value)
        if "error" not in vt_result:
            intel.update({f"vt_{k}": v for k, v in vt_result.items() if v})
            if int(vt_result.get("positives", "0")) > 10:
                enriched.risk_level = RiskLevel.CRITICAL
            elif int(vt_result.get("positives", "0")) > 3:
                enriched.risk_level = RiskLevel.HIGH

        enriched.threat_intel = intel

    return enriched
