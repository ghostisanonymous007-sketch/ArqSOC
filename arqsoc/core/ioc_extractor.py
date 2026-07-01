"""IOC extractor - extract IPs, domains, URLs, C2 indicators from binaries."""

from __future__ import annotations

import re
from pathlib import Path

from arqsoc.models.ioc import IOC, IOCType, RiskLevel

PRIVATE_IPV4 = re.compile(
    r"^(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)"
)
LOOPBACK_IPV4 = re.compile(r"^127\.")
LINK_LOCAL = re.compile(r"^169\.254\.")
MULTICAST = re.compile(r"^(?:22[4-9]|23[0-9])\.")
RESERVED = re.compile(r"^(?:0\.|240\.|24[1-9]|25[0-5]\.)")

IPV4_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
IPV6_PATTERN = re.compile(
    r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,7}:"
    r"|:(?:[0-9a-fA-F]{1,4}:){1,7}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"
)
DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|io|xyz|top|info|biz|cc|ru|cn|tk|ml|ga|cf|gq|pw|me|tv|co|us|uk|de|fr|it|es|nl|be|at|ch|se|no|dk|fi|pl|cz|sk|hu|ro|bg|hr|si|rs|ba|me|mk|al|mt|lv|lt|ee|lu|ie|pt|gr|cy|mt|is|li|mc|va|sm|ad)\b",
    re.IGNORECASE,
)
URL_PATTERN = re.compile(r"https?://[^\s<>\"']+")
EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
MUTEX_PATTERN = re.compile(r"(?:Global|Local)\\{?[A-Fa-f0-9-]+}?")
REGISTRY_PATTERN = re.compile(r"[Hh][Kk][Ee][Yy]_[A-Za-z_\\]+")

BASE64_PATTERN = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")

CDN_DOMAIN_KEYWORDS = {
    "cloudfront", "akamai", "cloudflare", "fastly", "azureedge",
    "amazonaws", "googleapis", "googleusercontent", "github",
    "githubusercontent", "microsoft", "windows", "mozilla",
    "apple", "cdn", "akamaiedge", "akamaized",
}

SINKHOLE_KEYWORDS = {
    "sinkhole", "malwaretrafficking", "danger", "sinking",
    "mandiant", "talos", "kaspersky", "virustotal",
}

C2_INDICATORS = {
    "beacon", "callback", "c2", "cnc", "command", "exfil",
    "shell", "reverse", "bind", "connect", "botnet",
}


def _is_internal_ip(ip: str) -> bool:
    return bool(PRIVATE_IPV4.match(ip) or LOOPBACK_IPV4.match(ip) or LINK_LOCAL.match(ip) or MULTICAST.match(ip) or RESERVED.match(ip))


def _is_cdn_domain(domain: str) -> bool:
    lower = domain.lower()
    return any(kw in lower for kw in CDN_DOMAIN_KEYWORDS)


def _is_sinkhole(domain: str) -> bool:
    lower = domain.lower()
    return any(kw in lower for kw in SINKHOLE_KEYWORDS)


def _decode_base64_iocs(text: str) -> list[IOC]:
    results: list[IOC] = []
    import base64

    for m in BASE64_PATTERN.finditer(text):
        try:
            decoded = base64.b64decode(m.group(), validate=True).decode("utf-8", errors="strict")
            urls = URL_PATTERN.findall(decoded)
            ips = IPV4_PATTERN.findall(decoded)
            domains = DOMAIN_PATTERN.findall(decoded)
            for url in urls:
                results.append(IOC(ioc_type=IOCType.URL, value=url, context=f"base64-decoded: {m.group()[:40]}", risk_level=RiskLevel.HIGH, source="base64_decode"))
            for ip in ips:
                if not _is_internal_ip(ip):
                    results.append(IOC(ioc_type=IOCType.IPV4, value=ip, context=f"base64-decoded: {m.group()[:40]}", risk_level=RiskLevel.HIGH, source="base64_decode"))
            for dom in domains:
                if not _is_cdn_domain(dom):
                    results.append(IOC(ioc_type=IOCType.DOMAIN, value=dom, context=f"base64-decoded: {m.group()[:40]}", risk_level=RiskLevel.MEDIUM, source="base64_decode"))
        except Exception:
            pass

    return results


def extract_iocs(file_path: Path) -> list[IOC]:
    try:
        data = file_path.read_bytes()
    except OSError:
        return []

    text = data.decode("ascii", errors="ignore")
    iocs: list[IOC] = []
    seen: set[str] = set()

    for m in IPV4_PATTERN.finditer(text):
        ip = m.group()
        key = f"ipv4:{ip}"
        if key in seen:
            continue
        seen.add(key)
        if _is_internal_ip(ip):
            risk = RiskLevel.INFO
            context = "internal/private IP"
        else:
            risk = RiskLevel.MEDIUM
            context = "public IP"
        iocs.append(IOC(ioc_type=IOCType.IPV4, value=ip, context=context, risk_level=risk, source="binary_strings"))

    for m in IPV6_PATTERN.finditer(text):
        ip = m.group()
        key = f"ipv6:{ip}"
        if key in seen:
            continue
        seen.add(key)
        iocs.append(IOC(ioc_type=IOCType.IPV6, value=ip, context="IPv6 address", risk_level=RiskLevel.MEDIUM, source="binary_strings"))

    for m in URL_PATTERN.finditer(text):
        url = m.group().rstrip("',\")")
        key = f"url:{url}"
        if key in seen:
            continue
        seen.add(key)
        lower_url = url.lower()
        if any(kw in lower_url for kw in C2_INDICATORS):
            risk = RiskLevel.CRITICAL
            context = "potential C2 URL"
        elif any(kw in lower_url for kw in CDN_DOMAIN_KEYWORDS):
            risk = RiskLevel.LOW
            context = "CDN/known domain"
        else:
            risk = RiskLevel.HIGH
            context = "external URL"
        iocs.append(IOC(ioc_type=IOCType.URL, value=url, context=context, risk_level=risk, source="binary_strings"))

    url_domains: set[str] = set()
    for m in URL_PATTERN.finditer(text):
        url = m.group()
        try:
            host = url.split("//")[1].split("/")[0].split(":")[0]
            url_domains.add(host.lower())
        except (IndexError, ValueError):
            pass

    for m in DOMAIN_PATTERN.finditer(text):
        domain = m.group()
        key = f"domain:{domain.lower()}"
        if key in seen:
            continue
        seen.add(key)
        if domain.lower() in url_domains:
            continue
        if _is_cdn_domain(domain):
            risk = RiskLevel.INFO
            context = "CDN/known domain"
        elif _is_sinkhole(domain):
            risk = RiskLevel.HIGH
            context = "sinkhole domain"
        else:
            risk = RiskLevel.MEDIUM
            context = "external domain"
        iocs.append(IOC(ioc_type=IOCType.DOMAIN, value=domain, context=context, risk_level=risk, source="binary_strings"))

    for m in EMAIL_PATTERN.finditer(text):
        email = m.group()
        key = f"email:{email.lower()}"
        if key in seen:
            continue
        seen.add(key)
        iocs.append(IOC(ioc_type=IOCType.EMAIL, value=email, context="email address", risk_level=RiskLevel.LOW, source="binary_strings"))

    for m in MUTEX_PATTERN.finditer(text):
        mutex = m.group()
        key = f"mutex:{mutex}"
        if key in seen:
            continue
        seen.add(key)
        iocs.append(IOC(ioc_type=IOCType.MUTEX, value=mutex, context="mutex name", risk_level=RiskLevel.MEDIUM, source="binary_strings"))

    for m in REGISTRY_PATTERN.finditer(text):
        reg = m.group()
        key = f"registry:{reg.lower()}"
        if key in seen:
            continue
        seen.add(key)
        iocs.append(IOC(ioc_type=IOCType.REGISTRY, value=reg, context="registry key", risk_level=RiskLevel.MEDIUM, source="binary_strings"))

    decoded_iocs = _decode_base64_iocs(text)
    for ioc in decoded_iocs:
        key = f"{ioc.ioc_type.value}:{ioc.value.lower()}"
        if key not in seen:
            seen.add(key)
            iocs.append(ioc)

    return iocs
