"""CEF (Common Event Format) output for SIEM integration."""

from __future__ import annotations

from arqsoc.models.alert import Alert, AlertSeverity
from arqsoc.models.ioc import IOC

CEF_VERSION = "0"
CEF_VENDOR = "ArqSOC"
CEF_PRODUCT = "arqsoc"
CEF_PRODUCT_VERSION = "1.0"

SEVERITY_MAP = {
    AlertSeverity.INFO: "1",
    AlertSeverity.LOW: "2",
    AlertSeverity.MEDIUM: "4",
    AlertSeverity.HIGH: "6",
    AlertSeverity.CRITICAL: "8",
}


def format_cef_alert(alert: Alert) -> str:
    sig_id = alert.alert_id or "unknown"
    name = alert.title.replace("|", "\\|").replace("=", "\\=")[:512]
    severity = SEVERITY_MAP.get(alert.severity, "2")

    extensions: list[str] = []
    extensions.append(f"cn1={int(alert.confidence * 100)}")
    extensions.append(f"cn1Label=Confidence")
    extensions.append(f"msg={alert.description.replace('|', '\\|')[:1024]}")

    if alert.related_iocs:
        ioc_values = [i.value for i in alert.related_iocs[:5]]
        extensions.append(f"cs1={','.join(ioc_values)}")
        extensions.append(f"cs1Label=RelatedIOCs")

    if alert.mitre_techniques:
        extensions.append(f"cs2={','.join(alert.mitre_techniques[:5])}")
        extensions.append(f"cs2Label=MITRETechniques")

    if alert.source:
        extensions.append(f"cs3={alert.source}")
        extensions.append(f"cs3Label=Source")

    if alert.timestamp:
        extensions.append(f"end={alert.timestamp}")

    ext_str = " ".join(extensions)

    return f"CEF:{CEF_VERSION}|{CEF_VENDOR}|{CEF_PRODUCT}|{CEF_PRODUCT_VERSION}|{sig_id}|{name}|{severity}|{ext_str}"


def format_cef_ioc(ioc: IOC) -> str:
    name = f"IOC Detected: {ioc.ioc_type.value}"
    sig_id = f"ioc_{ioc.ioc_type.value}"

    risk_to_sev = {"info": "1", "low": "2", "medium": "4", "high": "6", "critical": "8"}
    severity = risk_to_sev.get(ioc.risk_level.value if hasattr(ioc.risk_level, "value") else str(ioc.risk_level), "2")

    extensions: list[str] = []
    extensions.append(f"msg={ioc.ioc_type.value} indicator: {ioc.value}")

    if ioc.context:
        extensions.append(f"cs1={ioc.context}")
        extensions.append(f"cs1Label=Context")

    if ioc.source:
        extensions.append(f"cs2={ioc.source}")
        extensions.append(f"cs2Label=Source")

    for k, v in ioc.threat_intel.items():
        safe_v = v.replace("|", "\\|").replace("=", "\\=")[:200]
        extensions.append(f"cs3={safe_v}")
        extensions.append(f"cs3Label=ThreatIntel")
        break

    ext_str = " ".join(extensions)

    return f"CEF:{CEF_VERSION}|{CEF_VENDOR}|{CEF_PRODUCT}|{CEF_PRODUCT_VERSION}|{sig_id}|{name}|{severity}|{ext_str}"


def alerts_to_cef(alerts: list[Alert]) -> list[str]:
    return [format_cef_alert(a) for a in alerts]


def iocs_to_cef(iocs: list[IOC]) -> list[str]:
    return [format_cef_ioc(i) for i in iocs]
