"""Incident report generator for ArqSOC using Jinja2."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from arqsoc.models.incident import IncidentReport

TEMPLATE_DIR = Path(__file__).parent.parent / "templates"


def generate_incident_report(report: IncidentReport, output_path: Path | None = None) -> str:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html"]),
    )

    try:
        template = env.get_template("incident.html.j2")
    except Exception:
        return _fallback_incident_report(report)

    html = template.render(
        report=report,
        generated=datetime.now().isoformat(),
        arqsoc_version="1.0.0",
    )

    if output_path is not None:
        output_path.write_text(html, encoding="utf-8")

    return html


def _fallback_incident_report(report: IncidentReport) -> str:
    lines: list[str] = []
    lines.append("<html><head><title>ArqSOC Incident Report</title></head><body>")
    lines.append("<h1>ArqSOC Incident Report</h1>")
    lines.append(f"<h2>{report.title or 'Untitled Incident'}</h2>")
    lines.append(f"<p>Date: {report.date}</p>")
    lines.append(f"<p>Summary: {report.summary}</p>")
    lines.append(f"<h3>IOCs ({len(report.iocs)})</h3>")
    lines.append("<ul>")
    for ioc in report.iocs[:20]:
        lines.append(f"<li>[{ioc.ioc_type.value}] {ioc.value} - {ioc.risk_level.value}</li>")
    lines.append("</ul>")
    lines.append(f"<h3>Alerts ({len(report.alerts)})</h3>")
    lines.append("<ul>")
    for alert in report.alerts[:20]:
        lines.append(f"<li>[{alert.severity.value}] {alert.title}</li>")
    lines.append("</ul>")
    lines.append(f"<h3>MITRE ATT&CK ({len(report.mitre_mappings)})</h3>")
    lines.append("<ul>")
    for m in report.mitre_mappings[:20]:
        lines.append(f"<li>{m.technique_id} - {m.name} ({m.tactic})</li>")
    lines.append("</ul>")
    lines.append(f"<h3>Timeline ({len(report.timeline)})</h3>")
    lines.append("<ul>")
    for entry in report.timeline[:20]:
        lines.append(f"<li>[{entry.severity}] {entry.timestamp} - {entry.description}</li>")
    lines.append("</ul>")
    lines.append(f"<h3>Risk Assessment</h3>")
    lines.append(f"<p>Score: {report.risk_assessment.risk_score:.0%}</p>")
    lines.append("<h3>Recommendations</h3>")
    lines.append("<ol>")
    for rec in report.recommendations:
        lines.append(f"<li>{rec}</li>")
    lines.append("</ol>")
    lines.append("</body></html>")
    return "\n".join(lines)
