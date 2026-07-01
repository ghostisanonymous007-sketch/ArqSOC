"""HTML scan report generator for ArqSOC using Jinja2."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from arqsoc.models.scan_result import ScanResult

TEMPLATE_DIR = Path(__file__).parent.parent / "templates"


def generate_html_report(result: ScanResult, output_path: Path | None = None) -> str:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html"]),
    )

    try:
        template = env.get_template("report.html.j2")
    except Exception:
        return _fallback_report(result)

    html = template.render(
        result=result,
        file_info=result.file_info,
        hashes=result.hashes,
        sections=result.sections,
        imports=result.imports,
        strings=result.strings,
        packer=result.packer,
        yara_matches=result.yara_matches,
        threat_level=result.threat_level.value,
        confidence=result.overall_confidence,
        indicators=result.threat_indicators,
        timeline=result.threat_timeline,
        generated=datetime.now().isoformat(),
        arqsoc_version="1.0.0",
    )

    if output_path is not None:
        output_path.write_text(html, encoding="utf-8")

    return html


def _fallback_report(result: ScanResult) -> str:
    lines: list[str] = []
    lines.append("<html><head><title>ArqSOC Report</title></head><body>")
    lines.append(f"<h1>ArqSOC Scan Report</h1>")
    lines.append(f"<h2>{result.file_info.name}</h2>")
    lines.append(f"<p>Path: {result.file_info.path}</p>")
    lines.append(f"<p>Size: {result.file_info.size} bytes</p>")
    lines.append(f"<p>Type: {result.file_info.binary_type.value}</p>")
    lines.append(f"<p>Architecture: {result.file_info.architecture.value}</p>")
    lines.append(f"<h3>Hashes</h3>")
    lines.append(f"<p>MD5: {result.hashes.md5}</p>")
    lines.append(f"<p>SHA256: {result.hashes.sha256}</p>")
    lines.append(f"<h3>Threat Assessment</h3>")
    lines.append(f"<p>Level: {result.threat_level.value}</p>")
    lines.append(f"<p>Confidence: {result.overall_confidence:.0%}</p>")
    lines.append(f"<p>Sections: {len(result.sections)}</p>")
    lines.append(f"<p>Imports: {len(result.imports)}</p>")
    lines.append(f"<p>Strings: {len(result.strings)}</p>")
    lines.append("</body></html>")
    return "\n".join(lines)
