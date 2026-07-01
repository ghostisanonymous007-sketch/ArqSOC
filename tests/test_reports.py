"""Tests for reports module."""

from __future__ import annotations

from pathlib import Path

from arqsoc.reports.html_report import generate_html_report, _fallback_report
from arqsoc.reports.incident_report import generate_incident_report, _fallback_incident_report
from arqsoc.models.scan_result import ScanResult, FileInfo, HashResult, BinaryType, ArchType
from arqsoc.models.incident import IncidentReport, RiskAssessment


def test_fallback_report() -> None:
    fi = FileInfo(path="/test", name="test.exe", size=1024, binary_type=BinaryType.PE64, architecture=ArchType.X64)
    result = ScanResult(file_info=fi, hashes=HashResult(md5="a" * 32, sha256="b" * 64))
    html = _fallback_report(result)
    assert "<html>" in html
    assert "test.exe" in html
    assert "ArqSOC" in html


def test_generate_html_report_fallback(tmp_path: Path) -> None:
    fi = FileInfo(path="/test", name="test.exe", size=1024, binary_type=BinaryType.PE64, architecture=ArchType.X64)
    result = ScanResult(file_info=fi, hashes=HashResult(md5="a" * 32, sha256="b" * 64))
    html = generate_html_report(result, output_path=tmp_path / "report.html")
    assert len(html) > 0


def test_fallback_incident_report() -> None:
    report = IncidentReport(title="Test Incident", risk_assessment=RiskAssessment(risk_score=0.75))
    html = _fallback_incident_report(report)
    assert "<html>" in html
    assert "Test Incident" in html


def test_generate_incident_report_fallback(tmp_path: Path) -> None:
    report = IncidentReport(title="Test IR", risk_assessment=RiskAssessment(risk_score=0.5))
    html = generate_incident_report(report, output_path=tmp_path / "incident.html")
    assert len(html) > 0
