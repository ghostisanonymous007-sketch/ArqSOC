"""Tests for core MITRE mapper module."""

from __future__ import annotations

from arqsoc.core.mitre_mapper import (
    map_imports_to_mitre,
    map_strings_to_mitre,
    build_mitre_report,
)
from arqsoc.models.scan_result import ImportEntry, ClassifiedString, StringClassification


def test_map_imports_injection() -> None:
    imports = [
        ImportEntry(name="VirtualAllocEx", dll="kernel32.dll"),
        ImportEntry(name="WriteProcessMemory", dll="kernel32.dll"),
        ImportEntry(name="CreateRemoteThread", dll="kernel32.dll"),
    ]
    mappings = map_imports_to_mitre(imports)
    assert len(mappings) > 0
    techniques = [m.technique_id for m in mappings]
    assert "T1055.012" in techniques


def test_map_imports_network() -> None:
    imports = [
        ImportEntry(name="InternetOpenA", dll="wininet.dll"),
        ImportEntry(name="HttpOpenRequestA", dll="wininet.dll"),
    ]
    mappings = map_imports_to_mitre(imports)
    techniques = [m.technique_id for m in mappings]
    assert "T1071.001" in techniques


def test_map_strings_url() -> None:
    strings = [
        ClassifiedString(value="https://evil.com/payload", classification=StringClassification.URL),
        ClassifiedString(value="HKEY_LOCAL_MACHINE\\Software", classification=StringClassification.REGISTRY),
    ]
    mappings = map_strings_to_mitre(strings)
    assert len(mappings) > 0


def test_build_mitre_report() -> None:
    imports = [ImportEntry(name="VirtualAllocEx", dll="kernel32.dll")]
    strings = [ClassifiedString(value="https://evil.com", classification=StringClassification.URL)]
    indicators: list[object] = []
    mappings = build_mitre_report(imports, strings, indicators)
    assert len(mappings) > 0
    for m in mappings:
        assert m.technique_id
        assert m.tactic


def test_map_imports_empty() -> None:
    mappings = map_imports_to_mitre([])
    assert mappings == []
