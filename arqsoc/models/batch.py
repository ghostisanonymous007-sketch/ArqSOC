"""Batch triage result models for ArqSOC."""

from __future__ import annotations

from pydantic import BaseModel


class TriageResult(BaseModel):
    file_path: str = ""
    priority: str = "normal"
    risk_score: float = 0.0
    vt_detections: str = ""
    entropy: float = 0.0
    is_packed: bool = False
    suspicious_strings_count: int = 0
    summary: str = ""
    sha256: str = ""
    file_size: int = 0
