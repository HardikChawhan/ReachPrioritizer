"""Pydantic response / request models."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ProjectOut(BaseModel):
    project_id: str
    name: str
    file_count: int = 0
    size_bytes: int = 0
    created_at: str
    scan_count: Optional[int] = None
    last_scan_at: Optional[str] = None


class ScanStartRequest(BaseModel):
    project_id: str
    entry_points: Optional[List[str]] = Field(default=None, description="Extra entry points: 'file.js' or 'file.js:function'")


class ScanOut(BaseModel):
    scan_id: str
    project_id: str
    project_name: str
    status: str
    stage: Optional[str] = None
    progress: int = 0
    finding_count: int = 0
    error_message: Optional[str] = None
    model_used: Optional[str] = None
    analysis_mode: Optional[str] = None
    duration_ms: Optional[int] = None
    summary: Optional[Dict[str, Any]] = None
    created_at: str
    updated_at: str
    completed_at: Optional[str] = None


class PathStep(BaseModel):
    id: str
    name: str
    file_path: Optional[str] = None
    line: Optional[int] = None
    node_type: Optional[str] = None


class FindingOut(BaseModel):
    finding_id: str
    scan_id: str
    function_id: Optional[str] = None
    function_name: Optional[str] = None
    file_path: str
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    line: Optional[int] = None
    related_lines: List[int] = []
    snippet: Optional[str] = None
    prediction: Optional[str] = None
    vulnerability_probability: float = 0.0
    model_used: Optional[str] = None
    rule_id: Optional[str] = None
    title: Optional[str] = None
    rule_message: Optional[str] = None
    severity: Optional[str] = None
    cwe: Optional[str] = None
    category: Optional[str] = None
    sink: Optional[str] = None
    taint: str = "none"
    reachability_status: str = "unknown"
    entry_point: Optional[Dict[str, Any]] = None
    call_path: List[str] = []
    taint_path: List[str] = []
    risk_score: float = 0.0
    risk_category: Optional[str] = None
    risk_breakdown: Optional[Dict[str, Any]] = None
    finding_type: Optional[str] = None
    detector: Optional[str] = None
    created_at: str


class FindingDetailOut(FindingOut):
    source_code: Optional[str] = None
    call_path_steps: List[PathStep] = []
    taint_path_steps: List[PathStep] = []
