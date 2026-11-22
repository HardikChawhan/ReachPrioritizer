"""Findings: filtered lists and full detail with resolved attack paths."""
from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, HTTPException, Query

from app.schemas.models import FindingDetailOut, FindingOut, PathStep
from app.services import persistence as db

router = APIRouter(prefix="/api/scans", tags=["findings"])


def _match(value: Optional[str], wanted: Optional[str]) -> bool:
    if not wanted:
        return True
    allowed = {w.strip().lower() for w in wanted.split(",") if w.strip()}
    return (value or "").lower() in allowed


@router.get("/{scan_id}/findings", response_model=List[FindingOut])
def list_findings(
    scan_id: str,
    severity: Optional[str] = Query(None, description="Comma list: critical,high,medium,low"),
    reachability: Optional[str] = Query(None, description="Comma list: reachable,startup_only,unreachable,unknown"),
    category: Optional[str] = Query(None, description="Risk category: Critical,High,Medium,Low"),
    taint: Optional[str] = Query(None, description="user_input,parameter,none,unknown"),
    finding_type: Optional[str] = Query(None, description="static_finding,ai_prediction"),
    q: Optional[str] = Query(None, description="Search in file, function, CWE, title"),
    sort: str = Query("risk", pattern="^(risk|severity|file|ai)$"),
):
    if not db.get_scan(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")
    needle = (q or "").lower().strip()
    out = []
    for f in db.get_findings(scan_id, sort=sort):
        if not (_match(f.get("severity"), severity) and _match(f.get("reachability_status"), reachability)
                and _match(f.get("risk_category"), category) and _match(f.get("taint"), taint)
                and _match(f.get("finding_type"), finding_type)):
            continue
        if needle and not any(needle in (f.get(k) or "").lower() for k in ("file_path", "function_name", "cwe", "title", "rule_message")):
            continue
        out.append(FindingOut(**f))
    return out


def _steps(scan_id: str, ids: List[str]) -> List[PathStep]:
    nodes = db.get_nodes_by_ids(scan_id, ids)
    steps = []
    for i in ids:
        n = nodes.get(i)
        if n:
            steps.append(PathStep(id=i, name=n["name"], file_path=n.get("file_path"), line=n.get("line"), node_type=n.get("node_type")))
        else:
            file_path, _, name = i.partition("::")
            steps.append(PathStep(id=i, name=name or i, file_path=file_path or None))
    return steps


@router.get("/{scan_id}/findings/{finding_id}", response_model=FindingDetailOut)
def get_finding(scan_id: str, finding_id: str):
    f = db.get_finding(finding_id)
    if not f or f.get("scan_id") != scan_id:
        raise HTTPException(status_code=404, detail="Finding not found")
    return FindingDetailOut(
        **f,
        call_path_steps=_steps(scan_id, f.get("call_path") or []),
        taint_path_steps=_steps(scan_id, f.get("taint_path") or []),
    )
