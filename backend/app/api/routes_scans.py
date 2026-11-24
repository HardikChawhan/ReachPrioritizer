"""Scan execution, status, deletion and report export."""
from __future__ import annotations

import json
import re
import uuid
from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query
from fastapi.responses import Response

from app.core.orchestrator import run_scan
from app.schemas.models import ScanOut, ScanStartRequest
from app.services import exporters
from app.services.compare import compare_scans
from app.services import persistence as db

router = APIRouter(prefix="/api/scans", tags=["scans"])


@router.post("", response_model=ScanOut, status_code=202)
def start_scan(payload: ScanStartRequest, background_tasks: BackgroundTasks):
    project = db.get_project(payload.project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    scan = db.create_scan(str(uuid.uuid4()), project["project_id"], project["name"], project.get("source_ref"))
    background_tasks.add_task(run_scan, scan["scan_id"], project["project_id"], payload.entry_points)
    return ScanOut(**scan)


@router.get("", response_model=List[ScanOut])
def list_scans(project_id: Optional[str] = None, limit: int = Query(200, ge=1, le=1000)):
    return [ScanOut(**s) for s in db.list_scans(project_id, limit)]


@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: str):
    s = db.get_scan(scan_id)
    if not s:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanOut(**s)


@router.delete("/{scan_id}")
def delete_scan(scan_id: str):
    s = db.get_scan(scan_id)
    if not s:
        raise HTTPException(status_code=404, detail="Scan not found")
    if s["status"] in ("queued", "running"):
        raise HTTPException(status_code=409, detail="Scan is still running")
    db.delete_scan(scan_id)
    return {"deleted": scan_id}


@router.get("/{scan_id}/previous")
def previous_scan(scan_id: str):
    """The latest completed scan of the same project that is older than this one (for Compare)."""
    s = db.get_scan(scan_id)
    if not s:
        raise HTTPException(status_code=404, detail="Scan not found")
    for other in db.list_scans(s["project_id"], 500):
        if other["scan_id"] != scan_id and other["status"] == "completed" and other["created_at"] < s["created_at"]:
            return ScanOut(**other)
    return None


@router.get("/{base_id}/compare/{head_id}")
def compare(base_id: str, head_id: str):
    """Fixed / new / still-open findings and call-graph changes between two completed scans."""
    if base_id == head_id:
        raise HTTPException(status_code=400, detail="Pick two different scans")
    for sid in (base_id, head_id):
        s = db.get_scan(sid)
        if not s:
            raise HTTPException(status_code=404, detail=f"Scan {sid} not found")
        if s["status"] != "completed":
            raise HTTPException(status_code=409, detail=f"Scan {sid[:8]} has not completed")
    return compare_scans(base_id, head_id)


@router.get("/{scan_id}/entry-points")
def entry_points(scan_id: str):
    if not db.get_scan(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")
    return db.get_entry_points(scan_id)


@router.get("/{scan_id}/export")
def export(scan_id: str, format: str = Query("json", pattern="^(json|sarif|csv)$")):
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan["status"] != "completed":
        raise HTTPException(status_code=409, detail="Scan has not completed")
    findings = db.get_findings(scan_id)
    stem = re.sub(r"[^A-Za-z0-9_-]+", "_", scan["project_name"])[:60] or "scan"
    if format == "sarif":
        body = json.dumps(exporters.to_sarif(scan, findings), indent=2)
        media, ext = "application/sarif+json", "sarif"
    elif format == "csv":
        body, media, ext = exporters.to_csv(findings), "text/csv", "csv"
    else:
        body = json.dumps(exporters.to_json(scan, findings, db.get_entry_points(scan_id)), indent=2)
        media, ext = "application/json", "json"
    return Response(content=body, media_type=media,
                    headers={"Content-Disposition": f'attachment; filename="reachprioritizer_{stem}_{scan_id[:8]}.{ext}"'})
