"""Project upload and management."""
from __future__ import annotations

import logging
import re
import uuid
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, File, Form, HTTPException, UploadFile

from app.config import MAX_ZIP_SIZE, UPLOAD_DIR
from app.core.orchestrator import run_scan
from app.core.upload_handler import UploadError, inspect_zip
from app.schemas.models import GitHubImportRequest, ProjectOut
from app.services import persistence as db
from app.services.github_import import GitHubImportError, download_repo

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/projects", tags=["projects"])


def _safe_name(name: str) -> str:
    base = Path(name or "project.zip").name
    return re.sub(r"[^A-Za-z0-9._-]+", "_", base)[:120] or "project.zip"


@router.post("/upload")
async def upload_project(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    name: Optional[str] = Form(None),
    auto_scan: bool = Form(True),
):
    """Upload a project ZIP; by default a scan starts immediately."""
    filename = _safe_name(file.filename or "")
    if not filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only .zip archives are accepted")

    project_id = str(uuid.uuid4())
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    dest = UPLOAD_DIR / f"{project_id}_{filename}"
    total = 0
    try:
        with open(dest, "wb") as out:
            while chunk := await file.read(1024 * 1024):
                total += len(chunk)
                if total > MAX_ZIP_SIZE:
                    raise HTTPException(status_code=413, detail=f"ZIP exceeds the {MAX_ZIP_SIZE // (1024 * 1024)} MB limit")
                out.write(chunk)
        info = inspect_zip(dest)
    except HTTPException:
        dest.unlink(missing_ok=True)
        raise
    except UploadError as exc:
        dest.unlink(missing_ok=True)
        raise HTTPException(status_code=400, detail=str(exc))

    project_name = (name or "").strip()[:120] or Path(filename).stem
    project = db.create_project(project_id, project_name, str(dest), info["source_files"], total)
    response = {"project": {k: v for k, v in project.items() if k != "upload_path"}, "scan": None}
    if auto_scan:
        response["scan"] = _start(background_tasks, project_id, project_name, filename)
    return response


def _start(background_tasks: BackgroundTasks, project_id: str, project_name: str, source_ref: Optional[str] = None) -> dict:
    scan_id = str(uuid.uuid4())
    scan = db.create_scan(scan_id, project_id, project_name, source_ref)
    background_tasks.add_task(run_scan, scan_id, project_id)
    return scan


def _remove_upload(path_str: Optional[str]) -> None:
    try:
        path = Path(path_str or "")
        if path.is_file() and UPLOAD_DIR.resolve() in path.resolve().parents:
            path.unlink(missing_ok=True)
    except OSError as exc:
        logger.warning("Could not remove upload %s: %s", path_str, exc)


def _github_download(url: str, branch: Optional[str], project_id: str):
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    dest = UPLOAD_DIR / f"{project_id}_{uuid.uuid4().hex[:8]}_github.zip"
    try:
        meta = download_repo(url, dest, branch)
        info = inspect_zip(dest)
    except GitHubImportError as exc:
        dest.unlink(missing_ok=True)
        raise HTTPException(status_code=400, detail=str(exc))
    except UploadError as exc:
        dest.unlink(missing_ok=True)
        raise HTTPException(status_code=400, detail=f"Repository rejected: {exc}")
    return dest, meta, info


@router.post("/from-github")
def import_from_github(payload: GitHubImportRequest, background_tasks: BackgroundTasks):
    """Download a public GitHub repository and (by default) scan it straight away."""
    project_id = str(uuid.uuid4())
    dest, meta, info = _github_download(payload.url, payload.branch, project_id)
    project_name = (payload.name or "").strip()[:120] or f"{meta['owner']}/{meta['repo']}"
    ref_label = meta["label"]
    project = db.create_project(project_id, project_name, str(dest), info["source_files"], int(meta["size"]),
                                source_type="github", source_url=str(meta["source_url"]), source_ref=ref_label)
    response = {"project": {k: v for k, v in project.items() if k != "upload_path"}, "scan": None, "github": {k: meta[k] for k in ("owner", "repo", "ref", "commit")}}
    if payload.auto_scan:
        response["scan"] = _start(background_tasks, project_id, project_name, ref_label)
    return response


@router.post("/{project_id}/refresh")
def refresh_from_github(project_id: str, background_tasks: BackgroundTasks, branch: Optional[str] = None):
    """Download the latest code of a GitHub project again and scan it (for Compare)."""
    p = db.get_project(project_id)
    if not p:
        raise HTTPException(status_code=404, detail="Project not found")
    if p.get("source_type") != "github" or not p.get("source_url"):
        raise HTTPException(status_code=400, detail="This project was uploaded as a ZIP; upload a new version instead")
    dest, meta, info = _github_download(p["source_url"], branch, project_id)
    old = p.get("upload_path")
    db.update_project_source(project_id, str(dest), info["source_files"], int(meta["size"]), meta["label"])
    if old != str(dest):
        _remove_upload(old)
    return {"scan": _start(background_tasks, project_id, p["name"], meta["label"]), "github": {k: meta[k] for k in ("owner", "repo", "ref", "commit")}}


@router.post("/{project_id}/version")
async def upload_new_version(project_id: str, background_tasks: BackgroundTasks, file: UploadFile = File(...), label: Optional[str] = Form(None)):
    """Upload a newer ZIP of an existing project (e.g. after fixing bugs) and scan it."""
    p = db.get_project(project_id)
    if not p:
        raise HTTPException(status_code=404, detail="Project not found")
    filename = _safe_name(file.filename or "")
    if not filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only .zip archives are accepted")
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    dest = UPLOAD_DIR / f"{project_id}_{uuid.uuid4().hex[:8]}_{filename}"
    total = 0
    try:
        with open(dest, "wb") as out:
            while chunk := await file.read(1024 * 1024):
                total += len(chunk)
                if total > MAX_ZIP_SIZE:
                    raise HTTPException(status_code=413, detail=f"ZIP exceeds the {MAX_ZIP_SIZE // (1024 * 1024)} MB limit")
                out.write(chunk)
        info = inspect_zip(dest)
    except HTTPException:
        dest.unlink(missing_ok=True)
        raise
    except UploadError as exc:
        dest.unlink(missing_ok=True)
        raise HTTPException(status_code=400, detail=str(exc))
    ref = (label or "").strip()[:80] or filename
    old = p.get("upload_path")
    db.update_project_source(project_id, str(dest), info["source_files"], total, ref)
    _remove_upload(old)
    return {"scan": _start(background_tasks, project_id, p["name"], ref)}


@router.get("/{project_id}/trend")
def project_trend(project_id: str):
    """Completed scans of a project, oldest first, with the numbers needed for a trend chart."""
    if not db.get_project(project_id):
        raise HTTPException(status_code=404, detail="Project not found")
    points = []
    for s in reversed(db.list_scans(project_id, 200)):
        if s["status"] != "completed":
            continue
        sm = s.get("summary") or {}
        cats = sm.get("by_risk_category") or {}
        points.append({
            "scan_id": s["scan_id"], "created_at": s["created_at"], "source_ref": s.get("source_ref"),
            "findings": sm.get("findings_total", s.get("finding_count", 0)),
            "actionable": sm.get("actionable", 0),
            "critical": cats.get("Critical", 0), "high": cats.get("High", 0), "medium": cats.get("Medium", 0), "low": cats.get("Low", 0),
            "max_risk": sm.get("max_risk", 0), "vulnerable_dependencies": (sm.get("dependencies") or {}).get("vulnerable_packages", 0),
        })
    return {"project_id": project_id, "points": points}


@router.get("", response_model=List[ProjectOut])
def list_projects():
    return [ProjectOut(**p) for p in db.list_projects()]


@router.get("/{project_id}", response_model=ProjectOut)
def get_project(project_id: str):
    p = db.get_project(project_id)
    if not p:
        raise HTTPException(status_code=404, detail="Project not found")
    return ProjectOut(**p)


@router.delete("/{project_id}")
def delete_project(project_id: str):
    p = db.delete_project(project_id)
    if not p:
        raise HTTPException(status_code=404, detail="Project not found")
    _remove_upload(p["upload_path"])
    return {"deleted": project_id}
