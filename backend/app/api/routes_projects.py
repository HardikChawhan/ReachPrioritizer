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
from app.schemas.models import ProjectOut
from app.services import persistence as db

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
        scan_id = str(uuid.uuid4())
        response["scan"] = db.create_scan(scan_id, project_id, project_name)
        background_tasks.add_task(run_scan, scan_id, project_id)
    return response


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
    try:
        path = Path(p["upload_path"])
        if path.is_file() and UPLOAD_DIR.resolve() in path.resolve().parents:
            path.unlink(missing_ok=True)
    except OSError as exc:
        logger.warning("Could not remove upload %s: %s", p["upload_path"], exc)
    return {"deleted": project_id}
