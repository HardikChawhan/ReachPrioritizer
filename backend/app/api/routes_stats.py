"""Dashboard-level statistics across all projects."""
from __future__ import annotations

from fastapi import APIRouter

from app.services import persistence as db

router = APIRouter(prefix="/api/stats", tags=["stats"])


@router.get("")
def stats():
    return db.global_stats()
