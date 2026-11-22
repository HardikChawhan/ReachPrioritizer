"""Experimental evaluation results (produced by evaluation/scripts/run_experiments.py)."""
from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException

from app.config import PROJECT_ROOT

router = APIRouter(prefix="/api/evaluation", tags=["evaluation"])
RESULTS = PROJECT_ROOT / "evaluation" / "results" / "comparative_evaluation.json"


@router.get("")
def get_evaluation():
    if not RESULTS.exists():
        raise HTTPException(status_code=404, detail="No evaluation results yet. Run: python evaluation/scripts/run_experiments.py")
    return json.loads(RESULTS.read_text(encoding="utf-8"))
