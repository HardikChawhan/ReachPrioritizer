"""AI model status, metrics and dataset summary."""
from __future__ import annotations

import json
from typing import Any, Dict

from fastapi import APIRouter

from app.config import PROJECT_ROOT
from app.services import ai_inference

router = APIRouter(prefix="/api/model", tags=["model"])


def _dataset_summary() -> Dict[str, Any]:
    path = PROJECT_ROOT / "reports" / "dataset_statistics.json"
    try:
        d = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    splits = d.get("splits", {})
    cwe = d.get("cwe_distribution", [])
    return {
        "total_samples": d.get("total_samples"),
        "vulnerable": d.get("label_dist", {}).get("vulnerable"),
        "benign": d.get("label_dist", {}).get("benign"),
        "vulnerable_ratio": d.get("label_dist", {}).get("vuln_fraction"),
        "repositories": d.get("repository_count"),
        "unique_cwes": d.get("unique_cwes"),
        "unique_cves": d.get("unique_cves"),
        "splits": {k: splits.get(k) for k in ("train", "validation", "test")},
        "top_cwes": cwe[:10] if isinstance(cwe, list) else [],
    }


@router.get("/status")
def model_status():
    selection = ai_inference.model_selection()
    return {
        "active_model": {k: selection.get(k) for k in ("model_name", "display_name", "threshold", "reason", "preference", "test_metrics")},
        "checkpoints": selection.get("checkpoints", {}),
        "load_errors": selection.get("load_errors", {}),
        "dataset": _dataset_summary(),
        "training": {
            "how_to": "python ai/training/train_codebert.py  (GPU recommended, see docs/AI_MODEL_AND_TRAINING.md)",
            "fallback": "python ai/training/train_fallback.py",
        },
    }
