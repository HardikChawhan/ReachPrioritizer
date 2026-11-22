"""AI inference service: wraps ai/inference/predictor.py for the scan pipeline."""
from __future__ import annotations

import logging
import sys
from typing import Any, Dict, List

from app.config import MODEL_CHECKPOINT_DIR, MODEL_PREFERENCE, PROJECT_ROOT

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ai.inference.predictor import describe_checkpoints, get_predictor  # noqa: E402

logger = logging.getLogger(__name__)


def score_functions(nodes: List[Dict[str, Any]]) -> Dict[str, float]:
    """Return {node_id: vulnerability probability} for every function node with source."""
    predictor, selection = get_predictor(MODEL_PREFERENCE, MODEL_CHECKPOINT_DIR)
    targets = [n for n in nodes if n.get("node_type") != "Module" and (n.get("source") or "").strip()]
    if predictor is None or not targets:
        return {}
    probs = predictor.predict_proba([n["source"] for n in targets])
    return {n["id"]: round(p, 4) for n, p in zip(targets, probs)}


def model_selection() -> Dict[str, Any]:
    _, selection = get_predictor(MODEL_PREFERENCE, MODEL_CHECKPOINT_DIR)
    return selection


def checkpoint_overview() -> Dict[str, Any]:
    return describe_checkpoints(MODEL_CHECKPOINT_DIR)
