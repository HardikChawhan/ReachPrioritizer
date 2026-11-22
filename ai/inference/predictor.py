"""
Vulnerability classifier used by the ReachPrioritizer backend and evaluation.

Two models can be available:
  * TF-IDF + Logistic Regression  (ai/checkpoints/tfidf_fallback)      — fast, CPU
  * Fine-tuned CodeBERT           (ai/checkpoints/codebert_vuln_classifier) — GPU/CPU

Model selection ("auto"): the model with the best *measured* test F1 is used.
A CodeBERT checkpoint produced by a --quick-test run, or one without recorded test
metrics, is never auto-selected (the old prototype shipped such a checkpoint with
validation F1 = 0.0, which silently disabled the AI layer).
"""
from __future__ import annotations

import json
import logging
import re
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CHECKPOINT_DIR = PROJECT_ROOT / "ai" / "checkpoints"
DEFAULT_THRESHOLD = 0.5


def normalize_source(src: str) -> str:
    """Identical to preprocessing/normalize.js -> normalizeSource (train/inference parity)."""
    if not isinstance(src, str):
        return ""
    s = src.replace("\r\n", "\n").replace("\r", "\n")
    s = re.sub(r"[ \t]+\n", "\n", s)
    s = re.sub(r"\n{3,}", "\n\n", s)
    return s.strip()


def _read_json(path: Path) -> Optional[Dict[str, Any]]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Predictors
# ---------------------------------------------------------------------------
class TfidfPredictor:
    name = "tfidf_logreg"
    display_name = "TF-IDF + Logistic Regression"

    def __init__(self, ckpt_dir: Path):
        import joblib  # type: ignore

        self.dir = ckpt_dir
        self.vectorizer = joblib.load(ckpt_dir / "vectorizer.joblib")
        self.classifier = joblib.load(ckpt_dir / "classifier.joblib")
        meta = _read_json(ckpt_dir / "metadata.json") or {}
        self.threshold = float(meta.get("threshold", DEFAULT_THRESHOLD))

    def predict_proba(self, sources: List[str]) -> List[float]:
        if not sources:
            return []
        X = self.vectorizer.transform([normalize_source(s) for s in sources])
        return [float(p[1]) for p in self.classifier.predict_proba(X)]


class CodeBertPredictor:
    name = "codebert"
    display_name = "CodeBERT (fine-tuned)"

    def __init__(self, ckpt_dir: Path, batch_size: int = 16):
        import torch  # type: ignore
        from transformers import AutoModelForSequenceClassification, AutoTokenizer  # type: ignore

        self.torch = torch
        self.dir = ckpt_dir
        meta = _read_json(ckpt_dir / "train_meta.json") or {}
        self.max_length = int(meta.get("max_length", 512))
        self.threshold = float(meta.get("threshold", DEFAULT_THRESHOLD))
        self.batch_size = batch_size
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.tokenizer = AutoTokenizer.from_pretrained(str(ckpt_dir))
        self.model = AutoModelForSequenceClassification.from_pretrained(str(ckpt_dir)).to(self.device)
        self.model.eval()

    def predict_proba(self, sources: List[str]) -> List[float]:
        out: List[float] = []
        torch = self.torch
        texts = [normalize_source(s) for s in sources]
        for i in range(0, len(texts), self.batch_size):
            batch = texts[i:i + self.batch_size]
            enc = self.tokenizer(batch, truncation=True, max_length=self.max_length, padding=True, return_tensors="pt")
            enc = {k: v.to(self.device) for k, v in enc.items()}
            with torch.no_grad():
                logits = self.model(**enc).logits
                probs = torch.softmax(logits.float(), dim=-1)[:, 1]
            out.extend(float(p) for p in probs.cpu().tolist())
        return out


# ---------------------------------------------------------------------------
# Model registry / selection
# ---------------------------------------------------------------------------
def describe_checkpoints(ckpt_root: Path = DEFAULT_CHECKPOINT_DIR) -> Dict[str, Dict[str, Any]]:
    """Recorded metrics of every checkpoint on disk."""
    info: Dict[str, Dict[str, Any]] = {}
    tf_dir = ckpt_root / "tfidf_fallback"
    if (tf_dir / "vectorizer.joblib").exists() and (tf_dir / "classifier.joblib").exists():
        ev = _read_json(tf_dir / "evaluation_results.json") or {}
        meta = _read_json(tf_dir / "metadata.json") or {}
        info["tfidf_logreg"] = {
            "available": True,
            "display_name": TfidfPredictor.display_name,
            "dir": str(tf_dir),
            "test_metrics": ev.get("test_metrics"),
            "val_metrics": ev.get("val_metrics"),
            "threshold": float(meta.get("threshold", DEFAULT_THRESHOLD)),
            "eligible": ev.get("test_metrics") is not None,
            "note": None,
        }
    cb_dir = ckpt_root / "codebert_vuln_classifier"
    has_weights = (cb_dir / "model.safetensors").exists() or (cb_dir / "pytorch_model.bin").exists()
    if cb_dir.exists():
        meta = _read_json(cb_dir / "train_meta.json") or {}
        quick = bool(meta.get("quick_test", False)) or meta.get("test_metrics") is None
        note = None
        if not has_weights:
            note = "weights file missing (train with ai/training/train_codebert.py)"
        elif meta.get("quick_test"):
            note = "pipeline smoke-test checkpoint (--quick-test); not used automatically"
        elif meta.get("test_metrics") is None:
            note = "no recorded test metrics; retrain with the current training script"
        info["codebert"] = {
            "available": has_weights,
            "display_name": CodeBertPredictor.display_name,
            "dir": str(cb_dir),
            "test_metrics": meta.get("test_metrics"),
            "val_metrics": meta.get("val_metrics") or ({"f1": meta.get("best_val_f1")} if "best_val_f1" in meta else None),
            "threshold": float(meta.get("threshold", DEFAULT_THRESHOLD)),
            "eligible": has_weights and not quick,
            "note": note,
            "trained_on": meta.get("device"),
            "epochs": meta.get("epochs_trained"),
        }
    return info


_lock = threading.Lock()
_cache: Dict[str, Any] = {}


def get_predictor(preference: str = "auto", ckpt_root: Path = DEFAULT_CHECKPOINT_DIR):
    """Return (predictor, selection_info). Cached per (preference, root)."""
    key = f"{preference}|{ckpt_root}"
    with _lock:
        if key in _cache:
            return _cache[key]
        info = describe_checkpoints(ckpt_root)
        order: List[str]
        reason: str
        if preference in ("tfidf", "tfidf_logreg"):
            order, reason = ["tfidf_logreg"], "forced by RP_MODEL=tfidf"
        elif preference == "codebert":
            order, reason = ["codebert", "tfidf_logreg"], "forced by RP_MODEL=codebert"
        else:
            eligible = [k for k, v in info.items() if v.get("eligible")]
            eligible.sort(key=lambda k: ((info[k].get("test_metrics") or {}).get("f1") or 0.0), reverse=True)
            order = eligible + [k for k in info if k not in eligible]
            reason = "highest recorded test F1" if eligible else "only available model"
        predictor = None
        chosen = None
        errors: Dict[str, str] = {}
        for name in order:
            try:
                if name == "codebert" and info.get("codebert", {}).get("available"):
                    predictor = CodeBertPredictor(Path(info["codebert"]["dir"]))
                elif name == "tfidf_logreg" and info.get("tfidf_logreg", {}).get("available"):
                    predictor = TfidfPredictor(Path(info["tfidf_logreg"]["dir"]))
                if predictor is not None:
                    chosen = name
                    break
            except Exception as exc:  # missing torch, corrupt checkpoint, ...
                errors[name] = str(exc)
                logger.warning("Could not load %s: %s", name, exc)
        selection = {
            "model_name": chosen or "none",
            "display_name": predictor.display_name if predictor else "No model available",
            "threshold": predictor.threshold if predictor else DEFAULT_THRESHOLD,
            "reason": reason if chosen else "no checkpoint could be loaded",
            "preference": preference,
            "checkpoints": info,
            "load_errors": errors,
        }
        if chosen:
            selection["test_metrics"] = info[chosen].get("test_metrics")
        _cache[key] = (predictor, selection)
        return predictor, selection


def reset_cache() -> None:
    with _lock:
        _cache.clear()
