"""Centralized configuration for the ReachPrioritizer backend.

Every value can be overridden with an environment variable, so the project runs
on any machine without editing code.
"""
from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


# backend/app/config.py -> backend -> project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

# --- AI model ---------------------------------------------------------------
MODEL_CHECKPOINT_DIR = Path(os.environ.get("RP_CHECKPOINT_DIR", PROJECT_ROOT / "ai" / "checkpoints"))
CODEBERT_CHECKPOINT_DIR = MODEL_CHECKPOINT_DIR / "codebert_vuln_classifier"
FALLBACK_CHECKPOINT_DIR = MODEL_CHECKPOINT_DIR / "tfidf_fallback"
# "auto" picks the model with the best measured test F1; "tfidf" / "codebert" force one.
MODEL_PREFERENCE = os.environ.get("RP_MODEL", "auto").lower()

# --- Analyzer (Node.js) -------------------------------------------------------
ANALYZER_DIR = PROJECT_ROOT / "analyzer"
ANALYZER_SCRIPT = ANALYZER_DIR / "analyze.js"
NODE_EXE = os.environ.get("NODE_EXE") or shutil.which("node") or "node"
ANALYZER_TIMEOUT_SEC = _env_int("RP_ANALYZER_TIMEOUT", 600)

# --- Optional Semgrep ---------------------------------------------------------
ENABLE_SEMGREP = os.environ.get("RP_ENABLE_SEMGREP", "0") == "1"
SEMGREP_CONFIG = os.environ.get("RP_SEMGREP_CONFIG", "p/javascript")

# --- Uploads ------------------------------------------------------------------
UPLOAD_DIR = Path(os.environ.get("RP_UPLOAD_DIR", Path(tempfile.gettempdir()) / "reachprioritizer_uploads"))
MAX_ZIP_SIZE = _env_int("RP_MAX_ZIP_MB", 100) * 1024 * 1024
MAX_FILES_IN_ZIP = _env_int("RP_MAX_FILES_IN_ZIP", 20000)
MAX_UNCOMPRESSED_SIZE = _env_int("RP_MAX_UNCOMPRESSED_MB", 500) * 1024 * 1024
MAX_SINGLE_FILE_SIZE = _env_int("RP_MAX_FILE_MB", 20) * 1024 * 1024
MAX_COMPRESSION_RATIO = _env_int("RP_MAX_COMPRESSION_RATIO", 200)
ALLOWED_EXTRACT_EXTENSIONS = {
    ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts", ".json",
}

# --- Scanning -----------------------------------------------------------------
MAX_CONCURRENT_SCANS = _env_int("RP_MAX_CONCURRENT_SCANS", 2)
# AI-only findings (no rule fired) are reported only above this probability,
# because the function-level classifier alone has low precision.
AI_ONLY_MIN_PROBABILITY = float(os.environ.get("RP_AI_ONLY_MIN_PROB", "0.85"))

# --- Storage ------------------------------------------------------------------
DB_PATH = Path(os.environ.get("RP_DB_PATH", PROJECT_ROOT / "backend" / "reachprioritizer.db"))

# --- HTTP ---------------------------------------------------------------------
CORS_ORIGINS = [
    o.strip()
    for o in os.environ.get(
        "RP_CORS_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173,http://localhost:4173,http://localhost:3000",
    ).split(",")
    if o.strip()
]

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
