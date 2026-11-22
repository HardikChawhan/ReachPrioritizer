"""Optional Semgrep integration (enable with RP_ENABLE_SEMGREP=1).

Semgrep results are normalized to the analyzer's finding format: project-relative
paths, low/medium/high/critical severities and a single CWE id, so they can be
attached to call-graph functions and scored like every other finding.
"""
from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List

from app.config import ENABLE_SEMGREP, SEMGREP_CONFIG

logger = logging.getLogger(__name__)

SEVERITY = {"ERROR": "high", "WARNING": "medium", "INFO": "low", "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
CWE_RE = re.compile(r"CWE-(\d+)")


def available() -> bool:
    return ENABLE_SEMGREP and shutil.which("semgrep") is not None


def _relpath(p: str, root: Path) -> str:
    path = Path(p)
    if path.is_absolute():
        try:
            path = path.resolve().relative_to(root.resolve())
        except ValueError:
            pass
    text = path.as_posix()
    return text[2:] if text.startswith("./") else text


def scan(project_dir: Path) -> List[Dict[str, Any]]:
    if not available():
        return []
    try:
        proc = subprocess.run(
            ["semgrep", "scan", f"--config={SEMGREP_CONFIG}", "--json", "--quiet", "--metrics=off", "."],
            capture_output=True, text=True, timeout=300, cwd=str(project_dir),
        )
        data = json.loads(proc.stdout or "{}")
    except Exception as exc:  # pragma: no cover - depends on local semgrep
        logger.warning("Semgrep failed: %s", exc)
        return []
    out = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        meta = extra.get("metadata", {}) or {}
        cwe_raw = meta.get("cwe")
        cwe_text = " ".join(cwe_raw) if isinstance(cwe_raw, list) else str(cwe_raw or "")
        m = CWE_RE.search(cwe_text)
        line = (r.get("start") or {}).get("line", 0)
        out.append({
            "rule_id": f"semgrep.{r.get('check_id', 'unknown')}",
            "cwe": f"CWE-{m.group(1)}" if m else "CWE-Unknown",
            "title": (extra.get("message") or "Semgrep finding").split("\n")[0][:160],
            "message": extra.get("message", ""),
            "severity": SEVERITY.get(str(extra.get("severity", "")).upper(), "medium"),
            "category": "semgrep",
            "file_path": _relpath(r.get("path", ""), project_dir),
            "line": line,
            "snippet": (extra.get("lines") or "").strip()[:240],
            "taint": "none",
            "sink": None,
        })
    return out
