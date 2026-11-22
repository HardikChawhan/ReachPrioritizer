"""Runs the Node.js analysis engine (analyzer/analyze.js) and returns its JSON result."""
from __future__ import annotations

import json
import logging
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.config import ANALYZER_SCRIPT, ANALYZER_TIMEOUT_SEC, NODE_EXE, PROJECT_ROOT

logger = logging.getLogger(__name__)


class AnalyzerError(RuntimeError):
    """The static analysis engine could not run."""


def run_analyzer(project_dir: Path, entry_points: Optional[List[str]] = None, with_source: bool = True) -> Dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="rp_an_") as tmp:
        out = Path(tmp) / "analysis.json"
        cmd = [NODE_EXE, str(ANALYZER_SCRIPT), "--project", str(project_dir), "--output", str(out)]
        if with_source:
            cmd.append("--with-source")
        if entry_points:
            cmd += ["--entry-points", ",".join(entry_points)]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=ANALYZER_TIMEOUT_SEC, cwd=str(PROJECT_ROOT),
            )
        except FileNotFoundError as exc:
            raise AnalyzerError(
                f"Node.js was not found ({NODE_EXE}). Install Node.js 18+ or set NODE_EXE."
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise AnalyzerError(f"Static analysis timed out after {ANALYZER_TIMEOUT_SEC}s") from exc
        if proc.returncode != 0 or not out.exists():
            tail = (proc.stderr or proc.stdout or "").strip()[-1500:]
            if "Cannot find module" in tail:
                tail += "\nHint: run `npm install` in the project root (installs @babel/parser and minimist)."
            raise AnalyzerError(f"Analyzer failed (exit {proc.returncode}): {tail}")
        if proc.stderr:
            logger.info(proc.stderr.strip().splitlines()[-1])
        with open(out, "r", encoding="utf-8") as fh:
            return json.load(fh)
