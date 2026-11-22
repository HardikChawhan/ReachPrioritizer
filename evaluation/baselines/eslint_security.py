"""Baseline 2: ESLint + eslint-plugin-security (a widely used JavaScript security linter).

Install once:  cd evaluation/baselines/eslint && npm install
If it is not installed the baseline is skipped.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

HERE = Path(__file__).resolve().parent / "eslint"
CONFIG = {
    "root": True,
    "parserOptions": {"ecmaVersion": "latest", "sourceType": "module", "ecmaFeatures": {"jsx": True}},
    "env": {"node": True, "es2022": True, "browser": True},
    "plugins": ["security"],
    "extends": ["plugin:security/recommended"],
}
RULE_CWE = {
    "security/detect-child-process": "CWE-78",
    "security/detect-eval-with-expression": "CWE-94",
    "security/detect-non-literal-fs-filename": "CWE-22",
    "security/detect-non-literal-require": "CWE-829",
    "security/detect-non-literal-regexp": "CWE-1333",
    "security/detect-unsafe-regex": "CWE-1333",
    "security/detect-object-injection": "CWE-1321",
    "security/detect-possible-timing-attacks": "CWE-208",
    "security/detect-pseudoRandomBytes": "CWE-338",
    "security/detect-buffer-noassert": "CWE-119",
    "security/detect-new-buffer": "CWE-119",
    "security/detect-disable-mustache-escape": "CWE-79",
    "security/detect-no-csrf-before-method-override": "CWE-352",
    "security/detect-bidi-characters": "CWE-1007",
}


def available() -> bool:
    return (HERE / "node_modules" / ".bin" / "eslint").exists() or (HERE / "node_modules" / "eslint").exists()


def scan(project_dir: Path) -> Optional[List[Dict[str, Any]]]:
    if not available() or not shutil.which("node"):
        return None
    cfg = HERE / ".eslintrc.reachprioritizer.json"
    cfg.write_text(json.dumps(CONFIG), encoding="utf-8")
    eslint_js = HERE / "node_modules" / "eslint" / "bin" / "eslint.js"
    proc = subprocess.run(
        ["node", str(eslint_js), "--no-eslintrc", "-c", str(cfg), "--resolve-plugins-relative-to", str(HERE),
         "-f", "json", "--ext", ".js,.mjs,.cjs", "--ignore-pattern", "node_modules/", "."],
        capture_output=True, text=True, cwd=str(project_dir), timeout=600,
    )
    try:
        data = json.loads(proc.stdout or "[]")
    except ValueError:
        return None
    out = []
    for file_res in data:
        rel = Path(file_res["filePath"]).resolve().relative_to(project_dir.resolve()).as_posix()
        for m in file_res.get("messages", []):
            rid = m.get("ruleId") or ""
            if not rid.startswith("security/"):
                continue
            out.append({"rule_id": rid, "file_path": rel, "line": m.get("line", 0), "cwe": RULE_CWE.get(rid, "CWE-Unknown"), "message": m.get("message", "")})
    return out
