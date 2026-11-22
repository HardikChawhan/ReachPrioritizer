"""Baseline 1: the v1 prototype's regex rule engine (kept verbatim for comparison).

This is the scanner ReachPrioritizer v1 used when Semgrep was not installed.
It matches text patterns line by line, with no data-flow or reachability awareness.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List

EXCLUDED_DIRS = {"node_modules", ".git", "dist", "build", ".next", "coverage", "vendor"}

class _Rule:
    def __init__(self, rule_id: str, pattern: re.Pattern, message: str,
                 severity: str, cwe: str):
        self.rule_id = rule_id
        self.pattern = pattern
        self.message = message
        self.severity = severity
        self.cwe = cwe


_RULES: List[_Rule] = [
    # SQL Injection
    _Rule(
        "rp.sqli.string-concat",
        re.compile(
            r'(?i)(query|sql)\s*[+]=?\s*|'
            r'["\']?\s*\+\s*(?:req\.|user|input|params|body)',
            re.MULTILINE,
        ),
        "Potential SQL injection: string concatenation in query construction.",
        "high",
        "CWE-89",
    ),
    # Command Injection
    _Rule(
        "rp.cmdi.exec-user-input",
        re.compile(
            r'(?:exec|execSync|execFile|spawn|spawnSync)\s*\([^)]*(?:req\.|user|input|params|body|argv)',
            re.MULTILINE,
        ),
        "Potential command injection: exec/spawn called with user-controlled input.",
        "critical",
        "CWE-78",
    ),
    # XSS - innerHTML
    _Rule(
        "rp.xss.innerhtml",
        re.compile(
            r'\.innerHTML\s*[+]?=\s*(?![\'"]\s*[\'"])',
            re.MULTILINE,
        ),
        "Potential XSS: assigning to innerHTML without sanitization.",
        "high",
        "CWE-79",
    ),
    # XSS - document.write
    _Rule(
        "rp.xss.document-write",
        re.compile(
            r'document\.write\s*\([^)]*(?:req\.|user|input|params|body|\+)',
            re.MULTILINE,
        ),
        "Potential XSS: document.write with user-controlled input.",
        "high",
        "CWE-79",
    ),
    # Path Traversal
    _Rule(
        "rp.path-traversal.fs",
        re.compile(
            r'fs\.(?:readFile|writeFile|appendFile|createReadStream|createWriteStream|unlink|rmdir)\s*\([^)]*(?:req\.|user|input|params|body|\.\.|path)',
            re.MULTILINE,
        ),
        "Potential path traversal: file operation with user-controlled path.",
        "high",
        "CWE-22",
    ),
    # Prototype Pollution
    _Rule(
        "rp.proto-pollution",
        re.compile(
            r'(?:__proto__|constructor\s*\[\s*["\']prototype["\']|Object\.prototype)\s*[\[.]',
            re.MULTILINE,
        ),
        "Potential prototype pollution: direct manipulation of __proto__ or Object.prototype.",
        "high",
        "CWE-1321",
    ),
    # Dangerous eval
    _Rule(
        "rp.eval.user-input",
        re.compile(
            r'\beval\s*\([^)]*(?:req\.|user|input|params|body|\+|`[^`]*\$)',
            re.MULTILINE,
        ),
        "Potential code injection: eval() called with dynamic or user-controlled input.",
        "critical",
        "CWE-95",
    ),
    # Hardcoded secrets (basic)
    _Rule(
        "rp.secrets.hardcoded",
        re.compile(
            r'(?:password|secret|api_key|apikey|token|passwd)\s*=\s*["\'][^"\']{6,}["\']',
            re.IGNORECASE | re.MULTILINE,
        ),
        "Potential hardcoded secret or credential in source code.",
        "medium",
        "CWE-798",
    ),
    # Open redirect
    _Rule(
        "rp.open-redirect",
        re.compile(
            r'res\.redirect\s*\([^)]*(?:req\.|user|input|params|body)',
            re.MULTILINE,
        ),
        "Potential open redirect: redirect destination from user input.",
        "medium",
        "CWE-601",
    ),
]


def _scan_file_with_rules(file_path: Path, project_dir: Path) -> List[Dict[str, Any]]:
    """Apply regex rules to a single file."""
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        logger.warning("Cannot read %s: %s", file_path, exc)
        return []

    lines = source.splitlines()
    findings = []

    try:
        rel_path = str(file_path.relative_to(project_dir))
    except ValueError:
        rel_path = str(file_path)

    for rule in _RULES:
        for m in rule.pattern.finditer(source):
            line_no = source[:m.start()].count('\n') + 1
            findings.append({
                "rule_id": rule.rule_id,
                "file_path": rel_path,
                "line": line_no,
                "message": rule.message,
                "severity": rule.severity,
                "cwe": rule.cwe,
                "source": "rule_engine",
            })

    return findings



def scan(project_dir: Path) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for root, dirs, files in os.walk(project_dir):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS and not d.startswith(".")]
        for fname in files:
            if Path(fname).suffix.lower() in {".js", ".mjs", ".ts"}:
                fp = Path(root) / fname
                findings.extend(_scan_file_with_rules(fp, project_dir))
    for f in findings:
        f["file_path"] = f["file_path"].replace("\\", "/")
    return findings
