"""Report exports: JSON, SARIF 2.1.0 (GitHub code scanning / IDEs) and CSV."""
from __future__ import annotations

import csv
import io
from typing import Any, Dict, List

SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def to_json(scan: Dict[str, Any], findings: List[Dict[str, Any]], entry_points: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {"tool": "ReachPrioritizer", "scan": scan, "entry_points": entry_points, "findings": findings}


def to_sarif(scan: Dict[str, Any], findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    rules: Dict[str, Dict[str, Any]] = {}
    results = []
    for f in findings:
        rid = f.get("rule_id") or "reachprioritizer.finding"
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": (f.get("title") or rid).replace(" ", ""),
                "shortDescription": {"text": f.get("title") or rid},
                "properties": {"tags": ["security", f.get("cwe") or "CWE-Unknown"]},
            }
        results.append({
            "ruleId": rid,
            "level": SARIF_LEVEL.get((f.get("severity") or "medium").lower(), "warning"),
            "message": {"text": f"{f.get('rule_message') or f.get('title')} [risk {f.get('risk_score')}, {f.get('reachability_status')}, taint={f.get('taint')}]"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.get("file_path")},
                    "region": {"startLine": int(f.get("line") or f.get("start_line") or 1)},
                },
                "logicalLocations": [{"name": f.get("function_name") or "", "kind": "function"}],
            }],
            "properties": {
                "risk_score": f.get("risk_score"),
                "risk_category": f.get("risk_category"),
                "reachability": f.get("reachability_status"),
                "taint": f.get("taint"),
                "cwe": f.get("cwe"),
                "call_path": f.get("call_path"),
                "ai_probability": f.get("vulnerability_probability"),
            },
            "rank": float(f.get("risk_score") or 0.0),
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "ReachPrioritizer", "informationUri": "https://github.com/HardikChawhan/ReachPrioritizer", "rules": list(rules.values())}},
            "results": results,
            "properties": {"scan_id": scan.get("scan_id"), "project": scan.get("project_name")},
        }],
    }


CSV_FIELDS = ["risk_score", "risk_category", "severity", "cwe", "title", "reachability_status", "taint",
              "file_path", "line", "function_name", "vulnerability_probability", "rule_id", "rule_message"]


def to_csv(findings: List[Dict[str, Any]]) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=CSV_FIELDS, extrasaction="ignore")
    w.writeheader()
    for f in findings:
        w.writerow({k: f.get(k) for k in CSV_FIELDS})
    return buf.getvalue()
