"""Scan pipeline.

    1. unpack the uploaded project (safe extraction)
    2. static analysis engine (Node.js): functions, call graph, entry points,
       reachability + call paths, taint-tracked security findings
    3. AI model scores every function
    4. optional Semgrep findings are attached to call-graph functions
    5. contextual risk score for every finding
    6. results are saved atomically

The pipeline is synchronous and runs in a worker thread, so the API stays responsive.
"""
from __future__ import annotations

import logging
import shutil
import tempfile
import threading
import time
import traceback
import uuid
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.config import AI_ONLY_MIN_PROBABILITY, MAX_CONCURRENT_SCANS
from app.core.upload_handler import UploadError, extract_project_zip, single_root
from app.services import ai_inference, semgrep_scanner
from app.services.analyzer_runner import AnalyzerError, run_analyzer
from app.services.persistence import get_project, save_scan_results, update_scan
from app.services.risk_scorer import calculate_risk

logger = logging.getLogger(__name__)
_slots = threading.BoundedSemaphore(max(1, MAX_CONCURRENT_SCANS))

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _stage(scan_id: str, stage: str, progress: int) -> None:
    update_scan(scan_id, stage=stage, progress=progress)


def _innermost(nodes_by_file: Dict[str, List[Dict]], file_path: str, line: int) -> Optional[Dict]:
    best = None
    for n in nodes_by_file.get(file_path, []):
        if (n.get("start_line") or 0) <= line <= (n.get("end_line") or 0):
            if best is None or (n["end_line"] - n["start_line"]) < (best["end_line"] - best["start_line"]):
                best = n
    return best


def _window(project_dir: Path, rel: str, line: int, radius: int = 6) -> Dict[str, Any]:
    try:
        lines = (project_dir / rel).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return {"source": "", "start": line}
    start = max(1, line - radius)
    end = min(len(lines), line + radius)
    return {"source": "\n".join(lines[start - 1:end]), "start": start, "end": end}


def build_findings(analysis: Dict[str, Any], ai_probs: Dict[str, float], model: Dict[str, Any],
                   project_dir: Path, extra_findings: Optional[List[Dict]] = None) -> List[Dict[str, Any]]:
    """Turn analyzer output (+ AI scores) into scored findings. Pure function; also used by evaluation."""
    nodes = analysis.get("nodes", [])
    by_id = {n["id"]: n for n in nodes}
    by_file: Dict[str, List[Dict]] = {}
    for n in nodes:
        by_file.setdefault(n["file_path"], []).append(n)
    model_name = model.get("model_name", "none")
    threshold = float(model.get("threshold", 0.5))
    out: List[Dict[str, Any]] = []
    seen = set()

    def make(f: Dict[str, Any], node: Optional[Dict], detector: str, finding_type: str) -> Dict[str, Any]:
        fid = node["id"] if node else f.get("function_id")
        ai = ai_probs.get(fid, 0.0) if fid else 0.0
        reach = (node or {}).get("reachability", "unknown")
        taint = f.get("taint", "none")
        score, category, breakdown = calculate_risk(f.get("severity", "medium"), taint, ai, reach)
        is_module = bool(node and node.get("node_type") == "Module")
        if node and not is_module and node.get("source"):
            src, start, end = node["source"], node["start_line"], node["end_line"]
        else:
            w = _window(project_dir, f.get("file_path", ""), int(f.get("line") or 1))
            src, start, end = w["source"], w["start"], w.get("end", w["start"])
        return {
            "finding_id": str(uuid.uuid4()),
            "function_id": fid,
            "function_name": (node or {}).get("name") or f.get("function_name") or "",
            "file_path": f.get("file_path", ""),
            "start_line": start,
            "end_line": end,
            "line": f.get("line"),
            "related_lines": f.get("related_lines") or [f.get("line")],
            "snippet": f.get("snippet"),
            "source_code": src,
            "prediction": "vulnerable",
            "vulnerability_probability": round(ai, 4),
            "model_used": model_name,
            "rule_id": f.get("rule_id"),
            "title": f.get("title"),
            "rule_message": f.get("message") or f.get("title"),
            "severity": f.get("severity", "medium"),
            "cwe": f.get("cwe") or "CWE-Unknown",
            "category": f.get("category"),
            "sink": f.get("sink"),
            "taint": taint,
            "reachability_status": reach,
            "entry_point": (node or {}).get("entry"),
            "call_path": (node or {}).get("call_path") or [],
            "taint_path": f.get("taint_path") or ([fid] if fid else []),
            "risk_score": score,
            "risk_category": category,
            "risk_breakdown": breakdown,
            "finding_type": finding_type,
            "detector": detector,
        }

    for f in analysis.get("findings", []):
        node = by_id.get(f.get("function_id"))
        out.append(make(f, node, "reachprioritizer-taint", "static_finding"))
        seen.add((f.get("function_id"), f.get("cwe")))

    for f in extra_findings or []:
        node = _innermost(by_file, f.get("file_path", ""), int(f.get("line") or 0))
        key = (node["id"] if node else None, f.get("cwe"))
        if key in seen:
            continue
        seen.add(key)
        out.append(make(f, node, "semgrep", "static_finding"))

    flagged = {fid for fid, _ in seen}
    ai_cut = max(AI_ONLY_MIN_PROBABILITY, threshold)
    for fid, prob in ai_probs.items():
        if fid in flagged or prob < ai_cut:
            continue
        node = by_id.get(fid)
        if not node or node.get("node_type") == "Module":
            continue
        f = {
            "rule_id": "ai.function-classifier",
            "title": "AI-suspected vulnerable function",
            "message": f"The {model.get('display_name', 'AI model')} rates this function {prob:.0%} likely to be vulnerable, but no rule identified a concrete source-to-sink flow. Review manually.",
            "severity": "low",
            "cwe": "CWE-Unknown",
            "category": "ai",
            "file_path": node["file_path"],
            "line": node["start_line"],
            "snippet": (node.get("source") or "").splitlines()[0][:240] if node.get("source") else "",
            "taint": "unknown",
        }
        out.append(make(f, node, "ai-model", "ai_prediction"))

    out.sort(key=lambda x: x["risk_score"], reverse=True)
    return out


def summarize(analysis: Dict[str, Any], findings: List[Dict[str, Any]], model: Dict[str, Any], duration_ms: int) -> Dict[str, Any]:
    stats = analysis.get("stats", {})
    by_cat = Counter(f["risk_category"] for f in findings)
    by_reach = Counter(f["reachability_status"] for f in findings)
    by_sev = Counter(f["severity"] for f in findings)
    by_taint = Counter(f["taint"] for f in findings)
    by_cwe = Counter(f["cwe"] for f in findings)
    total = len(findings)
    actionable = sum(1 for f in findings if f["reachability_status"] == "reachable" and f["taint"] == "user_input")
    deprioritized = sum(1 for f in findings if f["reachability_status"] in ("unreachable", "startup_only"))
    entries = analysis.get("entry_points", [])
    return {
        "files_analyzed": stats.get("files_analyzed", 0),
        "functions": stats.get("functions", 0),
        "edges": stats.get("edges", 0),
        "parse_errors": stats.get("parse_errors", 0),
        "functions_by_reachability": {k: stats.get(k, 0) for k in ("reachable", "startup_only", "unreachable")},
        "entry_points": {
            "routes": sum(1 for e in entries if e.get("kind") == "route" and e.get("active")),
            "inactive_routes": sum(1 for e in entries if e.get("kind") == "route" and not e.get("active")),
            "startup": sum(1 for e in entries if e.get("kind") == "startup"),
            "other": sum(1 for e in entries if e.get("kind") not in ("route", "startup")),
        },
        "analysis_mode": analysis.get("mode"),
        "findings_total": total,
        "actionable": actionable,
        "deprioritized": deprioritized,
        "noise_reduction_pct": round(100.0 * deprioritized / total, 1) if total else 0.0,
        "by_risk_category": dict(by_cat),
        "by_reachability": dict(by_reach),
        "by_severity": {k: by_sev.get(k, 0) for k in SEVERITY_ORDER if by_sev.get(k)},
        "by_taint": dict(by_taint),
        "top_cwes": dict(by_cwe.most_common(8)),
        "max_risk": max((f["risk_score"] for f in findings), default=0.0),
        "model": {k: model.get(k) for k in ("model_name", "display_name", "threshold", "reason")},
        "duration_ms": duration_ms,
        "analyzer_ms": analysis.get("elapsed_ms"),
    }


def graph_nodes(analysis: Dict[str, Any], findings: List[Dict], ai_probs: Dict[str, float]) -> List[Dict]:
    per_fn: Dict[str, List[float]] = {}
    for f in findings:
        if f.get("function_id"):
            per_fn.setdefault(f["function_id"], []).append(f["risk_score"])
    entry_kind: Dict[str, str] = {}
    for e in analysis.get("entry_points", []):
        if e.get("active") or e.get("kind") == "startup":
            entry_kind.setdefault(e["id"], e.get("kind"))
    nodes = []
    for n in analysis.get("nodes", []):
        risks = per_fn.get(n["id"], [])
        nodes.append({
            **{k: n.get(k) for k in ("id", "name", "file_path", "start_line", "end_line", "node_type", "reachability")},
            "entry_kind": entry_kind.get(n["id"]),
            "ai_probability": ai_probs.get(n["id"]),
            "finding_count": len(risks),
            "max_risk": max(risks) if risks else 0.0,
        })
    return nodes


def run_scan(scan_id: str, project_id: str, entry_points: Optional[List[str]] = None) -> None:
    """Background entry point: runs the whole pipeline and records the outcome."""
    with _slots:
        _run_scan_locked(scan_id, project_id, entry_points)


def _run_scan_locked(scan_id: str, project_id: str, entry_points: Optional[List[str]]) -> None:
    started = time.time()
    workdir = Path(tempfile.mkdtemp(prefix=f"rp_scan_{scan_id[:8]}_"))
    try:
        update_scan(scan_id, status="running", stage="Unpacking project", progress=5)
        project = get_project(project_id)
        if not project:
            raise UploadError("Project not found")
        upload = Path(project["upload_path"])
        if not upload.exists():
            raise UploadError("Uploaded archive no longer exists on the server; please upload the project again")
        if upload.is_file():
            target = single_root(extract_project_zip(upload, workdir / "src"))
        else:
            target = upload

        _stage(scan_id, "Parsing code, building call graph, tracking taint", 20)
        analysis = run_analyzer(target, entry_points=entry_points)
        if analysis.get("stats", {}).get("files_analyzed", 0) == 0:
            raise AnalyzerError("No parsable JavaScript/TypeScript files were found in the project")

        _stage(scan_id, "Scoring functions with the AI model", 55)
        model = ai_inference.model_selection()
        try:
            ai_probs = ai_inference.score_functions(analysis.get("nodes", []))
        except Exception as exc:  # AI must never break a scan
            logger.exception("AI inference failed: %s", exc)
            ai_probs = {}
            model = {**model, "model_name": "unavailable", "reason": f"inference error: {exc}"}

        extra: List[Dict] = []
        if semgrep_scanner.available():
            _stage(scan_id, "Running Semgrep rules", 70)
            extra = semgrep_scanner.scan(target)

        _stage(scan_id, "Prioritizing findings", 82)
        findings = build_findings(analysis, ai_probs, model, target, extra)
        nodes = graph_nodes(analysis, findings, ai_probs)

        _stage(scan_id, "Saving results", 92)
        duration_ms = int((time.time() - started) * 1000)
        summary = summarize(analysis, findings, model, duration_ms)
        save_scan_results(scan_id, nodes, analysis.get("edges", []), analysis.get("entry_points", []), findings)
        update_scan(
            scan_id, status="completed", stage="Completed", progress=100, finding_count=len(findings),
            model_used=model.get("model_name"), analysis_mode=analysis.get("mode"), summary=summary,
            duration_ms=duration_ms, completed_at=time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()),
            error_message=None,
        )
        logger.info("Scan %s completed: %d findings in %d ms", scan_id, len(findings), duration_ms)
    except (UploadError, AnalyzerError) as exc:
        logger.warning("Scan %s failed: %s", scan_id, exc)
        update_scan(scan_id, status="failed", stage="Failed", error_message=str(exc))
    except Exception as exc:  # pragma: no cover - unexpected
        logger.error("Scan %s crashed: %s\n%s", scan_id, exc, traceback.format_exc())
        update_scan(scan_id, status="failed", stage="Failed", error_message=f"Internal error: {exc}")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
