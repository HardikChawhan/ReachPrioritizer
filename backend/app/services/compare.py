"""Compare two scans: which findings were fixed, which are new, which are still open,
and how the call graph / attack surface changed between the two versions of the code."""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from app.services import persistence as db

REACH_RANK = {"reachable": 3, "startup_only": 2, "unknown": 1, "unreachable": 0}
SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

STUB_KEYS = ("finding_id", "scan_id", "function_id", "function_name", "file_path", "line", "title", "cwe", "severity",
             "category", "taint", "reachability_status", "risk_score", "risk_category", "finding_type", "call_path", "taint_path")


def _key(f: Dict[str, Any]) -> Tuple:
    dep = f.get("dependency") or {}
    if dep.get("package"):
        return ("dep", dep["package"])
    return ("code", f.get("function_id") or f"{f.get('file_path')}::{f.get('function_name')}", f.get("cwe"))


def _loose_key(f: Dict[str, Any]) -> Optional[Tuple]:
    """Fallback when a function moved to another file: same name + same weakness."""
    if (f.get("dependency") or {}).get("package") or not f.get("function_name"):
        return None
    return (f.get("function_name"), f.get("cwe"))


def _stub(f: Dict[str, Any]) -> Dict[str, Any]:
    s = {k: f.get(k) for k in STUB_KEYS}
    dep = f.get("dependency") or {}
    if dep:
        s["dependency"] = {k: dep.get(k) for k in ("package", "version", "fix_version")}
    att = f.get("attack") or {}
    if att:
        s["attack_verdict"] = att.get("verdict")
    return s


def _change(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    notes: List[str] = []
    ra, rb = a.get("reachability_status"), b.get("reachability_status")
    if ra != rb:
        notes.append(f"reachability {ra} → {rb}")
    if a.get("taint") != b.get("taint"):
        notes.append(f"input {a.get('taint')} → {b.get('taint')}")
    if a.get("severity") != b.get("severity"):
        notes.append(f"severity {a.get('severity')} → {b.get('severity')}")
    da, dbv = (a.get("dependency") or {}).get("version"), (b.get("dependency") or {}).get("version")
    if da and dbv and da != dbv:
        notes.append(f"version {da} → {dbv}")
    path_changed = (a.get("call_path") or []) != (b.get("call_path") or [])
    if path_changed:
        notes.append("attack path changed")
    delta = round(float(b.get("risk_score") or 0) - float(a.get("risk_score") or 0), 1)
    trend = "worse" if delta > 0.5 else ("better" if delta < -0.5 else "same")
    return {"risk_delta": delta, "trend": trend, "notes": notes, "path_changed": path_changed}


def compare_scans(base_id: str, head_id: str) -> Dict[str, Any]:
    base_scan, head_scan = db.get_scan(base_id), db.get_scan(head_id)
    base_f = db.get_findings(base_id)
    head_f = db.get_findings(head_id)

    head_by_key: Dict[Tuple, Dict] = {}
    for f in head_f:
        head_by_key.setdefault(_key(f), f)
    matched_head = set()
    pairs: List[Tuple[Dict, Dict]] = []
    unmatched_base: List[Dict] = []
    for f in base_f:
        h = head_by_key.get(_key(f))
        if h is not None and h["finding_id"] not in matched_head:
            pairs.append((f, h))
            matched_head.add(h["finding_id"])
        else:
            unmatched_base.append(f)
    # second pass: functions that moved file but keep name + weakness
    loose: Dict[Tuple, List[Dict]] = {}
    for h in head_f:
        if h["finding_id"] not in matched_head and _loose_key(h):
            loose.setdefault(_loose_key(h), []).append(h)
    fixed: List[Dict] = []
    for f in unmatched_base:
        cands = loose.get(_loose_key(f)) if _loose_key(f) else None
        if cands and len(cands) == 1 and cands[0]["finding_id"] not in matched_head:
            pairs.append((f, cands[0]))
            matched_head.add(cands[0]["finding_id"])
        else:
            fixed.append(f)
    new = [h for h in head_f if h["finding_id"] not in matched_head]

    still_open = []
    for a, b in pairs:
        still_open.append({"base": _stub(a), "head": _stub(b), **_change(a, b)})
    still_open.sort(key=lambda x: -(x["head"]["risk_score"] or 0))
    fixed.sort(key=lambda f: -(f.get("risk_score") or 0))
    new.sort(key=lambda f: -(f.get("risk_score") or 0))

    # ---- call graph / attack surface diff
    gb, gh = db.get_call_graph(base_id), db.get_call_graph(head_id)
    nb = {n["node_id"]: n for n in gb["nodes"]}
    nh = {n["node_id"]: n for n in gh["nodes"]}
    eb = {(e["caller_id"], e["callee_id"]) for e in gb["edges"]}
    eh = {(e["caller_id"], e["callee_id"]) for e in gh["edges"]}
    routes_b = {e["label"] for e in gb["entry_points"] if e.get("kind") == "route" and e.get("active")}
    routes_h = {e["label"] for e in gh["entry_points"] if e.get("kind") == "route" and e.get("active")}
    reach_changes = []
    for nid in set(nb) & set(nh):
        ra, rb = nb[nid].get("reachability"), nh[nid].get("reachability")
        if ra != rb and nb[nid].get("node_type") != "Module":
            reach_changes.append({"node_id": nid, "name": nh[nid].get("name"), "file_path": nh[nid].get("file_path"), "from": ra, "to": rb,
                                  "direction": "exposed" if REACH_RANK.get(rb, 0) > REACH_RANK.get(ra, 0) else "hidden"})
    reach_changes.sort(key=lambda r: (r["direction"] != "exposed", r["name"] or ""))

    # node colouring for the side-by-side graphs
    base_status: Dict[str, str] = {}
    head_status: Dict[str, str] = {}
    for f in fixed:
        if f.get("function_id"):
            base_status[f["function_id"]] = "fixed"
    for a, b in pairs:
        if a.get("function_id"):
            base_status.setdefault(a["function_id"], "open")
        if b.get("function_id"):
            head_status.setdefault(b["function_id"], "open")
    for f in new:
        if f.get("function_id"):
            head_status[f["function_id"]] = "new"
    for nid in set(nb) - set(nh):
        base_status.setdefault(nid, "removed")
    for nid in set(nh) - set(nb):
        head_status.setdefault(nid, "added")

    def totals(fs: List[Dict]) -> Dict[str, Any]:
        cats: Dict[str, int] = {}
        for f in fs:
            cats[f.get("risk_category") or "Low"] = cats.get(f.get("risk_category") or "Low", 0) + 1
        return {
            "findings": len(fs),
            "actionable": sum(1 for f in fs if f.get("reachability_status") == "reachable" and f.get("taint") == "user_input"),
            "risk_sum": round(sum(float(f.get("risk_score") or 0) for f in fs), 1),
            "max_risk": max((float(f.get("risk_score") or 0) for f in fs), default=0.0),
            "by_risk_category": cats,
        }

    tb, th = totals(base_f), totals(head_f)
    return {
        "base": {k: base_scan.get(k) for k in ("scan_id", "project_id", "project_name", "created_at", "source_ref")},
        "head": {k: head_scan.get(k) for k in ("scan_id", "project_id", "project_name", "created_at", "source_ref")},
        "same_project": base_scan.get("project_id") == head_scan.get("project_id"),
        "summary": {
            "fixed": len(fixed), "new": len(new), "still_open": len(pairs),
            "worse": sum(1 for x in still_open if x["trend"] == "worse"),
            "better": sum(1 for x in still_open if x["trend"] == "better"),
            "base": tb, "head": th,
            "risk_change": round(th["risk_sum"] - tb["risk_sum"], 1),
        },
        "fixed": [_stub(f) for f in fixed],
        "new": [_stub(f) for f in new],
        "still_open": still_open,
        "graph": {
            "functions_added": len(set(nh) - set(nb)), "functions_removed": len(set(nb) - set(nh)),
            "edges_added": len(eh - eb), "edges_removed": len(eb - eh),
            "routes_added": sorted(routes_h - routes_b), "routes_removed": sorted(routes_b - routes_h),
            "reachability_changes": reach_changes[:100],
            "base_node_status": base_status, "head_node_status": head_status,
        },
    }


__all__ = ["compare_scans"]
