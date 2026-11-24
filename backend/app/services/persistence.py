"""SQLite persistence layer (synchronous; FastAPI runs sync endpoints in a thread pool)."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from app.models.database import get_connection

JSON_FIELDS_FINDING = ("call_path", "taint_path", "related_lines", "risk_breakdown", "entry_point")
EXTRA_KEYS = ("attack", "dependency")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _dumps(v: Any) -> Optional[str]:
    return None if v is None else json.dumps(v)


def _loads(v: Optional[str], default: Any = None) -> Any:
    if v is None or v == "":
        return default
    try:
        return json.loads(v)
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------
# Projects
# ---------------------------------------------------------------------------
def create_project(project_id: str, name: str, upload_path: str, file_count: int, size_bytes: int,
                   source_type: str = "zip", source_url: Optional[str] = None, source_ref: Optional[str] = None) -> Dict:
    conn = get_connection()
    try:
        ts = now_iso()
        conn.execute(
            "INSERT INTO projects (project_id, name, upload_path, file_count, size_bytes, created_at, source_type, source_url, source_ref) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (project_id, name, upload_path, file_count, size_bytes, ts, source_type, source_url, source_ref),
        )
        conn.commit()
        return {"project_id": project_id, "name": name, "upload_path": upload_path, "file_count": file_count, "size_bytes": size_bytes,
                "created_at": ts, "source_type": source_type, "source_url": source_url, "source_ref": source_ref}
    finally:
        conn.close()


def update_project_source(project_id: str, upload_path: str, file_count: int, size_bytes: int, source_ref: Optional[str] = None) -> None:
    """A new version of the project's code (new ZIP or a fresh GitHub download)."""
    conn = get_connection()
    try:
        conn.execute("UPDATE projects SET upload_path=?, file_count=?, size_bytes=?, source_ref=? WHERE project_id=?",
                     (upload_path, file_count, size_bytes, source_ref, project_id))
        conn.commit()
    finally:
        conn.close()


def get_project(project_id: str) -> Optional[Dict]:
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM projects WHERE project_id=?", (project_id,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def list_projects() -> List[Dict]:
    conn = get_connection()
    try:
        rows = conn.execute(
            """SELECT p.*, COUNT(s.scan_id) AS scan_count, MAX(s.created_at) AS last_scan_at
               FROM projects p LEFT JOIN scans s ON s.project_id = p.project_id
               GROUP BY p.project_id ORDER BY p.created_at DESC"""
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def delete_project(project_id: str) -> Optional[Dict]:
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM projects WHERE project_id=?", (project_id,)).fetchone()
        if not row:
            return None
        conn.execute("DELETE FROM projects WHERE project_id=?", (project_id,))
        conn.commit()
        return dict(row)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------
def _scan_row(row) -> Dict:
    d = dict(row)
    d["summary"] = _loads(d.pop("summary_json", None), None)
    return d


def create_scan(scan_id: str, project_id: str, project_name: str, source_ref: Optional[str] = None) -> Dict:
    conn = get_connection()
    try:
        ts = now_iso()
        conn.execute(
            "INSERT INTO scans (scan_id, project_id, project_name, status, stage, progress, finding_count, created_at, updated_at, source_ref) "
            "VALUES (?, ?, ?, 'queued', 'Queued', 0, 0, ?, ?, ?)",
            (scan_id, project_id, project_name, ts, ts, source_ref),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM scans WHERE scan_id=?", (scan_id,)).fetchone()
        return _scan_row(row)
    finally:
        conn.close()


def update_scan(scan_id: str, **fields: Any) -> None:
    if not fields:
        return
    if "summary" in fields:
        fields["summary_json"] = _dumps(fields.pop("summary"))
    fields["updated_at"] = now_iso()
    cols = ", ".join(f"{k}=?" for k in fields)
    conn = get_connection()
    try:
        conn.execute(f"UPDATE scans SET {cols} WHERE scan_id=?", (*fields.values(), scan_id))
        conn.commit()
    finally:
        conn.close()


def get_scan(scan_id: str) -> Optional[Dict]:
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM scans WHERE scan_id=?", (scan_id,)).fetchone()
        return _scan_row(row) if row else None
    finally:
        conn.close()


def list_scans(project_id: Optional[str] = None, limit: int = 200) -> List[Dict]:
    conn = get_connection()
    try:
        if project_id:
            rows = conn.execute("SELECT * FROM scans WHERE project_id=? ORDER BY created_at DESC LIMIT ?", (project_id, limit)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM scans ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [_scan_row(r) for r in rows]
    finally:
        conn.close()


def delete_scan(scan_id: str) -> bool:
    conn = get_connection()
    try:
        cur = conn.execute("DELETE FROM scans WHERE scan_id=?", (scan_id,))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def mark_interrupted_scans() -> int:
    """Scans left running by a previous server process can never finish."""
    conn = get_connection()
    try:
        cur = conn.execute(
            "UPDATE scans SET status='failed', stage='Interrupted', error_message='Server restarted while the scan was running', updated_at=? "
            "WHERE status IN ('queued','running')",
            (now_iso(),),
        )
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Scan results (written once, atomically)
# ---------------------------------------------------------------------------
def save_scan_results(scan_id: str, nodes: List[Dict], edges: List[Dict], entry_points: List[Dict], findings: List[Dict]) -> None:
    conn = get_connection()
    try:
        ts = now_iso()
        conn.execute("DELETE FROM findings WHERE scan_id=?", (scan_id,))
        conn.execute("DELETE FROM call_graph_nodes WHERE scan_id=?", (scan_id,))
        conn.execute("DELETE FROM call_graph_edges WHERE scan_id=?", (scan_id,))
        conn.execute("DELETE FROM entry_points WHERE scan_id=?", (scan_id,))
        conn.executemany(
            "INSERT INTO call_graph_nodes (scan_id, node_id, name, file_path, line, end_line, node_type, reachability, entry_kind, ai_probability, finding_count, max_risk) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            [(scan_id, n["id"], n.get("name", ""), n.get("file_path"), n.get("start_line"), n.get("end_line"), n.get("node_type"),
              n.get("reachability"), n.get("entry_kind"), n.get("ai_probability"), n.get("finding_count", 0), n.get("max_risk", 0.0))
             for n in nodes],
        )
        conn.executemany(
            "INSERT INTO call_graph_edges (scan_id, caller_id, callee_id, kind, line) VALUES (?,?,?,?,?)",
            [(scan_id, e["caller_id"], e["callee_id"], e.get("kind"), e.get("line")) for e in edges],
        )
        conn.executemany(
            "INSERT INTO entry_points (scan_id, node_id, kind, label, active, file_path, line) VALUES (?,?,?,?,?,?,?)",
            [(scan_id, e["id"], e.get("kind"), e.get("label"), 1 if e.get("active") else 0, e.get("file"), e.get("line")) for e in entry_points],
        )
        conn.executemany(
            """INSERT INTO findings (finding_id, scan_id, function_id, function_name, file_path, start_line, end_line, line,
                related_lines, snippet, source_code, prediction, vulnerability_probability, model_used, rule_id, title, rule_message,
                severity, cwe, category, sink, taint, reachability_status, entry_point, call_path, taint_path, risk_score,
                risk_category, risk_breakdown, finding_type, detector, extra_json, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            [(
                f.get("finding_id") or str(uuid.uuid4()), scan_id, f.get("function_id"), f.get("function_name"), f.get("file_path", ""),
                f.get("start_line"), f.get("end_line"), f.get("line"), _dumps(f.get("related_lines")), f.get("snippet"),
                f.get("source_code"), f.get("prediction"), f.get("vulnerability_probability", 0.0), f.get("model_used"),
                f.get("rule_id"), f.get("title"), f.get("rule_message"), f.get("severity"), f.get("cwe"), f.get("category"),
                f.get("sink"), f.get("taint", "none"), f.get("reachability_status", "unknown"), _dumps(f.get("entry_point")),
                _dumps(f.get("call_path")), _dumps(f.get("taint_path")), f.get("risk_score", 0.0), f.get("risk_category"),
                _dumps(f.get("risk_breakdown")), f.get("finding_type"), f.get("detector"),
                _dumps({k: f[k] for k in EXTRA_KEYS if f.get(k) is not None} or None), ts,
            ) for f in findings],
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _finding_row(row, with_source: bool) -> Dict:
    d = dict(row)
    for k in JSON_FIELDS_FINDING:
        d[k] = _loads(d.get(k), [] if k in ("call_path", "taint_path", "related_lines") else None)
    extra = _loads(d.pop("extra_json", None), None) or {}
    for k in EXTRA_KEYS:
        d[k] = extra.get(k)
    if not with_source:
        d.pop("source_code", None)
    return d


SORTS = {
    "risk": "risk_score DESC",
    "severity": "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, risk_score DESC",
    "file": "file_path ASC, line ASC",
    "ai": "vulnerability_probability DESC",
}


def get_findings(scan_id: str, sort: str = "risk", with_source: bool = False) -> List[Dict]:
    conn = get_connection()
    try:
        rows = conn.execute(f"SELECT * FROM findings WHERE scan_id=? ORDER BY {SORTS.get(sort, SORTS['risk'])}", (scan_id,)).fetchall()
        return [_finding_row(r, with_source) for r in rows]
    finally:
        conn.close()


def get_finding(finding_id: str) -> Optional[Dict]:
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM findings WHERE finding_id=?", (finding_id,)).fetchone()
        return _finding_row(row, True) if row else None
    finally:
        conn.close()


def get_nodes_by_ids(scan_id: str, ids: Iterable[str]) -> Dict[str, Dict]:
    ids = list(dict.fromkeys(ids))
    if not ids:
        return {}
    conn = get_connection()
    try:
        out: Dict[str, Dict] = {}
        for i in range(0, len(ids), 500):
            chunk = ids[i:i + 500]
            q = f"SELECT * FROM call_graph_nodes WHERE scan_id=? AND node_id IN ({','.join('?' * len(chunk))})"
            for r in conn.execute(q, (scan_id, *chunk)).fetchall():
                out[r["node_id"]] = dict(r)
        return out
    finally:
        conn.close()


def get_call_graph(scan_id: str) -> Dict:
    conn = get_connection()
    try:
        nodes = [dict(r) for r in conn.execute("SELECT * FROM call_graph_nodes WHERE scan_id=?", (scan_id,)).fetchall()]
        edges = [dict(r) for r in conn.execute("SELECT caller_id, callee_id, kind, line FROM call_graph_edges WHERE scan_id=?", (scan_id,)).fetchall()]
        entries = [dict(r) for r in conn.execute("SELECT node_id, kind, label, active, file_path, line FROM entry_points WHERE scan_id=?", (scan_id,)).fetchall()]
        return {"scan_id": scan_id, "nodes": nodes, "edges": edges, "entry_points": entries}
    finally:
        conn.close()


def get_entry_points(scan_id: str) -> List[Dict]:
    conn = get_connection()
    try:
        return [dict(r) for r in conn.execute("SELECT node_id, kind, label, active, file_path, line FROM entry_points WHERE scan_id=?", (scan_id,)).fetchall()]
    finally:
        conn.close()


def global_stats() -> Dict[str, Any]:
    conn = get_connection()
    try:
        latest = conn.execute(
            """SELECT s.* FROM scans s
               JOIN (SELECT project_id, MAX(created_at) AS m FROM scans WHERE status='completed' GROUP BY project_id) x
               ON x.project_id = s.project_id AND x.m = s.created_at"""
        ).fetchall()
        latest_ids = [r["scan_id"] for r in latest]
        totals = {"projects": conn.execute("SELECT COUNT(*) FROM projects").fetchone()[0],
                  "scans": conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0],
                  "completed_scans": conn.execute("SELECT COUNT(*) FROM scans WHERE status='completed'").fetchone()[0]}
        by_cat: Dict[str, int] = {}
        by_reach: Dict[str, int] = {}
        by_cwe: Dict[str, int] = {}
        if latest_ids:
            ph = ",".join("?" * len(latest_ids))
            for r in conn.execute(f"SELECT risk_category, COUNT(*) c FROM findings WHERE scan_id IN ({ph}) GROUP BY risk_category", latest_ids):
                by_cat[r["risk_category"] or "Low"] = r["c"]
            for r in conn.execute(f"SELECT reachability_status, COUNT(*) c FROM findings WHERE scan_id IN ({ph}) GROUP BY reachability_status", latest_ids):
                by_reach[r["reachability_status"] or "unknown"] = r["c"]
            for r in conn.execute(f"SELECT cwe, COUNT(*) c FROM findings WHERE scan_id IN ({ph}) GROUP BY cwe ORDER BY c DESC LIMIT 8", latest_ids):
                by_cwe[r["cwe"] or "CWE-Unknown"] = r["c"]
        return {"totals": totals, "by_risk_category": by_cat, "by_reachability": by_reach, "top_cwes": by_cwe,
                "latest_scan_ids": latest_ids}
    finally:
        conn.close()
