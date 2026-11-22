"""Call graph for visualization."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from app.services import persistence as db

router = APIRouter(prefix="/api/scans", tags=["call-graph"])


@router.get("/{scan_id}/graph")
def get_graph(
    scan_id: str,
    include_modules: bool = Query(True, description="Include module (file top-level) nodes"),
    focus: str = Query("all", pattern="^(all|reachable|findings)$", description="Restrict to reachable code or to paths that lead to findings"),
):
    if not db.get_scan(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")
    g = db.get_call_graph(scan_id)
    nodes = g["nodes"]
    if not include_modules:
        nodes = [n for n in nodes if n.get("node_type") != "Module"]
    if focus == "reachable":
        nodes = [n for n in nodes if n.get("reachability") in ("reachable", "startup_only")]
    elif focus == "findings":
        keep = set()
        for f in db.get_findings(scan_id):
            keep.update(f.get("call_path") or [])
            keep.update(f.get("taint_path") or [])
            if f.get("function_id"):
                keep.add(f["function_id"])
        nodes = [n for n in nodes if n["node_id"] in keep]
    ids = {n["node_id"] for n in nodes}
    edges = [e for e in g["edges"] if e["caller_id"] in ids and e["callee_id"] in ids]
    return {"scan_id": scan_id, "nodes": nodes, "edges": edges, "entry_points": g["entry_points"]}
