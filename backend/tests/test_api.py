"""API + full pipeline tests against the bundled test applications."""
import io
import time
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app

ROOT = Path(__file__).resolve().parents[2]
APPS = ROOT / "test-applications"


def _zip_dir(name: str) -> bytes:
    buf = io.BytesIO()
    base = APPS / name
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in base.rglob("*"):
            if p.is_file():
                zf.write(p, f"{name}/{p.relative_to(base).as_posix()}")
    return buf.getvalue()


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def _scan(client, app_name):
    r = client.post("/api/projects/upload", files={"file": (f"{app_name}.zip", _zip_dir(app_name), "application/zip")}, data={"name": app_name})
    assert r.status_code == 200, r.text
    scan_id = r.json()["scan"]["scan_id"]
    for _ in range(300):
        s = client.get(f"/api/scans/{scan_id}").json()
        if s["status"] in ("completed", "failed"):
            break
        time.sleep(0.1)
    assert s["status"] == "completed", s
    return s


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["analyzer"] is True


def test_rejects_non_zip(client):
    r = client.post("/api/projects/upload", files={"file": ("x.txt", b"hello", "text/plain")})
    assert r.status_code == 400


def test_mixed_app_prioritization(client):
    s = _scan(client, "mixed-app")
    findings = client.get(f"/api/scans/{s['scan_id']}/findings").json()
    static = [f for f in findings if f["finding_type"] == "static_finding"]
    assert static, "expected findings"
    top = static[0]
    assert top["function_name"] == "processCommand"
    assert top["reachability_status"] == "reachable"
    assert top["taint"] == "user_input"
    assert top["call_path"][0].endswith("__top_level__")
    unreachable = [f for f in static if f["reachability_status"] == "unreachable"]
    assert all(u["risk_score"] < top["risk_score"] for u in unreachable)
    detail = client.get(f"/api/scans/{s['scan_id']}/findings/{top['finding_id']}").json()
    assert [st["name"] for st in detail["call_path_steps"]][-1] == "processCommand"
    assert "exec" in detail["source_code"]
    assert s["summary"]["actionable"] >= 1


def test_secure_app_has_no_rule_findings(client):
    s = _scan(client, "secure-app")
    findings = client.get(f"/api/scans/{s['scan_id']}/findings", params={"finding_type": "static_finding"}).json()
    assert findings == []


def test_graph_export_and_delete(client):
    s = _scan(client, "vulnerable-app")
    sid = s["scan_id"]
    g = client.get(f"/api/scans/{sid}/graph").json()
    assert len(g["nodes"]) > 10 and len(g["edges"]) > 5
    assert any(n["finding_count"] > 0 for n in g["nodes"])
    focused = client.get(f"/api/scans/{sid}/graph", params={"focus": "findings"}).json()
    assert 0 < len(focused["nodes"]) < len(g["nodes"])
    sarif = client.get(f"/api/scans/{sid}/export", params={"format": "sarif"})
    assert sarif.status_code == 200 and sarif.json()["version"] == "2.1.0"
    csv = client.get(f"/api/scans/{sid}/export", params={"format": "csv"})
    assert csv.text.startswith("risk_score")
    filtered = client.get(f"/api/scans/{sid}/findings", params={"reachability": "reachable", "taint": "user_input"}).json()
    assert filtered and all(f["reachability_status"] == "reachable" for f in filtered)
    # rescanning the same project keeps both scans' graphs (per-scan node keys)
    r = client.post("/api/scans", json={"project_id": s["project_id"]})
    assert r.status_code == 202
    sid2 = r.json()["scan_id"]
    for _ in range(300):
        if client.get(f"/api/scans/{sid2}").json()["status"] == "completed":
            break
        time.sleep(0.1)
    assert len(client.get(f"/api/scans/{sid}/graph").json()["nodes"]) == len(g["nodes"])
    assert client.delete(f"/api/scans/{sid}").status_code == 200
    assert client.get(f"/api/scans/{sid}").status_code == 404


def test_model_status_and_stats(client):
    m = client.get("/api/model/status").json()
    assert m["active_model"]["model_name"] == "tfidf_logreg"
    assert m["dataset"]["total_samples"] == 21896
    assert "codebert" in m["checkpoints"]
    st = client.get("/api/stats").json()
    assert st["totals"]["projects"] >= 1
