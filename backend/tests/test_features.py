"""GitHub import, new-version upload, scan comparison, attack simulation and dependency check."""
import io
import shutil
import time
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services import dependency_check, github_import
from app.services.github_import import GitHubImportError, parse_github_url

ROOT = Path(__file__).resolve().parents[2]
APPS = ROOT / "test-applications"


def _zip_dir(name: str, patch=None) -> bytes:
    """ZIP a test app; `patch(rel_path, text) -> text` edits files on the way (a 'new version')."""
    buf = io.BytesIO()
    base = APPS / name
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in base.rglob("*"):
            if p.is_file():
                rel = p.relative_to(base).as_posix()
                data = p.read_bytes()
                if patch and p.suffix == ".js":
                    data = patch(rel, data.decode()).encode()
                zf.writestr(f"{name}/{rel}", data)
    return buf.getvalue()


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def _wait(client, scan_id):
    for _ in range(400):
        s = client.get(f"/api/scans/{scan_id}").json()
        if s["status"] in ("completed", "failed"):
            break
        time.sleep(0.1)
    assert s["status"] == "completed", s
    return s


# --------------------------------------------------------------- GitHub URLs
@pytest.mark.parametrize("url,branch,expected", [
    ("https://github.com/OWASP/NodeGoat", None, ("OWASP", "NodeGoat", None)),
    ("https://github.com/OWASP/NodeGoat.git", None, ("OWASP", "NodeGoat", None)),
    ("github.com/appsecco/dvna/", None, ("appsecco", "dvna", None)),
    ("https://github.com/OWASP/NodeGoat/tree/feature/x", None, ("OWASP", "NodeGoat", "feature/x")),
    ("OWASP/NodeGoat", "develop", ("OWASP", "NodeGoat", "develop")),
])
def test_parse_github_url(url, branch, expected):
    assert parse_github_url(url, branch) == expected


@pytest.mark.parametrize("bad", ["https://gitlab.com/a/b", "https://github.com/onlyowner", "https://evil.com/github.com/a/b", "", "https://github.com/a/b/tree/../x"])
def test_parse_github_url_rejects(bad):
    with pytest.raises(GitHubImportError):
        parse_github_url(bad)


def test_github_import_and_refresh(client, monkeypatch):
    versions = [_zip_dir("express-app")]

    def fake_download(url, dest, branch=None):
        dest.write_bytes(versions[-1])
        owner, repo, ref = parse_github_url(url, branch)
        return {"owner": owner, "repo": repo, "ref": ref, "commit": None, "size": len(versions[-1]),
                "source_url": f"https://github.com/{owner}/{repo}", "label": ref or "default branch"}

    monkeypatch.setattr("app.api.routes_projects.download_repo", fake_download)
    r = client.post("/api/projects/from-github", json={"url": "https://github.com/acme/shop"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["project"]["name"] == "acme/shop"
    assert body["project"]["source_type"] == "github"
    first = _wait(client, body["scan"]["scan_id"])
    assert first["summary"]["findings_total"] > 0

    # new commit: the open redirect is fixed
    versions.append(_zip_dir("express-app", lambda rel, t: t.replace("res.redirect(req.query.next)", "res.redirect('/')")))
    r = client.post(f"/api/projects/{body['project']['project_id']}/refresh")
    assert r.status_code == 200, r.text
    second = _wait(client, r.json()["scan"]["scan_id"])
    prev = client.get(f"/api/scans/{second['scan_id']}/previous").json()
    assert prev["scan_id"] == first["scan_id"]
    cmp = client.get(f"/api/scans/{first['scan_id']}/compare/{second['scan_id']}").json()
    assert [f["cwe"] for f in cmp["fixed"]] == ["CWE-601"]
    assert cmp["new"] == []
    trend = client.get(f"/api/projects/{body['project']['project_id']}/trend").json()
    assert len(trend["points"]) == 2


def test_github_import_bad_url(client):
    r = client.post("/api/projects/from-github", json={"url": "https://example.com/not/github"})
    assert r.status_code == 400


# --------------------------------------------------------------- compare
def test_new_version_compare(client):
    r = client.post("/api/projects/upload", files={"file": ("express-app.zip", _zip_dir("express-app"), "application/zip")}, data={"name": "shop"})
    pid = r.json()["project"]["project_id"]
    base = _wait(client, r.json()["scan"]["scan_id"])

    def patch(rel, text):
        if rel == "src/services/userService.js":  # fix the SQL injection
            text = text.replace("const sql = `SELECT id, name FROM users WHERE name LIKE '%${term}%'`;\n    return this.db.query(sql);",
                                "return this.db.query('SELECT id, name FROM users WHERE name LIKE ?', [`%${term}%`]);")
        if rel == "src/routes/fileRoutes.js":  # add a command injection
            text = text.replace("module.exports = router;",
                                "router.get('/ping', function ping(req, res) {\n  require('child_process').exec('ping -c 1 ' + req.query.host);\n  res.end();\n});\n\nmodule.exports = router;")
        return text

    r = client.post(f"/api/projects/{pid}/version", files={"file": ("v2.zip", _zip_dir("express-app", patch), "application/zip")}, data={"label": "v2"})
    assert r.status_code == 200, r.text
    head = _wait(client, r.json()["scan"]["scan_id"])
    assert head["source_ref"] == "v2"
    cmp = client.get(f"/api/scans/{base['scan_id']}/compare/{head['scan_id']}").json()
    assert {(f["function_name"], f["cwe"]) for f in cmp["fixed"]} == {("UserService.search", "CWE-89")}
    assert {(f["function_name"], f["cwe"]) for f in cmp["new"]} == {("ping", "CWE-78")}
    assert cmp["summary"]["still_open"] >= 5
    assert "GET /api/files/ping" in cmp["graph"]["routes_added"]
    assert cmp["graph"]["head_node_status"]["src/routes/fileRoutes.js::ping"] == "new"
    assert cmp["graph"]["base_node_status"]["src/services/userService.js::UserService.search"] == "fixed"
    assert client.get(f"/api/scans/{base['scan_id']}/compare/{base['scan_id']}").status_code == 400


# --------------------------------------------------------------- attack simulation
def test_attack_simulation(client):
    r = client.post("/api/projects/upload", files={"file": ("express-app.zip", _zip_dir("express-app"), "application/zip")}, data={"name": "atk"})
    s = _wait(client, r.json()["scan"]["scan_id"])
    fs = {f["function_name"]: f for f in client.get(f"/api/scans/{s['scan_id']}/findings").json()}
    dl = fs["downloadFile"]["attack"]
    assert dl["verdict"] == "exploitable"
    assert dl["request"]["url"] == "http://localhost:3005/api/files/download?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd"
    sq = fs["UserService.search"]["attack"]
    assert sq["request"]["method"] == "POST" and sq["request"]["path"] == "/api/users/search"
    assert sq["effect"] == "SELECT id, name FROM users WHERE name LIKE '%' OR '1'='1' -- %'"
    assert [st["kind"] for st in sq["steps"]] == ["request", "hop", "hop", "sink", "impact"]
    dead = fs["adminEval"]["attack"]
    assert dead["verdict"] == "blocked" and "never mounted" in dead["verdict_text"]
    assert fs["__top_level__"]["attack"] is None  # hardcoded secret: no request involved
    assert s["summary"]["attack_simulations"] >= 6


# --------------------------------------------------------------- dependency check
def test_dependency_check(client, monkeypatch):
    monkeypatch.setattr(dependency_check, "ENABLED", True)
    monkeypatch.setattr(dependency_check, "query_osv", lambda pkgs: [["GHSA-test"] if n == "lodash" else [] for n, _ in pkgs])
    monkeypatch.setattr(dependency_check, "vuln_details", lambda vid: {
        "id": vid, "summary": "Command injection in lodash", "details": "The template function allows code injection.",
        "aliases": ["CVE-2021-23337"], "database_specific": {"severity": "HIGH", "cwe_ids": ["CWE-94"]},
        "affected": [{"package": {"name": "lodash"}, "ranges": [{"events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}],
    })
    r = client.post("/api/projects/upload", files={"file": ("express-app.zip", _zip_dir("express-app"), "application/zip")}, data={"name": "deps"})
    s = _wait(client, r.json()["scan"]["scan_id"])
    deps = [f for f in client.get(f"/api/scans/{s['scan_id']}/findings").json() if f["finding_type"] == "dependency"]
    assert len(deps) == 1
    d = deps[0]
    assert d["dependency"]["package"] == "lodash" and d["dependency"]["fix_version"] == "4.17.21"
    assert d["dependency"]["vulnerable_functions_called"] == ["lodash.template"]
    assert d["reachability_status"] == "reachable" and d["taint"] == "user_input"
    assert d["function_name"] == "renderTemplate"
    assert s["summary"]["dependencies"]["vulnerable_packages"] == 1


def test_dependency_check_offline(monkeypatch, tmp_path):
    shutil.copytree(APPS / "express-app", tmp_path / "app")
    monkeypatch.setattr(dependency_check, "ENABLED", True)

    def boom(pkgs):
        raise OSError("no network")

    monkeypatch.setattr(dependency_check, "query_osv", boom)
    findings, summary = dependency_check.check(tmp_path / "app", {"nodes": []})
    assert findings == [] and summary["status"] == "offline"


def test_spec_to_version():
    assert dependency_check.spec_to_version("^4.17.4") == "4.17.4"
    assert dependency_check.spec_to_version("~1.2") == "1.2.0"
    assert dependency_check.spec_to_version("git+https://x") is None
    assert dependency_check.spec_to_version("latest") is None
