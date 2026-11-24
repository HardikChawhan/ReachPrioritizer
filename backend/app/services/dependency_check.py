"""Reachable dependency check.

1. Read every package.json (and package-lock.json / yarn.lock for exact versions).
2. Ask the public OSV database (https://osv.dev, run by Google) which of those
   package versions have known vulnerabilities (CVE / GHSA advisories).
3. Use the call graph to decide whether the project actually *calls* the
   vulnerable package from a reachable route, and whether user input is passed in.

Most dependency scanners stop at step 2 and flag every old package. Step 3 is what
lets ReachPrioritizer rank "lodash is called from GET /api/merge with request
data" far above "an old dev tool that is never imported".
"""
from __future__ import annotations

import json
import logging
import os
import re
import threading
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from app.services.risk_scorer import calculate_risk

logger = logging.getLogger(__name__)

OSV_API = os.environ.get("RP_OSV_URL", "https://api.osv.dev").rstrip("/")
ENABLED = os.environ.get("RP_ENABLE_DEPCHECK", "1") != "0"
TIMEOUT = float(os.environ.get("RP_OSV_TIMEOUT", "20"))
MAX_MANIFESTS = 25

_cache: Dict[str, Dict[str, Any]] = {}
_cache_lock = threading.Lock()

SEVERITY_MAP = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}
SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
REACH_RANK = {"reachable": 3, "startup_only": 2, "unknown": 1, "unreachable": 0}
GENERIC_API_WORDS = {"default", "call", "apply", "bind", "then", "catch", "use", "json", "send", "end", "on", "get", "set"}


# ---------------------------------------------------------------- versions
def parse_version(v: str) -> Tuple[int, ...]:
    m = re.match(r"^\D*(\d+)(?:\.(\d+))?(?:\.(\d+))?", v or "")
    if not m:
        return (0,)
    return tuple(int(x or 0) for x in m.groups())


def spec_to_version(spec: str) -> Optional[str]:
    """'^4.17.4' -> '4.17.4' (the lowest version the range allows)."""
    if not isinstance(spec, str):
        return None
    s = spec.strip()
    if any(s.startswith(p) for p in ("git", "http", "file:", "link:", "workspace:", "npm:")) or "/" in s:
        return None
    m = re.match(r"^[\^~>=v\s]*(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)", s)
    if m:
        return m.group(1)
    m = re.match(r"^[\^~>=v\s]*(\d+)\.(\d+)(?:\.[x*])?$", s)
    if m:
        return f"{m.group(1)}.{m.group(2)}.0"
    return None


def _lock_versions(folder: Path) -> Dict[str, str]:
    out: Dict[str, str] = {}
    lock = folder / "package-lock.json"
    if lock.is_file():
        try:
            data = json.loads(lock.read_text(encoding="utf-8", errors="replace"))
            for key, info in (data.get("packages") or {}).items():
                if key.startswith("node_modules/") and "/node_modules/" not in key[len("node_modules/"):] and isinstance(info, dict) and info.get("version"):
                    out[key[len("node_modules/"):]] = info["version"]
            for name, info in (data.get("dependencies") or {}).items():
                if isinstance(info, dict) and info.get("version") and name not in out:
                    out[name] = info["version"]
        except (OSError, ValueError) as exc:
            logger.info("Could not read %s: %s", lock, exc)
    yarn = folder / "yarn.lock"
    if yarn.is_file() and not out:
        try:
            current: List[str] = []
            for line in yarn.read_text(encoding="utf-8", errors="replace").splitlines():
                if line and not line.startswith((" ", "#")) and line.rstrip().endswith(":"):
                    current = []
                    for part in line.rstrip(":").split(","):
                        part = part.strip().strip('"')
                        name = part.rsplit("@", 1)[0] if part.count("@") > (1 if part.startswith("@") else 0) else part
                        if name:
                            current.append(name)
                else:
                    m = re.match(r'^\s+version:?\s+"?([^"\s]+)"?', line)
                    if m and current:
                        for name in current:
                            out.setdefault(name, m.group(1))
                        current = []
        except OSError:
            pass
    return out


def find_dependencies(root: Path) -> List[Dict[str, Any]]:
    deps: List[Dict[str, Any]] = []
    manifests: List[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in ("node_modules", ".git", "dist", "build", "coverage")]
        if "package.json" in filenames:
            manifests.append(Path(dirpath) / "package.json")
        if len(manifests) >= MAX_MANIFESTS:
            break
    for mf in sorted(manifests, key=lambda p: len(p.parts)):
        try:
            text = mf.read_text(encoding="utf-8", errors="replace")
            pkg = json.loads(text)
        except (OSError, ValueError):
            continue
        if not isinstance(pkg, dict):
            continue
        locked = _lock_versions(mf.parent)
        lines = text.splitlines()
        rel = mf.relative_to(root).as_posix()
        for section, dev in (("dependencies", False), ("devDependencies", True), ("optionalDependencies", False)):
            block = pkg.get(section)
            if not isinstance(block, dict):
                continue
            for name, spec in block.items():
                version = locked.get(name)
                source = "package-lock" if version else "package.json range"
                version = version or spec_to_version(spec if isinstance(spec, str) else "")
                line = next((i + 1 for i, l in enumerate(lines) if re.search(rf'"{re.escape(name)}"\s*:', l)), 1)
                deps.append({"name": name, "spec": spec, "version": version, "version_source": source if version else "unknown",
                             "dev": dev, "manifest": rel, "line": line})
    return deps


# ---------------------------------------------------------------- OSV
def _post(url: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json", "User-Agent": "ReachPrioritizer"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return json.loads(r.read().decode("utf-8"))


def _get(url: str) -> Dict[str, Any]:
    req = urllib.request.Request(url, headers={"User-Agent": "ReachPrioritizer"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return json.loads(r.read().decode("utf-8"))


def query_osv(packages: List[Tuple[str, str]]) -> List[List[str]]:
    """Vulnerability ids for each (name, version)."""
    results: List[List[str]] = []
    for i in range(0, len(packages), 500):
        chunk = packages[i:i + 500]
        data = _post(f"{OSV_API}/v1/querybatch", {"queries": [{"package": {"name": n, "ecosystem": "npm"}, "version": v} for n, v in chunk]})
        for res in data.get("results", []):
            results.append([v["id"] for v in (res.get("vulns") or [])])
    return results


def vuln_details(vid: str) -> Dict[str, Any]:
    with _cache_lock:
        if vid in _cache:
            return _cache[vid]
    d = _get(f"{OSV_API}/v1/vulns/{vid}")
    with _cache_lock:
        _cache[vid] = d
    return d


def _fixed_for(vuln: Dict[str, Any], name: str) -> List[str]:
    out = []
    for a in vuln.get("affected", []):
        if (a.get("package") or {}).get("name") != name:
            continue
        for r in a.get("ranges", []):
            for e in r.get("events", []):
                if e.get("fixed"):
                    out.append(e["fixed"])
    return out


def _advisory(vuln: Dict[str, Any], name: str, version: str) -> Dict[str, Any]:
    dbs = vuln.get("database_specific") or {}
    sev = SEVERITY_MAP.get(str(dbs.get("severity") or "").upper(), "medium")
    fixed = sorted({f for f in _fixed_for(vuln, name) if parse_version(f) > parse_version(version)}, key=parse_version)
    aliases = vuln.get("aliases") or []
    cves = [a for a in aliases if a.startswith("CVE-")]
    vid = vuln.get("id", "")
    return {
        "id": vid,
        "cve": cves[0] if cves else None,
        "summary": vuln.get("summary") or (vuln.get("details") or "")[:160],
        "details": (vuln.get("details") or "")[:1500],
        "severity": sev,
        "cwes": dbs.get("cwe_ids") or [],
        "fixed": fixed[0] if fixed else None,
        "url": f"https://osv.dev/vulnerability/{vid}",
    }


# ---------------------------------------------------------------- reachability
def _usage_reach(uses: List[Dict[str, Any]], by_id: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    calls = [u for u in uses if not u.get("import")]
    best = None
    best_key = (-1, -1)
    for u in calls or uses:
        n = by_id.get(u.get("caller")) or {}
        r = n.get("reachability") or "unknown"
        if n.get("node_type") == "Module" and r == "reachable" and not u.get("import"):
            r = "reachable"
        key = (REACH_RANK.get(r, 0), 1 if u.get("user_input") else 0)
        if key > best_key:
            best_key, best = key, {**u, "reachability": r, "node": n}
    if not uses:
        return {"status": "unused", "reachability": "unreachable", "best": None}
    if not calls:
        # imported but no call detected: importing runs the package's top level only
        r = (best or {}).get("reachability", "unknown")
        return {"status": "imported", "reachability": "startup_only" if r in ("reachable", "startup_only") else "unreachable", "best": best}
    return {"status": "called", "reachability": best["reachability"], "best": best}


def _called_functions(uses: List[Dict[str, Any]], advisories: List[Dict[str, Any]]) -> List[str]:
    text = " ".join(f"{a['summary']} {a['details']}" for a in advisories).lower()
    hits = []
    for u in uses:
        api = u.get("api") or ""
        if u.get("import") or "." not in api:
            continue
        fn = api.split(".")[-1]
        if len(fn) < 3 or fn.lower() in GENERIC_API_WORDS:
            continue
        if re.search(rf"(?<![a-z0-9_]){re.escape(fn.lower())}(?![a-z0-9_])", text) and api not in hits:
            hits.append(api)
    return hits[:8]


def check(project_dir: Path, analysis: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Return (findings, summary). Never raises: network problems become a summary note."""
    summary: Dict[str, Any] = {"status": "skipped", "packages": 0, "checked": 0, "vulnerable_packages": 0, "advisories": 0, "reachable": 0}
    if not ENABLED:
        summary["note"] = "Dependency check disabled (RP_ENABLE_DEPCHECK=0)"
        return [], summary
    deps = find_dependencies(project_dir)
    summary["packages"] = len(deps)
    if not deps:
        summary.update(status="no_manifest", note="No package.json found")
        return [], summary
    seen = {}
    for d in deps:
        if d["version"] and (d["name"], d["version"]) not in seen:
            seen[(d["name"], d["version"])] = d
    pkgs = list(seen.keys())
    summary["checked"] = len(pkgs)
    try:
        ids = query_osv(pkgs)
        all_ids = sorted({i for lst in ids for i in lst})
        with ThreadPoolExecutor(max_workers=8) as ex:
            details = dict(zip(all_ids, ex.map(vuln_details, all_ids)))
    except (urllib.error.URLError, OSError, ValueError, TimeoutError) as exc:
        logger.warning("OSV lookup failed: %s", exc)
        summary.update(status="offline", note=f"Could not reach the OSV vulnerability database ({exc.__class__.__name__}); dependency check skipped.")
        return [], summary

    nodes = analysis.get("nodes", [])
    by_id = {n["id"]: n for n in nodes}
    usage = analysis.get("dependency_usage") or {}
    findings: List[Dict[str, Any]] = []
    for (name, version), vids in zip(pkgs, ids):
        if not vids:
            continue
        dep = seen[(name, version)]
        advisories = [_advisory(details[v], name, version) for v in vids if v in details]
        # drop withdrawn / duplicate aliases
        advisories.sort(key=lambda a: -SEV_RANK.get(a["severity"], 0))
        sev = advisories[0]["severity"] if advisories else "medium"
        fixes = [a["fixed"] for a in advisories if a["fixed"]]
        fix_version = max(fixes, key=parse_version) if fixes else None
        uses = usage.get(name, [])
        reach = _usage_reach(uses, by_id)
        best = reach["best"] or {}
        node = best.get("node") or {}
        called = _called_functions(uses, advisories)
        taint = "user_input" if any(u.get("user_input") for u in uses if not u.get("import")) else "none"
        reachability = reach["reachability"]
        if dep["dev"] and reach["status"] == "unused":
            reachability = "unreachable"
        # a called advisory-named function is stronger evidence than a plain import
        ai_like = 0.9 if called else (0.5 if reach["status"] == "called" else 0.1)
        score, category, breakdown = calculate_risk(sev, taint, ai_like, reachability)
        breakdown = {**breakdown, "note": "AI term replaced by evidence that the vulnerable package function is called (0.9), the package is called (0.5) or only imported/unused (0.1)."}
        cwes = [c for a in advisories for c in a["cwes"]]
        usage_rows = [{k: u.get(k) for k in ("caller", "api", "line", "file", "user_input", "import")} for u in uses[:25]]
        status_text = {
            "called": f"called from {node.get('name') or best.get('caller', '?')}",
            "imported": "imported, but no call to it was found",
            "unused": "declared in package.json but never imported",
        }[reach["status"]]
        msg = (f"{name}@{version} has {len(advisories)} known vulnerabilit{'y' if len(advisories) == 1 else 'ies'} "
               f"(worst: {sev}); the package is {status_text}.")
        if called:
            msg += f" The code calls {', '.join(called[:3])}, which the advisory text mentions."
        if fix_version:
            msg += f" Upgrade to {fix_version} or later."
        findings.append({
            "function_id": best.get("caller") if reach["status"] != "unused" else None,
            "function_name": node.get("name") or (f"{name} (package)" if reach["status"] == "unused" else ""),
            "file_path": dep["manifest"],
            "start_line": dep["line"],
            "end_line": dep["line"],
            "line": dep["line"],
            "related_lines": [dep["line"]],
            "snippet": f'"{name}": "{dep["spec"]}"',
            "source_code": f'"{name}": "{dep["spec"]}"',
            "prediction": "vulnerable",
            "vulnerability_probability": 0.0,
            "model_used": "osv.dev",
            "rule_id": "rp.dep.vulnerable-package",
            "title": f"Vulnerable dependency: {name}@{version}",
            "rule_message": msg,
            "severity": sev,
            "cwe": cwes[0] if cwes else "CWE-1395",
            "category": "dependency",
            "sink": called[0] if called else (best.get("api") if reach["status"] == "called" else None),
            "taint": taint,
            "reachability_status": reachability,
            "entry_point": node.get("entry"),
            "call_path": node.get("call_path") or [],
            "taint_path": [best["caller"]] if best.get("caller") and reach["status"] != "unused" else [],
            "risk_score": score,
            "risk_category": category,
            "risk_breakdown": breakdown,
            "finding_type": "dependency",
            "detector": "osv.dev",
            "attack": None,
            "dependency": {
                "package": name, "version": version, "version_source": dep["version_source"], "spec": dep["spec"],
                "dev": dep["dev"], "manifest": dep["manifest"], "fix_version": fix_version, "usage_status": reach["status"],
                "vulnerable_functions_called": called, "advisories": advisories, "usage": usage_rows,
            },
        })
    summary.update(status="ok", vulnerable_packages=len(findings), advisories=sum(len(f["dependency"]["advisories"]) for f in findings),
                   reachable=sum(1 for f in findings if f["reachability_status"] == "reachable"))
    return findings, summary


__all__ = ["check", "find_dependencies", "spec_to_version", "parse_version"]
