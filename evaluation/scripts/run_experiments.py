"""
ReachPrioritizer experimental evaluation.

Runs the *production* pipeline (Node analysis engine + AI model + risk scorer, exactly
as the backend does) on every benchmark application and measures:

  A. Detection (function level)   — ReachPrioritizer taint engine vs. baselines:
       * AI-only classifier (function probability >= model threshold)
       * v1 prototype regex rule engine
       * ESLint + eslint-plugin-security (if installed)
  B. Reachability accuracy         — predicted "reachable from a request entry point"
                                     vs. ground truth
  C. Prioritization (ranking)      — 6 scoring schemes over the same candidate set:
       E0 severity only (classic SAST ordering)      E3 AI + reachability
       E1 AI probability only                        E4 AI + severity + reachability (v1 formula)
       E2 AI + severity                              E5 full ReachPrioritizer (+ taint evidence)
     relevance = function is truly vulnerable AND truly reachable (exploitable)

Benchmarks:
  * test-applications/{vulnerable,secure,mixed,express}-app      (controlled, fully labeled)
  * evaluation/realworld/repos/{NodeGoat,dvna}                    (real projects; fetch with
    evaluation/realworld/fetch_realworld.sh — skipped when absent)

Usage:  python evaluation/scripts/run_experiments.py
Output: evaluation/results/comparative_evaluation.json and evaluation/results/RESULTS.md
"""
from __future__ import annotations

import json
import math
import platform
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "evaluation" / "baselines"))

import warnings  # noqa: E402

warnings.filterwarnings("ignore")

from app.core.orchestrator import build_findings  # noqa: E402
from app.services.analyzer_runner import run_analyzer  # noqa: E402
from app.services.risk_scorer import REACHABILITY_MULTIPLIER, SEVERITY_WEIGHT, calculate_risk  # noqa: E402
from ai.inference.predictor import get_predictor  # noqa: E402
import eslint_security  # noqa: E402
import legacy_regex_scanner  # noqa: E402

RESULTS_DIR = ROOT / "evaluation" / "results"
CONTROLLED = ["vulnerable-app", "secure-app", "mixed-app", "express-app"]
REALWORLD = [("NodeGoat", "nodegoat"), ("dvna", "dvna")]
KS = (1, 3, 5)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def find_node(nodes: List[Dict], gt: Dict) -> Optional[Dict]:
    in_file = [n for n in nodes if n["file_path"] == gt["file"]]
    if gt.get("line"):
        cont = [n for n in in_file if n["node_type"] != "Module" and n["start_line"] <= gt["line"] <= n["end_line"]]
        cont.sort(key=lambda n: n["end_line"] - n["start_line"])
        return cont[0] if cont else None
    return next((n for n in in_file if n["name"] == gt["function"]), None) or next((n for n in in_file if n.get("short") == gt["function"]), None)


def innermost(nodes_by_file: Dict[str, List[Dict]], file_path: str, line: int) -> Optional[str]:
    best = None
    for n in nodes_by_file.get(file_path, []):
        if n["start_line"] <= line <= n["end_line"]:
            if best is None or (n["end_line"] - n["start_line"]) < (best["end_line"] - best["start_line"]):
                best = n
    return best["id"] if best else None


def prf(tp: int, fp: int, fn: int, tn: Optional[int] = None) -> Dict[str, Any]:
    p = tp / (tp + fp) if tp + fp else (1.0 if fn == 0 and tp == 0 else 0.0)
    r = tp / (tp + fn) if tp + fn else 1.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    out = {"tp": tp, "fp": fp, "fn": fn, "precision": round(p, 4), "recall": round(r, 4), "f1": round(f, 4)}
    if tn is not None:
        out["tn"] = tn
        out["accuracy"] = round((tp + tn) / max(1, tp + tn + fp + fn), 4)
    return out


def dcg(rels: List[int], k: int) -> float:
    return sum((2 ** r - 1) / math.log2(i + 2) for i, r in enumerate(rels[:k]))


def ranking_metrics(rels: List[int], total_relevant: int) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k in KS:
        out[f"precision_at_{k}"] = round(sum(rels[:k]) / k, 4) if rels else 0.0
    ideal = sorted(rels, reverse=True)
    for k in (5, 10):
        idcg = dcg([1] * min(total_relevant, k), k)
        out[f"ndcg_at_{k}"] = round(dcg(rels, k) / idcg, 4) if idcg else None
    hits, ap = 0, 0.0
    for i, r in enumerate(rels):
        if r:
            hits += 1
            ap += hits / (i + 1)
    out["average_precision"] = round(ap / total_relevant, 4) if total_relevant else None
    out["first_relevant_rank"] = next((i + 1 for i, r in enumerate(rels) if r), None)
    out["candidates"] = len(rels)
    out["relevant"] = total_relevant
    return out


# ---------------------------------------------------------------------------
# scoring schemes (applied to the same per-function candidates)
# ---------------------------------------------------------------------------
V1_REACH = {"reachable": 1.0, "unknown": 0.6, "startup_only": 0.25, "unreachable": 0.25}


def schemes() -> Dict[str, Tuple[str, Callable[[Dict], float]]]:
    sev = lambda c: SEVERITY_WEIGHT.get(c["severity"], 0.4)  # noqa: E731
    return {
        "E0_severity_only": ("Severity only (classic SAST)", lambda c: sev(c)),
        "E1_ai_only": ("AI probability only", lambda c: c["ai"]),
        "E2_ai_severity": ("AI + severity", lambda c: 0.5 * c["ai"] + 0.5 * sev(c)),
        "E3_ai_reachability": ("AI + reachability", lambda c: REACHABILITY_MULTIPLIER.get(c["reach"], 0.6) * c["ai"]),
        "E4_ai_severity_reachability": ("AI + severity + reachability (v1 formula)", lambda c: V1_REACH.get(c["reach"], 0.6) * (0.5 * c["ai"] + 0.5 * sev(c))),
        "E5_reachprioritizer": ("Full ReachPrioritizer (severity + taint + AI + reachability)", lambda c: calculate_risk(c["severity"], c["taint"], c["ai"], c["reach"])[0] / 100.0),
    }


# ---------------------------------------------------------------------------
# per-application evaluation
# ---------------------------------------------------------------------------
def evaluate_app(name: str, app_dir: Path, gt: Dict, predictor, selection: Dict, labeled_safe: bool) -> Dict[str, Any]:
    t0 = time.time()
    analysis = run_analyzer(app_dir)
    nodes = analysis["nodes"]
    by_id = {n["id"]: n for n in nodes}
    by_file: Dict[str, List[Dict]] = {}
    for n in nodes:
        by_file.setdefault(n["file_path"], []).append(n)
    fn_nodes = [n for n in nodes if n["node_type"] != "Module" and (n.get("source") or "").strip()]
    probs = dict(zip([n["id"] for n in fn_nodes], predictor.predict_proba([n["source"] for n in fn_nodes]))) if predictor else {}
    findings = build_findings(analysis, probs, selection, app_dir)
    elapsed = round(time.time() - t0, 2)

    # ---- ground-truth mapping
    labels: Dict[str, Dict] = {}
    missing = []
    for entry in gt["functions"]:
        node = find_node(nodes, entry)
        if node:
            labels[node["id"]] = entry
        else:
            missing.append(f"{entry['file']}::{entry['function']}")

    # ---- detectors -> set of flagged function ids
    threshold = float(selection.get("threshold", 0.5))
    detectors: Dict[str, Optional[set]] = {
        "reachprioritizer_taint": {f["function_id"] for f in findings if f["finding_type"] == "static_finding"},
        "ai_only_classifier": {fid for fid, p in probs.items() if p >= threshold},
        "v1_regex_rules": {innermost(by_file, f["file_path"], f["line"]) for f in legacy_regex_scanner.scan(app_dir)} - {None},
    }
    es = eslint_security.scan(app_dir)
    detectors["eslint_plugin_security"] = None if es is None else ({innermost(by_file, f["file_path"], f["line"]) for f in es} - {None})

    detection = {}
    for det, flagged in detectors.items():
        if flagged is None:
            detection[det] = None
            continue
        tp = sum(1 for fid, e in labels.items() if e["is_vulnerable"] and fid in flagged)
        fn = sum(1 for fid, e in labels.items() if e["is_vulnerable"] and fid not in flagged)
        fp = sum(1 for fid, e in labels.items() if not e["is_vulnerable"] and fid in flagged)
        tn = sum(1 for fid, e in labels.items() if not e["is_vulnerable"] and fid not in flagged)
        d = prf(tp, fp, fn, tn) if labeled_safe else {"tp": tp, "fn": fn, "recall": round(tp / max(1, tp + fn), 4)}
        d["flagged_functions"] = len(flagged)
        d["flagged_unlabeled"] = len([f for f in flagged if f not in labels])
        detection[det] = d

    # ---- reachability (labeled functions only)
    tp = fp = fn = tn = 0
    reach_errors = []
    for fid, e in labels.items():
        pred = by_id[fid]["reachability"] == "reachable"
        if pred and e["is_reachable"]:
            tp += 1
        elif pred and not e["is_reachable"]:
            fp += 1
            reach_errors.append(f"{fid} predicted reachable")
        elif not pred and e["is_reachable"]:
            fn += 1
            reach_errors.append(f"{fid} predicted {by_id[fid]['reachability']}")
        else:
            tn += 1
    reachability = prf(tp, fp, fn, tn)
    reachability["errors"] = reach_errors

    # ---- prioritization: one candidate per function (its highest-risk finding)
    best: Dict[str, Dict] = {}
    for f in findings:
        fid = f["function_id"]
        if fid not in best or f["risk_score"] > best[fid]["risk_score"]:
            best[fid] = f
    for fid, p in probs.items():  # AI-flagged functions are candidates too (AI-only scheme must be fair)
        if p >= threshold and fid not in best:
            n = by_id[fid]
            best[fid] = {"function_id": fid, "severity": "low", "taint": "unknown", "reachability_status": n["reachability"]}
    candidates = []
    for fid, f in best.items():
        e = labels.get(fid)
        candidates.append({
            "fid": fid, "severity": f["severity"], "taint": f["taint"], "reach": f["reachability_status"],
            "ai": probs.get(fid, 0.0), "relevant": int(bool(e and e["is_vulnerable"] and e["is_reachable"])),
        })
    total_rel = sum(1 for e in labels.values() if e["is_vulnerable"] and e["is_reachable"])
    ranking = {}
    for key, (label, fn_score) in schemes().items():
        ordered = sorted(candidates, key=lambda c: (-fn_score(c), c["fid"]))
        m = ranking_metrics([c["relevant"] for c in ordered], total_rel)
        m["name"] = label
        m["top_5"] = [{"rank": i + 1, "function": c["fid"], "score": round(fn_score(c), 4), "exploitable": bool(c["relevant"]),
                       "reachability": c["reach"], "taint": c["taint"]} for i, c in enumerate(ordered[:5])]
        ranking[key] = m

    return {
        "application": name,
        "files": analysis["stats"]["files_analyzed"],
        "functions": analysis["stats"]["functions"],
        "edges": analysis["stats"]["edges"],
        "analysis_seconds": elapsed,
        "labeled_functions": len(labels),
        "labeled_vulnerable": sum(1 for e in labels.values() if e["is_vulnerable"]),
        "exploitable": total_rel,
        "missing_ground_truth_functions": missing,
        "detection": detection,
        "reachability": reachability,
        "prioritization": ranking,
        "findings_total": len(findings),
        "findings_reachable_user_input": sum(1 for f in findings if f["reachability_status"] == "reachable" and f["taint"] == "user_input"),
    }


def mean_over(apps: List[Dict], scheme: str, metric: str) -> Optional[float]:
    vals = [a["prioritization"][scheme].get(metric) for a in apps if a["exploitable"] > 0 and a["prioritization"][scheme].get(metric) is not None]
    return round(sum(vals) / len(vals), 4) if vals else None


def pooled_detection(apps: List[Dict], det: str) -> Optional[Dict]:
    rows = [a["detection"][det] for a in apps if a["detection"].get(det) is not None and "fp" in a["detection"][det]]
    if not rows:
        return None
    return prf(sum(r["tp"] for r in rows), sum(r["fp"] for r in rows), sum(r["fn"] for r in rows), sum(r["tn"] for r in rows))


def main() -> None:
    predictor, selection = get_predictor("auto")
    print(f"Model: {selection['display_name']} (threshold {selection['threshold']})")
    controlled, realworld = [], []
    for app in CONTROLLED:
        d = ROOT / "test-applications" / app
        gt = json.loads((d / "ground-truth.json").read_text(encoding="utf-8"))
        r = evaluate_app(app, d, gt, predictor, selection, labeled_safe=True)
        controlled.append(r)
        print(f"  {app:16s} detection F1={r['detection']['reachprioritizer_taint']['f1']:.3f}  reach acc={r['reachability']['accuracy']:.3f}  "
              f"E5 P@1={r['prioritization']['E5_reachprioritizer']['precision_at_1']}")
    for repo, gtname in REALWORLD:
        d = ROOT / "evaluation" / "realworld" / "repos" / repo
        if not d.exists():
            print(f"  {repo}: not fetched (run evaluation/realworld/fetch_realworld.sh) — skipped")
            continue
        gt = json.loads((ROOT / "evaluation" / "realworld" / f"{gtname}.ground-truth.json").read_text(encoding="utf-8"))
        r = evaluate_app(repo, d, gt, predictor, selection, labeled_safe=False)
        r["repository"], r["commit"] = gt.get("repository"), gt.get("commit")
        realworld.append(r)
        print(f"  {repo:16s} recall={r['detection']['reachprioritizer_taint']['recall']:.3f}  reach acc={r['reachability']['accuracy']:.3f}")

    all_apps = controlled + realworld
    summary = {
        "detection_controlled_pooled": {det: pooled_detection(controlled, det) for det in controlled[0]["detection"]},
        "detection_realworld_recall": {
            det: (round(sum(a["detection"][det]["tp"] for a in realworld) / max(1, sum(a["detection"][det]["tp"] + a["detection"][det]["fn"] for a in realworld)), 4)
                  if realworld and all(a["detection"].get(det) is not None for a in realworld) else None)
            for det in controlled[0]["detection"]
        },
        "reachability_pooled": prf(*(sum(a["reachability"][k] for a in all_apps) for k in ("tp", "fp", "fn", "tn"))),
        "prioritization_mean": {
            s: {m: mean_over(all_apps, s, m) for m in ("precision_at_1", "precision_at_3", "precision_at_5", "ndcg_at_5", "ndcg_at_10", "average_precision")}
            | {"name": schemes()[s][0]}
            for s in schemes()
        },
    }
    result = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "description": "Comparative evaluation of detection, reachability and prioritization (produced by evaluation/scripts/run_experiments.py)",
        "environment": {
            "model": selection["model_name"], "model_display": selection["display_name"], "threshold": selection["threshold"],
            "model_test_metrics": selection.get("test_metrics"), "python": platform.python_version(),
            "eslint_baseline": eslint_security.available(),
        },
        "relevance_definition": "A candidate is relevant (exploitable) when ground truth marks the function vulnerable AND reachable from an active request entry point.",
        "summary": summary,
        "controlled": controlled,
        "realworld": realworld,
    }
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    (RESULTS_DIR / "comparative_evaluation.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    (RESULTS_DIR / "RESULTS.md").write_text(render_markdown(result), encoding="utf-8")
    print(f"\nWrote {RESULTS_DIR / 'comparative_evaluation.json'} and RESULTS.md")


def _fmt(v: Any) -> str:
    if v is None:
        return "–"
    if isinstance(v, float):
        return f"{v:.3f}"
    return str(v)


def render_markdown(r: Dict[str, Any]) -> str:
    s = r["summary"]
    lines = [
        "# ReachPrioritizer — evaluation results",
        "",
        f"Generated {r['generated_at']} by `evaluation/scripts/run_experiments.py` (do not edit by hand).",
        f"AI model: **{r['environment']['model_display']}** (threshold {r['environment']['threshold']}).",
        "",
        "## A. Detection on the controlled applications (function level, pooled)",
        "",
        "| Detector | TP | FP | FN | TN | Precision | Recall | F1 |",
        "|---|---|---|---|---|---|---|---|",
    ]
    names = {"reachprioritizer_taint": "ReachPrioritizer taint engine", "ai_only_classifier": "AI classifier only",
             "v1_regex_rules": "v1 prototype regex rules", "eslint_plugin_security": "ESLint plugin-security"}
    for det, m in s["detection_controlled_pooled"].items():
        if m is None:
            lines.append(f"| {names.get(det, det)} | – | – | – | – | – | – | – |")
        else:
            lines.append(f"| {names.get(det, det)} | {m['tp']} | {m['fp']} | {m['fn']} | {m['tn']} | {_fmt(m['precision'])} | {_fmt(m['recall'])} | {_fmt(m['f1'])} |")
    if r["realworld"]:
        lines += ["", "Recall on the documented vulnerabilities of the real-world projects: " +
                  ", ".join(f"{names.get(k, k)} {_fmt(v)}" for k, v in s["detection_realworld_recall"].items()) + "."]
    rp = s["reachability_pooled"]
    lines += ["", "## B. Reachability (labeled functions, all applications)", "",
              f"Accuracy **{_fmt(rp['accuracy'])}**, precision {_fmt(rp['precision'])}, recall {_fmt(rp['recall'])}, F1 {_fmt(rp['f1'])} "
              f"(TP {rp['tp']}, FP {rp['fp']}, FN {rp['fn']}, TN {rp['tn']}).", "",
              "## C. Prioritization (mean over applications that contain exploitable vulnerabilities)", "",
              "| Scheme | P@1 | P@3 | P@5 | NDCG@5 | NDCG@10 | MAP |", "|---|---|---|---|---|---|---|"]
    for key, m in s["prioritization_mean"].items():
        lines.append(f"| {m['name']} | {_fmt(m['precision_at_1'])} | {_fmt(m['precision_at_3'])} | {_fmt(m['precision_at_5'])} | {_fmt(m['ndcg_at_5'])} | {_fmt(m['ndcg_at_10'])} | {_fmt(m['average_precision'])} |")
    lines += ["", "## Per application", "", "| Application | Files | Functions | Labeled | Vulnerable | Exploitable | Taint F1 / recall | Reachability acc. | E5 P@1 | E5 MAP |", "|---|---|---|---|---|---|---|---|---|---|"]
    for a in r["controlled"] + r["realworld"]:
        d = a["detection"]["reachprioritizer_taint"]
        det = _fmt(d.get("f1")) if "f1" in d else f"recall {_fmt(d['recall'])}"
        e5 = a["prioritization"]["E5_reachprioritizer"]
        p1 = _fmt(e5['precision_at_1']) if a['exploitable'] else "–"
        lines.append(f"| {a['application']} | {a['files']} | {a['functions']} | {a['labeled_functions']} | {a['labeled_vulnerable']} | {a['exploitable']} | {det} | {_fmt(a['reachability']['accuracy'])} | {p1} | {_fmt(e5['average_precision'])} |")
    lines += ["", "Ties in a ranking are broken alphabetically by function id (neutral). Unlabeled functions in the real-world projects count as non-relevant, so their precision figures are lower bounds.", ""]
    return "\n".join(lines)


if __name__ == "__main__":
    main()
