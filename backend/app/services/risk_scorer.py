"""Contextual risk scoring.

    base  = 0.45 * severity + 0.35 * exploitability + 0.20 * ai_probability
    risk  = 100 * base * reachability_multiplier

* severity        — impact of the vulnerability class (critical 1.0 … info 0.1)
* exploitability  — taint evidence: user input proven to reach the sink (1.0),
                    only a function parameter reaches it (0.6), no data flow
                    (configuration issues such as hardcoded secrets, 0.35)
* ai_probability  — function-level vulnerability probability from the ML model
* reachability    — reachable from an active request entry point (1.0),
                    unknown (0.6), executed only at startup (0.4), dead code (0.2)

Every score is returned with its breakdown so the UI can explain it.
"""
from __future__ import annotations

from typing import Dict, Tuple

SEVERITY_WEIGHT: Dict[str, float] = {
    "critical": 1.0, "high": 0.8, "medium": 0.55, "low": 0.3, "info": 0.1, "unknown": 0.4,
}
EXPLOITABILITY_WEIGHT: Dict[str, float] = {
    "user_input": 1.0, "parameter": 0.6, "none": 0.35, "unknown": 0.3,
}
REACHABILITY_MULTIPLIER: Dict[str, float] = {
    "reachable": 1.0, "unknown": 0.6, "startup_only": 0.4, "unreachable": 0.2,
}
WEIGHTS = {"severity": 0.45, "exploitability": 0.35, "ai": 0.20}
CATEGORY_THRESHOLDS = [(70.0, "Critical"), (45.0, "High"), (25.0, "Medium"), (0.0, "Low")]


def categorize(score: float) -> str:
    for threshold, label in CATEGORY_THRESHOLDS:
        if score >= threshold:
            return label
    return "Low"


def calculate_risk(
    severity: str,
    taint: str,
    ai_probability: float,
    reachability: str,
) -> Tuple[float, str, Dict[str, float]]:
    sev = SEVERITY_WEIGHT.get((severity or "unknown").lower(), 0.4)
    exp = EXPLOITABILITY_WEIGHT.get((taint or "unknown").lower(), 0.3)
    ai = max(0.0, min(1.0, float(ai_probability or 0.0)))
    reach = REACHABILITY_MULTIPLIER.get((reachability or "unknown").lower(), 0.6)
    base = WEIGHTS["severity"] * sev + WEIGHTS["exploitability"] * exp + WEIGHTS["ai"] * ai
    score = round(100.0 * base * reach, 2)
    breakdown = {
        "severity_weight": sev,
        "exploitability_weight": exp,
        "ai_probability": round(ai, 4),
        "reachability_multiplier": reach,
        "base": round(base, 4),
        "severity_contribution": round(100 * WEIGHTS["severity"] * sev * reach, 2),
        "exploitability_contribution": round(100 * WEIGHTS["exploitability"] * exp * reach, 2),
        "ai_contribution": round(100 * WEIGHTS["ai"] * ai * reach, 2),
    }
    return score, categorize(score), breakdown
