"""Risk scoring formula."""
from app.services.risk_scorer import calculate_risk, categorize


def test_confirmed_reachable_critical_is_top_priority():
    score, cat, b = calculate_risk("critical", "user_input", 0.9, "reachable")
    # 100 * 1.0 * (0.45*1.0 + 0.35*1.0 + 0.20*0.9) = 98.0
    assert score == 98.0
    assert cat == "Critical"
    assert b["reachability_multiplier"] == 1.0


def test_dead_code_is_deprioritized_even_when_critical():
    score, cat, _ = calculate_risk("critical", "user_input", 0.9, "unreachable")
    assert score == 19.6
    assert cat == "Low"


def test_ordering_reachability_beats_severity():
    reachable_medium, _, _ = calculate_risk("medium", "user_input", 0.3, "reachable")
    unreachable_critical, _, _ = calculate_risk("critical", "user_input", 0.9, "unreachable")
    startup_high, _, _ = calculate_risk("high", "parameter", 0.5, "startup_only")
    assert reachable_medium > startup_high > unreachable_critical


def test_taint_evidence_raises_score():
    a, _, _ = calculate_risk("high", "user_input", 0.5, "reachable")
    b, _, _ = calculate_risk("high", "parameter", 0.5, "reachable")
    c, _, _ = calculate_risk("high", "none", 0.5, "reachable")
    assert a > b > c


def test_breakdown_contributions_sum_to_score():
    score, _, b = calculate_risk("high", "parameter", 0.42, "startup_only")
    total = b["severity_contribution"] + b["exploitability_contribution"] + b["ai_contribution"]
    assert abs(total - score) < 0.05


def test_categories():
    assert categorize(70) == "Critical"
    assert categorize(45) == "High"
    assert categorize(25) == "Medium"
    assert categorize(10) == "Low"
