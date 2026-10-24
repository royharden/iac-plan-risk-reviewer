"""Regression source for aggregate renderer; synthetic counters are not measurements."""
from __future__ import annotations

import pytest

from eval.runner.results import ARMS, COUNT_KEYS, RATE_KEYS, RULES, render_results


def _score(*, status="INCOMPLETE", d_gate=False, private_case_id="private-case-id", failed_arms=("D",)):
    arms = {}
    for arm in ARMS:
        per_rule = {}
        for index, rule in enumerate(RULES):
            counts = {key: 0 for key in COUNT_KEYS}
            counts["total"] = 1 if index == 0 else 0
            per_rule[rule] = counts | {key: None for key in RATE_KEYS}
        arms[arm] = {
            "measurement_status": status, "comparison_basis": "fixture",
            "per_rule": per_rule,
            "failures": [{"case_id": private_case_id, "resource_id": "private-resource",
                          "rule_id": "R1", "reasons": ["abstention"]}] if arm in failed_arms else [],
            "row_known_usd_subtotal": 0.0, "known_usd": None, "all_attempt_cost": None,
            "cost_completeness": "ROW_SUBTOTAL_ONLY", "cost_scope": "row only",
            "billing_fully_known": False, "row_unresolved_upper_bounds_known": True,
            "row_unresolved_usd_upper_subtotal": 0.0, "unresolved_upper_bounds_known": False,
            "unresolved_usd_upper": None,
        }
    return {"split": "validation", "oracle_rows": 1, "arms": arms,
            "deterministic_exact_gate": d_gate, "authorship_authenticated": False,
            "product_acceptance": False, "limitations": []}


def test_all_seven_arms_render_with_missing_as_not_measured():
    result = render_results(_score())
    assert tuple(result["arms"]) == ARMS
    assert all(result["arms"][arm]["status"] == "NOT MEASURED" for arm in ARMS)
    assert "NOT MEASURED" in result["markdown"]


def test_zero_metric_denominator_renders_na_and_negative_gate_is_failure():
    source = _score(status="RECORDED", d_gate=False)
    result = render_results(source)
    assert result["arms"]["D"]["status"] == "FAIL"
    assert "D exact gate: **FAIL**" in result["markdown"]
    assert "NA" in result["markdown"]


def test_private_case_identifiers_do_not_enter_aggregate_output():
    result = render_results(_score())
    assert "private-case-id" not in result["markdown"]
    assert "private-resource" not in result["markdown"]
    assert "private-case-id" not in str(result["arms"])


def test_pairwise_failure_overlap_is_counted_without_exposing_case_keys():
    result = render_results(_score(failed_arms=("D", "L")))
    assert result["failure_overlap"]["D|L"] == 1
    assert "D / L | 1" in result["markdown"]
    assert "private-case-id" not in result["markdown"]


def test_missing_model_accounting_is_not_replaced_by_row_zero():
    result = render_results(_score())
    cost = result["arms"]["P"]["cost"]
    assert cost["all_attempt"].startswith("NOT MEASURED")
    assert cost["row_known_usd_subtotal"] == 0.0
    assert "all-attempt accounting absent" in cost["all_attempt"]


def test_batch_renderer_keeps_distinct_scenarios_and_one_global_cost_boundary():
    batch = {"batch": True, "eligible_raw_scenarios": 24, "eligible_findings": 48,
        "invocations": [{} for _ in range(24)], "cases_missing_or_incomplete": [],
        "unmatched_global_attempt_ids": ["private-unmatched-attempt"],
        "cost_accounting": {"invocation_totals_added_to_global": False,
            "global_journal": {"summary": {"requests": 24, "known_usd": "0",
                "unresolved_usd_upper": "0", "billing_known": True,
                "pending_attempt_ids": []}}},
        "p_utility": {"measurement_status": "INCOMPLETE", "expected_explanations": 48}}
    result = render_results(_score(), assessment_import=batch)
    summary = result["assessment_batch"]
    assert summary["raw_scenarios"] == 24
    assert summary["finding_rows"] == 48
    assert summary["invocation_costs_added_to_global"] is False
    assert summary["total_usd"] is None
    assert summary["status"] == "INCOMPLETE"
    assert "private-unmatched-attempt" not in result["markdown"]


def test_mock_accounting_is_reported_as_cost_only_and_never_as_measurement():
    source = _score(status="INCOMPLETE")
    source["arms"]["P"]["failures"] = []
    accounting = {"P": {
        "requests": 2, "known_usd_decimal": "0.25", "unresolved_usd_upper_decimal": "0.10",
        "billing_fully_known": False, "total_usd_decimal": None, "usage_complete": False,
        "pending_attempt_ids": ["opaque"], "live_evidence_eligible": False,
    }}
    result = render_results(source, producer_accounting=accounting)
    assert result["arms"]["P"]["status"] == "NOT MEASURED"
    assert result["arms"]["P"]["cost"]["known_usd"] == "0.25"
    assert result["arms"]["P"]["cost"]["total_usd"] is None


def test_inconsistent_billing_total_is_rejected():
    source = _score()
    accounting = {"P": {
        "requests": 1, "known_usd_decimal": "0.25", "unresolved_usd_upper_decimal": "0",
        "billing_fully_known": True, "total_usd_decimal": None, "usage_complete": True,
        "pending_attempt_ids": [], "live_evidence_eligible": False,
    }}
    with pytest.raises(ValueError, match="billing completeness"):
        render_results(source, producer_accounting=accounting)


def test_incomplete_eligibility_stays_not_measured_even_without_failures():
    source = _score(status="INCOMPLETE")
    for arm in ARMS:
        source["arms"][arm]["failures"] = []
    result = render_results(source)
    assert all(result["arms"][arm]["status"] == "NOT MEASURED" for arm in ARMS)


def test_arm_inventory_is_closed():
    source = _score()
    source["arms"].pop("T")
    with pytest.raises(ValueError, match="all seven"):
        render_results(source)
