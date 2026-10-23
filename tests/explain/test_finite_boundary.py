"""Finite selector adversarial development cases; source only, no model calls."""
import pytest

from iac_review.explain import FakeSelector, build_capsule, validate_selection
from iac_review.ingest import load_plan
from iac_review.report import build_report
from iac_review.rules import evaluate


@pytest.fixture
def transition_capsule(core_change, core_plan_file):
    entry = core_change(
        address='aws_db_instance.synthetic["ADDRESS_CANARY"]',
        before={"publicly_accessible": False, "storage_encrypted": True},
        after={"publicly_accessible": True, "storage_encrypted": True},
    )
    plan = load_plan(core_plan_file([entry], complete=False))
    shared = build_report(plan, evaluate(plan)).shareable
    finding = next(row for row in shared["evaluations"] if row["rule_id"] == "R2")
    return build_capsule(shared, finding["finding_id"])


def test_finite_selection_preserves_outcome_and_contains_no_private_locations(transition_capsule):
    capsule = transition_capsule
    before = capsule.model_dump_json()
    result = validate_selection(capsule, FakeSelector().select(capsule))
    assert result.accepted is True
    assert set(capsule.required_fact_ids) <= set(result.selected_fact_ids)
    assert result.limitation_ids == capsule.required_limitation_ids
    assert capsule.model_dump_json() == before
    assert "ADDRESS_CANARY" not in before and "pointer" not in before


@pytest.mark.parametrize("fault", ["reverse", "foreign", "missing_fact", "missing_limit", "forbidden_result", "oversize"])
def test_invalid_selection_uses_full_deterministic_fallback(transition_capsule, fault):
    capsule = transition_capsule
    response = FakeSelector().select(capsule).model_dump(mode="json")
    if fault == "reverse":
        before = next(fact.fact_id for fact in capsule.facts if fact.field == "publicly_accessible" and fact.side == "before")
        after = next(fact.fact_id for fact in capsule.facts if fact.field == "publicly_accessible" and fact.side == "after")
        response["clauses"] = [clause for clause in response["clauses"]
                               if not set(clause["fact_ids"]) & {before, after}]
        response["clauses"].append({"template_id": "boolean_transition", "fact_ids": [after, before]})
    elif fault == "foreign":
        response["clauses"][1]["fact_ids"] = ["foreign-id"]
    elif fault == "missing_fact":
        omitted = capsule.required_fact_ids[0]
        response["clauses"] = [clause for clause in response["clauses"] if omitted not in clause["fact_ids"]]
    elif fault == "missing_limit":
        response["limitation_ids"] = []
    elif fault == "forbidden_result":
        response["outcome"] = "clear"
    else:
        response = "x" * 16_385
    result = validate_selection(capsule, response)
    assert result.accepted is False and result.source == "deterministic_fallback"
    assert result.text == capsule.baseline
    assert result.selected_fact_ids == capsule.required_fact_ids
