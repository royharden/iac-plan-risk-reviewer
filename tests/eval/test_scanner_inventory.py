"""Capability regression SOURCE, not executed in Dirty Mode; no scanner or oracle."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from eval.scanners.artifacts import Mapping
from eval.scanners.capabilities import inventory


def contract() -> dict:
    path = Path(__file__).resolve().parents[2] / "policies" / "checkov-custom" / "mapping.json"
    return json.loads(path.read_text(encoding="utf-8"))


def test_all_arms_rules_and_ordered_replacements_are_visible() -> None:
    """what_bug_this_catches: inventory silently omits required arm or replacement ordering."""
    report = inventory(contract())
    assert report["arms"] == ["C", "C-custom", "T"]
    assert {row["rule_id"] for row in report["cells"]} == {"R1", "R2", "R3", "R4"}
    keys = [(r["arm"], r["rule_id"], r["resource_type"], r["actions"]) for r in report["cells"]]
    assert len(keys) == len(set(keys))
    assert ("delete", "create") in {row["actions"] for row in report["cells"]}
    assert ("create", "delete") in {row["actions"] for row in report["cells"]}


def test_default_inventory_does_not_invent_built_in_mappings_or_measurement() -> None:
    """what_bug_this_catches: candidate metadata presented as scanner correctness proof."""
    report = inventory(contract())
    assert report["measurement_status"] == "NOT_MEASURED" and report["product_acceptance"] is False
    for row in report["cells"]:
        assert row["measured_correctness"] is False and row["execution_eligible"] is False
        if row["arm"] in {"C", "T"}:
            assert row["check_ids"] == ()


def test_custom_delete_and_deposed_gaps_are_explicit() -> None:
    """what_bug_this_catches: absent Checkov delete callback becomes a benign negative."""
    report = inventory(contract())
    rows = [row for row in report["cells"] if row["arm"] == "C-custom"
            and row["rule_id"] == "R4" and row["actions"] == ("delete",)
            and row["resource_type"] in {"aws_db_instance", "aws_ebs_volume"}]
    assert len(rows) == 2 and all(row["declaration_status"] == "incomplete_callback" for row in rows)
    assert any("deposed" in limitation for limitation in report["limitations"])


def declaration(*, types: tuple[str, ...] = ("aws_db_instance",)) -> Mapping:
    # Artificial declaration for pure metadata checks, never a genuine pin.
    return Mapping(arm="C", scanner_name="checkov", version="artificial-metadata-only",
                   executable_sha256="a" * 64, policy_sha256="b" * 64, rule_id="R2",
                   check_ids=("CKV_ARTIFICIAL",), supported_actions=(("create",),),
                   supported_types=types, compatibility="verified",
                   compatibility_evidence_sha256="c" * 64)


def test_declared_verified_mapping_stays_metadata_not_execution_eligibility() -> None:
    """what_bug_this_catches: supplied compatibility flag treated as executed evidence."""
    report = inventory(contract(), (declaration(),))
    cell = next(row for row in report["cells"] if row["arm"] == "C" and row["rule_id"] == "R2"
                and row["actions"] == ("create",))
    assert cell["declaration_status"] == "declared_compatible"
    assert cell["execution_eligible"] is False and cell["measured_correctness"] is False
    assert cell["declared_version"] == "artificial-metadata-only"


def test_out_of_scope_types_cannot_be_widened_by_mapping_metadata() -> None:
    """what_bug_this_catches: mapping adds unsupported resource types to v1 denominator."""
    with pytest.raises(ValueError, match="widens"):
        inventory(contract(), (declaration(types=("aws_s3_bucket",)),))


def test_duplicate_arm_rule_declaration_is_rejected() -> None:
    """what_bug_this_catches: inventory cherry-picks one of conflicting mappings."""
    with pytest.raises(ValueError, match="duplicate"):
        inventory(contract(), (declaration(), declaration()))


def test_missing_rule_contract_is_not_silently_complete() -> None:
    """what_bug_this_catches: candidate contract loses a rule while inventory reports four."""
    value = contract()
    value["rules"].pop()
    with pytest.raises(ValueError, match="four"):
        inventory(value)


def test_unknown_and_sensitive_limits_never_become_clear_outcomes() -> None:
    """what_bug_this_catches: knowledge gaps exported as measured benign labels."""
    report = inventory(contract())
    assert any("necessary_unknown_or_sensitive_fact" in row["reason_codes"] for row in report["cells"])
    assert all("outcome" not in row and "introduced_prediction" not in row for row in report["cells"])


def test_unrecognized_ordered_actions_reject_the_contract() -> None:
    """what_bug_this_catches: sorting/deduping actions silently admits a new action shape."""
    value = contract()
    value["rules"][0]["candidate_actions"].append(["delete", "create", "delete"])
    with pytest.raises(ValueError, match="unsupported candidate action"):
        inventory(value)
