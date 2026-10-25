"""Independent PUBLIC scorer arithmetic; no hidden cases or paid measurements."""

from __future__ import annotations

import pytest
from eval.runner.scoring import (
    ArmRow,
    EligibilityManifest,
    EligibleMeasurement,
    OracleRow,
    record_digest,
    score,
)


def result(gold_outcomes, predictions, *, statuses=None, arm="D", mock=False):
    gold, measured, pins = [], [], []
    statuses = statuses or ["ok"] * len(predictions)
    for i, (expected, actual, status) in enumerate(zip(gold_outcomes, predictions, statuses)):
        identity = {
            "case_id": f"public-math-{i}",
            "resource_id": f"public-resource-{i}",
            "rule_id": "R1",
        }
        gold.append(
            OracleRow(
                **identity,
                family_id=f"family-{i}",
                configuration_lineage=f"config-{i}",
                mutation_lineage=f"mutation-{i}",
                split="dev",
                applicability="supported",
                outcome=expected,
                reason_code="public-expectation",
            )
        )
        meta = EligibleMeasurement(
            arm=arm,
            measurement_ref=f"public-executed-{i}",
            source_sha256="a" * 64,
            build_sha256="b" * 64,
            kind="mock" if mock else "executed",
            provenance_sha256="c" * 64,
            actual_execution_attested=True,
        )
        pins.append(meta)
        measured.append(
            ArmRow(
                **identity,
                arm=arm,
                status=status,
                applicability="supported",
                outcome=actual,
                reason_code="public-expectation",
                schema_version=2,
                measurement_kind=meta.kind,
                eligibility_ref=record_digest(meta),
                source_sha256=meta.source_sha256,
                build_sha256=meta.build_sha256,
                measurement_ref=meta.measurement_ref,
            )
        )
    manifest = EligibilityManifest(edition_id="public-arithmetic-only", rows=tuple(pins))
    return score(
        gold,
        measured,
        "dev",
        eligibility=manifest,
        expected_eligibility_sha256=record_digest(manifest),
    )


def test_zero_tp_with_fp_and_fn_has_zero_f1():
    """what_bug_this_catches: a total misclassification becomes undefined F1 rather than zero."""
    counts = result(["introduced_risk", "clear"], ["clear", "introduced_risk"])["arms"]["D"][
        "per_rule"
    ]["R1"]
    assert (counts["tp"], counts["fp"], counts["fn"]) == (0, 1, 1)
    assert counts["f1"] == 0.0


@pytest.mark.parametrize(
    ("gold", "prediction", "expected"),
    [("clear", "clear", None), ("clear", "introduced_risk", 0.0), ("introduced_risk", None, 0.0)],
)
def test_f1_is_na_only_for_a_zero_count_denominator(gold, prediction, expected):
    """what_bug_this_catches: zero positives emitted hides a miss, or all-negative data fabricates F1."""
    counts = result([gold], [prediction])["arms"]["D"]["per_rule"]["R1"]
    assert counts["f1"] == expected


@pytest.mark.parametrize("status", ["invalid", "timeout", "error", "not_run", "unmapped"])
def test_positive_abstention_stays_in_recall_denominator(status):
    """what_bug_this_catches: failed or absent attempts inflate recall by dropping positive cases."""
    row = result(["introduced_risk"], [None], statuses=[status])["arms"]["D"]
    counts = row["per_rule"]["R1"]
    assert counts["fn"] == 1 and counts["recall"] == 0.0
    assert counts["decidable_abstentions"] == 1 and counts["tn"] == 0
    assert row["measurement_status"] == (
        "INCOMPLETE" if status in {"not_run", "unmapped"} else "RECORDED"
    )


def test_unknown_gold_definite_prediction_is_certainty_error():
    """what_bug_this_catches: guessing on unknown gold is counted as an ordinary negative."""
    counts = result(["indeterminate"], ["clear"])["arms"]["D"]["per_rule"]["R1"]
    assert counts["certainty_errors"] == 1
    assert counts["tn"] == counts["supported_decidable"] == 0


def test_mock_never_passes_execution_gate_and_missing_arms_keep_unknown_cost():
    """what_bug_this_catches: fabricated mock eligibility or absent model arms become successful zero-cost rows."""
    scored = result(["introduced_risk"], ["introduced_risk"], mock=True)
    assert not scored["deterministic_exact_gate"]
    assert scored["arms"]["D"]["measurement_status"] == "INCOMPLETE"
    for arm in ("L", "P", "M"):
        row = scored["arms"][arm]
        assert row["measurement_status"] == "INCOMPLETE"
        assert row["known_usd"] is None and row["all_attempt_cost"] is None
        assert row["per_rule"]["R1"]["fn"] == 1
