"""Scoring-handoff regression SOURCE (authored under Dirty Mode, NOT run).

Artificial public outcome JSON only; no oracle, gold, heldout input or scanner output.
"""
import ast
import hashlib
import json
from pathlib import Path

from types import SimpleNamespace

import pytest

from eval.runner import scoring_handoff as sh
from eval.runner.scoring import ARMS
from test_benchmark_access import committed

PIN = "a" * 64


def outcome(*, statuses=None, rows=(), snapshot=None, commit=PIN, oracle_opened=False):
    if statuses is None:
        statuses = [{"case_id": "case_one", "arm": arm, "status": "not_run", "reason_code": "fixture"}
                    for arm in ARMS]
    value = {"schema_version": "m4-frozen-run-outcome-v1", "run_id": "fixture_run", "split": "heldout",
             "frozen_selection_sha256": PIN, "run_manifest_sha256": PIN, "exposure_commit_sha256": commit,
             "access_authorization_sha256": PIN, "case_records_sha256": PIN, "build_sha256": PIN,
             "prompt_sha256": PIN, "rubric_sha256": PIN, "arm_inventory_sha256": PIN,
             "statuses": statuses, "journal_snapshot": snapshot or {"summary": {"requests": 0}, "journal_sha256": PIN,
                                                                 "reservation_overrun": False, "attempts": []},
             "rows": list(rows), "live_eligible": False, "product_acceptance": False,
             "oracle_opened": oracle_opened, "missing": ["external_execution_eligibility_and_scoring_required"]}
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return raw, hashlib.sha256(raw.encode()).hexdigest()


def receipts_for(measurement_pin):
    """Only .arm and .measurements_sha256 are read by the scoring check."""
    return tuple(SimpleNamespace(arm=arm, measurements_sha256=measurement_pin) for arm in ARMS)


def prepare(raw, pin):
    return sh.prepare_handoff(raw, expected_outcome_sha256=pin, edition_id="fixture_edition",
                              input_commit=committed(PIN))


def test_outcome_pin_mismatch_refuses():
    """what_bug_this_catches: a modified outcome is scored under the frozen run's pin."""
    raw, _ = outcome()
    with pytest.raises(ValueError, match="exact_frozen_outcome"):
        prepare(raw, "b" * 64)


def test_outcome_must_bind_the_committed_input_exposure():
    """what_bug_this_catches: results from a different (or uncommitted) exposure reach scoring."""
    raw, pin = outcome(commit="c" * 64)
    with pytest.raises(ValueError, match="commit_mismatch"):
        prepare(raw, pin)


def test_opened_oracle_outcome_is_refused():
    """what_bug_this_catches: an outcome that already saw the oracle is laundered into scoring."""
    raw, pin = outcome(oracle_opened=True)
    with pytest.raises(ValueError, match="profile_or_commit_mismatch"):
        prepare(raw, pin)


def test_dropped_arm_or_case_refuses_instead_of_shrinking_denominator():
    """what_bug_this_catches: failed arms are silently omitted so only favorable arms are scored."""
    statuses = [{"case_id": "case_one", "arm": arm, "status": "ok", "reason_code": "fixture"} for arm in ARMS[:-1]]
    raw, pin = outcome(statuses=statuses)
    with pytest.raises(ValueError, match="full_required_case_arm_inventory_missing"):
        prepare(raw, pin)


def test_not_run_and_mock_arms_stay_incomplete_and_v2_eligibility_missing():
    """what_bug_this_catches: unmeasured arms are reported as complete because rows exist."""
    raw, pin = outcome()
    handoff, measurements = prepare(raw, pin)
    assert set(handoff.incomplete_arms) == set(ARMS) and measurements == b""
    assert "external_v2_execution_eligibility_required" in handoff.missing
    assert handoff.oracle_opened is False and handoff.scoring_permission_granted is False
    assert handoff.measurements_sha256 == hashlib.sha256(b"").hexdigest()


def test_incomplete_journal_snapshot_marks_every_arm_incomplete():
    """what_bug_this_catches: lost attempts/costs are hidden and some arms claimed complete."""
    statuses = [{"case_id": "case_one", "arm": arm, "status": "ok", "reason_code": "fixture"} for arm in ARMS]
    raw, pin = outcome(statuses=statuses, snapshot={"summary": {"requests": 3}, "snapshot_unavailable": True,
                                                    "all_attempts_retained": False})
    handoff, _ = prepare(raw, pin)
    assert handoff.all_attempts_retained is False and set(handoff.incomplete_arms) == set(ARMS)
    assert "journal_snapshot_incomplete" in handoff.missing


def test_scoring_check_refuses_measurements_differing_from_handoff():
    """what_bug_this_catches: a different results file is scored with receipts for another one."""
    raw, pin = outcome()
    handoff, measurements = prepare(raw, pin)
    actual = hashlib.sha256(measurements).hexdigest()
    sh.check_handoff_for_scoring(handoff, edition_id="fixture_edition", build_sha256=PIN,
                                 receipts=receipts_for(actual), measurement_sha256=actual, measured=[])  # control
    with pytest.raises(ValueError, match="scoring_handoff_pins_differ"):
        sh.check_handoff_for_scoring(handoff, edition_id="fixture_edition", build_sha256=PIN,
                                     receipts=receipts_for(actual), measurement_sha256="b" * 64, measured=[])


def test_write_handoff_needs_fresh_directory_and_matching_receipts(tmp_path):
    """what_bug_this_catches: a handoff overwrites an earlier one or carries mismatched receipts."""
    raw, pin = outcome()
    handoff, measurements = prepare(raw, pin)
    existing = tmp_path / "existing"
    existing.mkdir()
    with pytest.raises(ValueError, match="fresh_handoff_directory"):
        sh.write_handoff(existing, handoff, measurements, ())
    with pytest.raises(ValueError, match="receipt_pin_mismatch"):
        sh.write_handoff(tmp_path / "fresh", handoff, measurements, ())
    assert not (tmp_path / "fresh").exists()


def test_eval_cli_checks_handoff_before_decoding_oracle():
    """what_bug_this_catches: the oracle is decoded before heldout handoff pins are verified."""
    source = Path(__file__).resolve().parents[2] / "scripts" / "eval.py"
    main = next(node for node in ast.parse(source.read_bytes()).body
                if isinstance(node, ast.FunctionDef) and node.name == "main")
    calls = [node for node in ast.walk(main) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)]
    check = next(node.lineno for node in calls if node.func.id == "check_handoff_for_scoring")
    oracle = next(node.lineno for node in calls if node.func.id == "decode_rows"
                  and ast.unparse(node.args[0]) == "oracle_bytes")
    assert check < oracle


def test_interrupted_or_overrun_journal_keeps_every_arm_incomplete():
    """what_bug_this_catches: unresolved attempts/liability are hidden behind per-arm ok statuses."""
    statuses = [{"case_id": "case_one", "arm": arm, "status": "ok", "reason_code": "fixture"} for arm in ARMS]
    for snapshot in ({"summary": {}, "journal_sha256": PIN, "reservation_overrun": True, "attempts": []},
                     {"summary": {}, "journal_sha256": PIN, "reservation_overrun": False,
                      "attempts": [{"attempt_id": "a1", "status": "interrupted", "requires_reconciliation": True}]}):
        raw, pin = outcome(statuses=statuses, snapshot=snapshot)
        handoff, _ = prepare(raw, pin)
        assert set(handoff.incomplete_arms) == set(ARMS)


def test_forged_incomplete_arm_list_is_refused_at_scoring():
    """what_bug_this_catches: an edited handoff clears incomplete arms to unlock a favorable score."""
    raw, pin = outcome()
    handoff, measurements = prepare(raw, pin)
    actual = hashlib.sha256(measurements).hexdigest()
    sh.check_handoff_for_scoring(handoff, edition_id="fixture_edition", build_sha256=PIN,
                                 receipts=receipts_for(actual), measurement_sha256=actual, measured=[])  # control
    forged = handoff.model_copy(update={"incomplete_arms": ()})
    with pytest.raises(ValueError, match="scoring_handoff_pins_differ"):
        sh.check_handoff_for_scoring(forged, edition_id="fixture_edition", build_sha256=PIN,
                                     receipts=receipts_for(actual), measurement_sha256=actual, measured=[])


def completion(commit):
    """Fully valid artificial v2 completion reference (no real release exists)."""
    from datetime import datetime, timezone
    from eval.runner.edition_release import ArmCompletion, CompletionReference
    arms = tuple(ArmCompletion(arm=arm, artifact_id="artifact_" + arm.replace("-", "_"), artifact_sha256=PIN,
                               score_status="FAIL", score_result_sha256=PIN, expected_rows=1) for arm in ARMS)
    return CompletionReference(run_manifest_sha256=PIN, authority_sha256=PIN, seal_sha256=PIN,
        input_exposure_authorization_sha256=PIN, input_exposure_commit_sha256=commit,
        input_exposure_receipt_file_sha256=PIN, post_measurement_exposure_sha256=PIN,
        eligibility_sha256=PIN, rubric_sha256=PIN, row_inventory_sha256=PIN,
        row_inventory=(("case_one", "resource_one", "R1"),), arms=arms,
        consumed_at=datetime(2026, 10, 24, tzinfo=timezone.utc))


def test_completion_reference_naming_another_input_commit_is_refused():
    """what_bug_this_catches: scoring and release silently describe different pre-access input exposures."""
    from eval.runner.custody import metadata_digest
    raw, pin = outcome()
    handoff, _ = prepare(raw, pin)
    same, other = completion(PIN), completion("d" * 64)
    assert sh.check_completion_reference(handoff, same,
                                         expected_completion_sha256=metadata_digest(same))["cross_checked"] is True
    with pytest.raises(ValueError, match="completion_reference_input_exposure_commit_mismatch"):
        sh.check_completion_reference(handoff, other, expected_completion_sha256=metadata_digest(other))


def test_completion_reference_pin_must_match():
    """what_bug_this_catches: an unpinned or substituted completion record passes the cross-check."""
    raw, pin = outcome()
    handoff, _ = prepare(raw, pin)
    with pytest.raises(ValueError, match="completion_reference_input_exposure_commit_mismatch"):
        sh.check_completion_reference(handoff, completion(PIN), expected_completion_sha256="b" * 64)
