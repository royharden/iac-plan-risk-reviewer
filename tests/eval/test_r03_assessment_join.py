"""Join behavior after separately tested authority/capture gates.

Public stubs deliberately isolate the join; they do not authenticate receipts,
execute models, annotate prose, or establish semantic assessment completeness.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace as NS

import pytest
from eval.runner import assessment_import as intake

H = "a" * 64


def public_join(monkeypatch, *, wrong_case=False, wrong_finding=False, duplicate=False):
    case = NS(case_id="public-case", resource_id="public-resource", rule_id="R1", input_sha256=H)
    approval = NS(
        reference_sha256=H,
        case_id=case.case_id,
        case_sha256=H,
        artifact_sha256=H,
        global_pin_sha256=H,
        rubric_sha256=H,
        prompt_sha256=H,
    )
    authorized = NS(
        expected_case=case,
        artifact_sha256=H,
        rubric_sha256=H,
        prompt_sha256=H,
        approval_reference=approval,
        approval_reference_sha256=H,
    )
    artifact = NS(
        artifact_id="public-artifact",
        case_id="other-case" if wrong_case else case.case_id,
        finding_id="other-finding" if wrong_finding else "public-finding",
        raw_input_sha256=H,
        decision=NS(rule_id="R1"),
        build_sha256=H,
        prompt_sha256=H,
        projection_sha256=H,
        response_sha256=H,
        prose_sha256=H,
        attempt_id="public-attempt",
        origin="mock",
    )
    outcome = NS(
        finding_id="public-finding",
        artifact_id=artifact.artifact_id,
        capture_state="exact_private_response",
    )
    verified = NS(
        artifacts=(artifact,),
        p_outcomes=(outcome, outcome) if duplicate else (outcome,),
        status="verified",
        assessment_inputs_complete=True,
        export_sha256=H,
        index_sha256=H,
        reasons=(),
    )
    rubric = NS(rubric_text="public plumbing only", rubric_text_sha256=H)
    submission = NS(
        artifact_id=artifact.artifact_id,
        rubric=rubric,
        inventory=None,
        first=None,
        second=None,
        catalogue=None,
        mapping=None,
        expected_mapping_sha256=H,
        limitation_bindings=(),
        adjudication=None,
        decision_row=None,
        generated_words=None,
        baseline_words=None,
        word_count_receipt_sha256=None,
    )
    authority = NS(
        cases=(authorized,), producer_pins=(), global_pin=NS(build_sha256=H), global_pin_sha256=H
    )
    request = NS(
        authority=authority,
        authority_sha256=H,
        journal_links=(),
        expected_export_sha256=H,
        expected_index_sha256=H,
        scenario_case_id=None,
        submissions=(submission,),
        batch_attempts=None,
        include_utility_summary=False,
    )
    producer = NS(
        attempts=(),
        authoritative_accounting=NS(model_dump=lambda **_: {}),
        snapshots=(),
        per_arm_costs={},
        unconverted_attempt_ids=(),
    )
    bundle = NS(
        observations_json=json.dumps(
            [
                {
                    "case_id": case.case_id,
                    "resource_id": case.resource_id,
                    "rule_id": case.rule_id,
                    "finding_id": "public-finding",
                }
            ]
        )
    )
    calls = []

    def bridge(*args, **kwargs):
        calls.append(args[0].artifact_id)
        return NS(
            bookkeeping_complete=False,
            observation=None,
            missing_or_incomplete=("public-stub",),
            model_dump=lambda **_: {"public_stub": True},
        )

    monkeypatch.setattr(intake, "_validate_authority", lambda *args: None)
    monkeypatch.setattr(intake, "bridge_bundle", lambda *args: producer)
    monkeypatch.setattr(intake, "links_for_bundle", lambda *args: ())
    monkeypatch.setattr(intake, "verify_capture_index", lambda *args, **kwargs: verified)
    for name in ("metadata_digest", "artifact_digest", "rubric_digest", "text_digest"):
        monkeypatch.setattr(intake, name, lambda *args: H)
    monkeypatch.setattr("eval.model.assessment_bridge.bridge_assessment", bridge)
    result = intake.import_assessments(
        request, bundle=bundle, capture_directory=Path("public-unused")
    )
    return result, calls


def test_verified_triple_joins_to_exact_capture(monkeypatch):
    """what_bug_this_catches: joining case_id twice creates a four-part key and discards every valid artifact."""
    result, calls = public_join(monkeypatch)
    assert calls == ["public-artifact"]
    assert result["receipts_observed"] == 1
    assert not any(
        row["reason"] == "missing_or_ambiguous_capture_artifact"
        for row in result["cases_missing_or_incomplete"]
    )
    assert result["observations_eligible_for_rubric_scoring"] == 0
    assert result["semantic_assessment_complete"] is False


@pytest.mark.parametrize("change", [{"wrong_case": True}, {"wrong_finding": True}])
def test_case_and_finding_mismatch_never_reach_assessment_bridge(monkeypatch, change):
    """what_bug_this_catches: repairing valid joins accidentally accepts a different case or finding."""
    result, calls = public_join(monkeypatch, **change)
    assert calls == [] and result["receipts_observed"] == 0
    assert any(
        row["reason"] == "missing_or_ambiguous_capture_artifact"
        for row in result["cases_missing_or_incomplete"]
    )


def test_duplicate_finding_outcomes_are_refused(monkeypatch):
    """what_bug_this_catches: duplicate outcomes overwrite capture identity during dictionary construction."""
    with pytest.raises(ValueError, match="duplicate P"):
        public_join(monkeypatch, duplicate=True)
