"""Regression source for pinned private D5/D7 assessment intake; never hidden gold."""
from __future__ import annotations

import inspect

from eval.runner import assessment_import


def test_external_authority_precedes_bridge_invocation():
    source = inspect.getsource(assessment_import.import_assessments)
    assert source.index("_validate_authority(") < source.index("bridge_bundle(")
    assert source.index("artifact_digest(artifact)") < source.index("bridge_assessment(")


def test_case_approval_is_bound_to_raw_case_artifact_and_global_manifest():
    source = inspect.getsource(assessment_import.import_assessments)
    for required in (
        "artifact.raw_input_sha256 != authorized.expected_case.input_sha256",
        "metadata_digest(authorized.expected_case)",
        "request.authority.global_pin_sha256",
        "authorized.rubric_sha256",
        "authorized.prompt_sha256",
        "expected_case_approval_ref_sha256=authorized.approval_reference_sha256",
        "case_ref = authorized.approval_reference",
        "case_ref.case_sha256 != metadata_digest(authorized.expected_case)",
        "case_ref.artifact_sha256 != artifact_digest(artifact)",
        "case_ref.global_pin_sha256 != request.authority.global_pin_sha256",
    ):
        assert required in source


def test_outer_capture_and_assessment_bookkeeping_gate_observation():
    source = inspect.getsource(assessment_import.import_assessments)
    assert 'verified.status == "verified"' in source
    assert "verified.assessment_inputs_complete" in source
    assert 'outcome.capture_state == "exact_private_response"' in source
    assert "receipt.bookkeeping_complete" in source
    assert "receipt.observation is not None" in source


def test_capture_case_identity_is_unique_before_join(monkeypatch):
    import pytest
    from test_r03_assessment_join import public_join
    with pytest.raises(ValueError, match="duplicate P"):
        public_join(monkeypatch, duplicate=True)


def test_all_attempt_accounting_and_ineligibility_survive_result():
    source = inspect.getsource(assessment_import.import_assessments)
    assert "producer.authoritative_accounting.model_dump" in source
    assert '"per_arm_costs": producer.per_arm_costs' in source
    assert '"unconverted_attempt_ids": list(producer.unconverted_attempt_ids)' in source
    assert '"live_eligible": False' in source
    assert '"identity_authenticated": False' in source
    assert '"semantic_assessment_complete": False' in source


def test_assessment_result_keeps_full_denominator_failures():
    source = inspect.getsource(assessment_import.import_assessments)
    assert '"cases_expected": len(cases)' in source
    assert '"cases_missing_or_incomplete": failures' in source
    assert '"independent_denominator_below_24"' in source
