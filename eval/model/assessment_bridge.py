"""Outer-bookkeeping -> existing utility candidate, never live admission or gold."""
from __future__ import annotations

import json
from typing import Literal

from pydantic import Field

from eval.model.annotation import export_assessments
from eval.model.explanation_artifacts import (
    AdjudicationSheet, AssessorSheet, ClaimInventory, Digest, ExplanationArtifact,
    LimitId, Rubric, Wire, digest,
)
from eval.model.protocol import ClaimAssessment
from eval.model.review_catalogue import ReviewCatalogue, validate_catalogue
from eval.runner.custody import Identity, metadata_digest
from eval.runner.fact_mapping import FactMapping
from eval.runner.scoring import ArmRow, record_digest
from eval.runner.utility import (
    Attempt, ExplanationCase, MeasurementPin, PObservation, attempt_summary,
)


class LimitationBinding(Wire):
    expected_id: Identity
    catalogue_id: LimitId


class CaseApprovalReference(Wire):
    """Externally selected case-pin reference; strings are not authentication."""
    reference_sha256: Digest
    case_id: Identity
    case_sha256: Digest
    artifact_sha256: Digest
    global_pin_sha256: Digest
    rubric_sha256: Digest
    prompt_sha256: Digest


class AssessmentReceipt(Wire):
    private: Literal[True] = True
    artifact_sha256: Digest
    inventory_sha256: Digest
    rubric_sha256: Digest
    catalogue_sha256: Digest
    mapping_sha256: Digest
    expected_case: ExplanationCase
    expected_case_sha256: Digest
    fact_mapping: FactMapping
    claim_ids: tuple[str, ...] = Field(max_length=1024)
    generated_claim_inventory_sha256: Digest
    first: tuple[ClaimAssessment, ...] = Field(max_length=1024)
    second: tuple[ClaimAssessment, ...] = Field(max_length=1024)
    adjudicated: tuple[ClaimAssessment, ...] = Field(max_length=1024)
    first_sheet: AssessorSheet
    second_sheet: AssessorSheet
    adjudication_sheet: AdjudicationSheet | None = None
    critical_false_claim_ids: tuple[str, ...] = Field(max_length=1024)
    unresolved_claim_ids: tuple[str, ...] = Field(max_length=1024)
    expected_fact_ids: tuple[Identity, ...] = Field(max_length=512)
    unmapped_expected_fact_ids: tuple[Identity, ...] = Field(max_length=512)
    attempts: tuple[Attempt, ...] = Field(max_length=10000)
    generated_words: int | None = Field(default=None, ge=0)
    baseline_words: int | None = Field(default=None, ge=0)
    word_count_receipt_sha256: Digest | None = None
    observation: PObservation | None = None
    missing_or_incomplete: tuple[str, ...]
    bookkeeping_complete: bool
    workflow_bookkeeping_complete: bool
    content_pin_mode: Literal["global", "case", "incomplete"] = "global"
    measurement_pin: MeasurementPin | None = None
    case_approval_ref: CaseApprovalReference | None = None
    # A candidate is never an admission; even supplied "live" strings are untrusted.
    measurement_status: Literal["INCOMPLETE"] = "INCOMPLETE"
    live_eligible: Literal[False] = False
    complete: Literal[False] = False
    identity_authenticated: Literal[False] = False
    product_prose_enabled: Literal[False] = False


def bridge_assessment(artifact: ExplanationArtifact, inventory: ClaimInventory, rubric: Rubric,
                      first: AssessorSheet, second: AssessorSheet, *, catalogue: ReviewCatalogue,
                      mapping: FactMapping, expected_mapping_sha256: str,
                      expected_case: ExplanationCase,
                      limitation_bindings: tuple[LimitationBinding, ...] = (),
                      adjudication: AdjudicationSheet | None = None,
                      decision_row: ArmRow | None = None,
                      attempts: tuple[Attempt, ...] = (), pin: MeasurementPin | None = None,
                      expected_pin_sha256: str | None = None,
                      generated_words: int | None = None, baseline_words: int | None = None,
                      word_count_receipt_sha256: str | None = None,
                      case_rubric_sha256: str | None = None, case_prompt_sha256: str | None = None,
                      case_approval_ref: CaseApprovalReference | None = None,
                      expected_case_approval_ref_sha256: str | None = None) -> AssessmentReceipt:
    """Recompute actual workflow. Never trust a caller's nested metrics/complete flag.

    No oracle is read here: expected_case and mapping come from an already
    authorized independent evaluator. They do not enter catalogue/model inputs.
    """
    validate_catalogue(artifact, catalogue)
    if len(attempts) > 10000:
        raise ValueError("attempt inventory bound exceeded")
    workflow = export_assessments(artifact, inventory, rubric, first, second, adjudication)
    FactMapping.model_validate_json(mapping.model_dump_json())
    if (digest(mapping) != expected_mapping_sha256 or mapping.artifact_sha256 != digest(artifact)
            or mapping.catalogue_sha256 != digest(catalogue)
            or mapping.case_id != artifact.case_id or mapping.source_sha256 != artifact.raw_input_sha256
            or mapping.resource_id != expected_case.resource_id
            or expected_case.case_id != artifact.case_id or expected_case.rule_id != artifact.decision.rule_id
            or expected_case.input_sha256 != artifact.raw_input_sha256):
        raise ValueError("independent case/mapping/artifact pins differ")
    expected_ids = tuple(row.expected_fact_id for row in mapping.rows)
    if len(set(expected_ids)) != len(expected_ids) or set(expected_ids) != set(expected_case.allowed_fact_ids):
        raise ValueError("mapping must retain the entire independent fact denominator")
    mapped = {row.report_fact_id: row.expected_fact_id for row in mapping.rows
              if row.status == "mapped" and row.report_fact_id is not None}
    if len(mapped) != sum(row.status == "mapped" for row in mapping.rows):
        raise ValueError("ambiguous or missing run-fact correspondence")
    if not set(mapped) <= set(artifact.fact_ids):
        raise ValueError("foreign mapped fact ID")
    loss = tuple(row.expected_fact_id for row in mapping.rows if row.status != "mapped")
    limits = {row.catalogue_id: row.expected_id for row in limitation_bindings}
    if (len(limits) != len(limitation_bindings)
            or len({row.expected_id for row in limitation_bindings}) != len(limitation_bindings)
            or not set(limits) <= set(artifact.limitation_ids)
            or not set(limits.values()) <= set(expected_case.allowed_limitation_ids)):
        raise ValueError("duplicate or foreign explicit limitation correspondence")
    missing = []
    if not workflow["bookkeeping_complete"] or workflow["unresolved_claim_ids"]:
        missing.append("outer_workflow_incomplete")
    if loss:
        missing.append("expected_fact_correspondence_loss")
    if set(limits.values()) != set(expected_case.allowed_limitation_ids):
        missing.append("limitation_correspondence_loss")
    if ({mapped.get(key) for key in rubric.required_fact_ids} != set(expected_case.required_fact_ids)
            or {limits.get(key) for key in rubric.required_limitation_ids} != set(expected_case.required_limitation_ids)):
        missing.append("independent_required_denominator_mismatch")

    def converted(records):
        result = []
        for value in records:
            row = ClaimAssessment.model_validate_json(json.dumps(value))
            if not set(row.necessary_fact_ids) <= set(mapped) or not set(row.limitation_ids) <= set(limits):
                missing.append("annotation_correspondence_loss")
                # Preserve originals below; do not output a selectively pruned utility row.
                continue
            result.append(row.model_copy(update={
                "necessary_fact_ids": tuple(mapped[key] for key in row.necessary_fact_ids),
                "limitation_ids": tuple(limits[key] for key in row.limitation_ids),
            }))
        return tuple(result)

    first_rows = converted(workflow["first"])
    second_rows = converted(workflow["second"])
    adjudicated_rows = converted(tuple(workflow["adjudicated"].values()))
    if decision_row is None:
        missing.append("decision_reference_missing")
    elif (decision_row.arm != "D" or record_digest(decision_row) != artifact.decision.immutable_outcome_sha256
          or decision_row.outcome != artifact.decision.outcome or decision_row.rule_id != artifact.decision.rule_id
          or decision_row.case_id != expected_case.case_id or decision_row.resource_id != expected_case.resource_id
          or decision_row.source_sha256 != artifact.raw_input_sha256 or decision_row.build_sha256 != artifact.build_sha256):
        raise ValueError("immutable D decision reference mismatch")
    if generated_words is None or baseline_words is None or word_count_receipt_sha256 is None:
        missing.append("word_counts_or_receipt_missing")
    if artifact.origin not in ("live", "replay"):
        missing.append("mock_or_unverified_origin")
    if not all((artifact.attempt_record_sha256, artifact.price_sha256, artifact.usage_sha256)):
        missing.append("artifact_attempt_price_usage_pins_missing")
    selected_attempts = [row for row in attempts if row.attempt_id == artifact.attempt_id]
    if len({row.attempt_id for row in attempts}) != len(attempts):
        raise ValueError("duplicate attempt inventory")
    if len(selected_attempts) != 1:
        missing.append("assessment_attempt_missing")
    else:
        attempt = selected_attempts[0]
        if (attempt.arm != "P" or attempt.source_sha256 != artifact.raw_input_sha256
                or attempt.response_sha256 != artifact.response_sha256
                or attempt.origin != artifact.origin
                or attempt.generated_claim_inventory_sha256 != workflow["generated_claim_inventory_sha256"]):
            missing.append("assessment_attempt_provenance_mismatch")
        if attempt.status == "pending" or attempt.terminal_record_sha256 is None:
            missing.append("attempt_pending_or_terminal_missing")
    override = any(value is not None for value in (case_rubric_sha256, case_prompt_sha256,
                    case_approval_ref, expected_case_approval_ref_sha256))
    content_pin_mode = "incomplete" if override else "global"
    accepted_approval = None
    if override:
        if (pin is None or expected_pin_sha256 is None or case_rubric_sha256 is None
                or case_prompt_sha256 is None or case_approval_ref is None
                or expected_case_approval_ref_sha256 is None):
            missing.append("case_content_approval_missing")
        else:
            try:
                approval = CaseApprovalReference.model_validate_json(case_approval_ref.model_dump_json())
                exact = (
                    case_rubric_sha256 == digest(rubric) == approval.rubric_sha256
                    and case_prompt_sha256 == artifact.prompt_sha256 == approval.prompt_sha256
                    and approval.reference_sha256 == expected_case_approval_ref_sha256
                    and approval.case_id == artifact.case_id == expected_case.case_id
                    and approval.case_sha256 == metadata_digest(expected_case)
                    and approval.artifact_sha256 == digest(artifact)
                    and approval.global_pin_sha256 == metadata_digest(pin) == expected_pin_sha256
                )
            except (ValueError, AttributeError):
                exact = False
            if exact:
                content_pin_mode, accepted_approval = "case", approval
            else:
                missing.append("case_content_approval_mismatch")
    if pin is None or expected_pin_sha256 is None:
        missing.append("measurement_pin_missing")
    else:
        if metadata_digest(pin) != expected_pin_sha256 or pin.build_sha256 != artifact.build_sha256:
            raise ValueError("global measurement authority/build pin mismatch")
        if not override and (pin.prompt_sha256 != artifact.prompt_sha256 or pin.rubric_sha256 != digest(rubric)):
            raise ValueError("measurement authority/artifact/rubric pin mismatch")
        summary = attempt_summary(pin, attempts, expected_pin_sha256, "P", 0)
        if not summary["all_attempts_complete"]:
            missing.append("all_attempts_incomplete")
        if not summary["live_evidence_eligible"]:
            missing.append("attempt_origin_or_provenance_ineligible")
        if not summary["billing_fully_known"]:
            missing.append("billing_or_pending_liability_unknown")
    observation = None
    if not missing:
        observation = PObservation(
            case_id=expected_case.case_id, resource_id=expected_case.resource_id,
            rule_id=expected_case.rule_id, attempt_id=artifact.attempt_id,
            claim_ids=tuple(workflow["claim_ids"]), first=first_rows, second=second_rows,
            adjudicated=adjudicated_rows, critical_false_claim_ids=tuple(workflow["critical_false_claim_ids"]),
            withheld=artifact.explanation_withheld,
        )
    # Original per-run ClaimAssessment rows are retained even when correspondence
    # fails. Only the separately gated observation uses independent expected IDs.
    return AssessmentReceipt(
        artifact_sha256=digest(artifact), inventory_sha256=digest(inventory), rubric_sha256=digest(rubric),
        catalogue_sha256=digest(catalogue), mapping_sha256=digest(mapping),
        expected_case=expected_case, expected_case_sha256=metadata_digest(expected_case), fact_mapping=mapping,
        claim_ids=tuple(workflow["claim_ids"]), generated_claim_inventory_sha256=workflow["generated_claim_inventory_sha256"],
        first=tuple(ClaimAssessment.model_validate_json(json.dumps(row)) for row in workflow["first"]),
        second=tuple(ClaimAssessment.model_validate_json(json.dumps(row)) for row in workflow["second"]),
        adjudicated=tuple(ClaimAssessment.model_validate_json(json.dumps(row)) for row in workflow["adjudicated"].values()),
        first_sheet=first, second_sheet=second, adjudication_sheet=adjudication,
        critical_false_claim_ids=tuple(workflow["critical_false_claim_ids"]), unresolved_claim_ids=tuple(workflow["unresolved_claim_ids"]),
        expected_fact_ids=expected_ids, unmapped_expected_fact_ids=loss, attempts=attempts,
        generated_words=generated_words, baseline_words=baseline_words, word_count_receipt_sha256=word_count_receipt_sha256,
        observation=observation, missing_or_incomplete=tuple(sorted(set(missing))),
        bookkeeping_complete=not missing, workflow_bookkeeping_complete=workflow["bookkeeping_complete"],
        content_pin_mode=content_pin_mode, measurement_pin=pin, case_approval_ref=accepted_approval,
    )
