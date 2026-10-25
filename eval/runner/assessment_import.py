"""Pinned private assessment intake; structure is not identity, truth, or live admission."""
from __future__ import annotations

from pathlib import Path
from pydantic import Field

from eval.model.explanation_artifacts import AdjudicationSheet, AssessorSheet
from eval.model.capture_index import VerifiedCaptureIndex, verify_capture_index
from eval.model.explanation_artifacts import ClaimInventory, ExplanationArtifact, Rubric
from eval.model.assessment_bridge import CaseApprovalReference, LimitationBinding
from eval.runner.fact_mapping import FactMapping
from eval.model.provenance import ExportBundle
from eval.model.review_catalogue import ReviewCatalogue
from eval.runner.custody import Digest, Identity, metadata_digest
from eval.runner.model_bridge import JournalLink, bridge_bundle, links_for_bundle
from eval.runner.utility import Attempt
from eval.runner.scoring import ArmRow, Record
from eval.runner.utility import ExplanationCase, MeasurementPin, PObservation, p_utility


class CaseAssessmentAuthority(Record):
    """Per-case approval material; the enclosing authority digest is pinned elsewhere."""
    expected_case: ExplanationCase
    artifact_sha256: Digest
    rubric_sha256: Digest
    prompt_sha256: Digest
    approval_reference_sha256: Digest
    approval_reference: CaseApprovalReference


class AssessmentAuthority(Record):
    edition_id: Identity
    global_pin: MeasurementPin
    global_pin_sha256: Digest
    # Includes pins for all producer attempts; each immutable pin keeps its own scope.
    producer_pins: tuple[MeasurementPin, ...] = Field(min_length=1, max_length=3)
    generator_authors: tuple[Identity, ...] = Field(min_length=1, max_length=256)
    appointed_assessors: tuple[Identity, Identity]
    appointed_adjudicator: Identity
    cases: tuple[CaseAssessmentAuthority, ...] = Field(min_length=1, max_length=4096)


class AssessmentSubmission(Record):
    artifact_id: Identity
    inventory: ClaimInventory
    rubric: Rubric
    first: AssessorSheet
    second: AssessorSheet
    adjudication: AdjudicationSheet | None = None
    catalogue: ReviewCatalogue
    mapping: FactMapping
    expected_mapping_sha256: Digest
    limitation_bindings: tuple[LimitationBinding, ...] = Field(default=(), max_length=32)
    decision_row: ArmRow | None = None
    generated_words: int | None = Field(default=None, ge=0)
    baseline_words: int | None = Field(default=None, ge=0)
    word_count_receipt_sha256: Digest | None = None


class AssessmentImportRequest(Record):
    authority: AssessmentAuthority
    authority_sha256: Digest
    expected_export_sha256: Digest
    expected_index_sha256: Digest | None = None
    submissions: tuple[AssessmentSubmission, ...] = Field(max_length=4096)
    journal_links: tuple[JournalLink, ...] = Field(default=(), max_length=10000)
    # Batch intake narrows capture work to one coordinator invocation while
       # retaining the full externally pinned authority inventory.
    scenario_case_id: Identity | None = None
    include_utility_summary: bool = True
    # Batch P assessment uses actual converted attempts from the shared pinned
    # journal boundary; omitted means the one-export legacy behavior.
    batch_attempts: tuple[Attempt, ...] | None = Field(default=None, max_length=10000)


def _validate_authority(authority: AssessmentAuthority, expected_sha256: str) -> None:
    if metadata_digest(authority) != expected_sha256:
        raise ValueError("assessment case authority digest mismatch")
    if metadata_digest(authority.global_pin) != authority.global_pin_sha256:
        raise ValueError("global assessment pin mismatch")
    if authority.global_pin.edition_id != authority.edition_id:
        raise ValueError("assessment edition mismatch")
    actors = (*authority.appointed_assessors, authority.appointed_adjudicator)
    if (len(set(actors)) != 3 or set(actors) & set(authority.generator_authors)
            or any(not value.strip() for value in (*actors, *authority.generator_authors))):
        raise ValueError("external generator/assessor appointments must be distinct")
    keys = [(row.expected_case.case_id, row.expected_case.resource_id,
             row.expected_case.rule_id) for row in authority.cases]
    if len(set(keys)) != len(keys):
        raise ValueError("duplicate authorized finding identity")
    raw_by_scenario = {}
    for row in authority.cases:
        case = row.expected_case
        prior = raw_by_scenario.setdefault(case.case_id, case.input_sha256)
        if prior != case.input_sha256:
            raise ValueError("scenario identity maps to multiple raw plans")
        approval = row.approval_reference
        if (approval.reference_sha256 != row.approval_reference_sha256
                or approval.case_id != case.case_id
                or approval.case_sha256 != metadata_digest(case)
                or approval.artifact_sha256 != row.artifact_sha256
                or approval.global_pin_sha256 != authority.global_pin_sha256
                or approval.rubric_sha256 != row.rubric_sha256
                or approval.prompt_sha256 != row.prompt_sha256):
            raise ValueError("externally pinned per-case approval reference mismatch")
    pin_ids = [attempt_id for pin in authority.producer_pins for attempt_id in pin.attempt_ids]
    if len(pin_ids) != len(set(pin_ids)):
        raise ValueError("producer attempt belongs to multiple pins")
    if not any(metadata_digest(pin) == authority.global_pin_sha256 for pin in authority.producer_pins):
        raise ValueError("global pin absent from producer pin inventory")
    if not set(authority.global_pin.attempt_ids) <= set(pin_ids):
        raise ValueError("global assessment attempts absent from producer pin inventory")


def import_assessments(
    request: AssessmentImportRequest, *, bundle: ExportBundle,
    capture_directory: Path | None,
) -> dict:
    """Verify external case authority before calling the canonical D7 bridge.

    The D5 index and accounting wires remain authoritative for capture coverage and
    all-attempt liabilities. Returned observations are private rubric inputs only.
    """
    _validate_authority(request.authority, request.authority_sha256)
    producer = bridge_bundle(bundle, request.authority.producer_pins,
                             links_for_bundle(bundle, request.journal_links))
    verified: VerifiedCaptureIndex = verify_capture_index(
        capture_directory, bundle, expected_export_sha256=request.expected_export_sha256,
        expected_index_sha256=request.expected_index_sha256,
    )
    selected_authority = tuple(row for row in request.authority.cases
        if request.scenario_case_id is None or row.expected_case.case_id == request.scenario_case_id)
    if not selected_authority:
        raise ValueError("scenario has no externally authorized findings")
    artifact_by_id = {row.artifact_id: row for row in verified.artifacts}
    if len(artifact_by_id) != len(verified.artifacts):
        raise ValueError("duplicate captured artifact identity")
    authority_by_key = {(row.expected_case.case_id, row.expected_case.resource_id,
                         row.expected_case.rule_id): row for row in selected_authority}
    if len({row.finding_id for row in verified.p_outcomes}) != len(verified.p_outcomes):
        raise ValueError("duplicate P outcome in verified capture index")
    outcome_by_finding = {row.finding_id: row for row in verified.p_outcomes}
    from eval.runner.model_bridge import _json as parse_export_json
    exported_observations = parse_export_json(bundle.observations_json)
    if type(exported_observations) is not list or len(exported_observations) > 10000:
        raise ValueError("bounded D5 finding observations required")
    finding_key = {}
    for row in exported_observations:
        if type(row) is not dict or not row.get("finding_id"):
            continue
        key = (row.get("case_id"), row.get("resource_id"), row.get("rule_id"))
        if row["finding_id"] in finding_key:
            raise ValueError("duplicate D5 finding identity")
        finding_key[row["finding_id"]] = key
    submissions = {row.artifact_id: row for row in request.submissions}
    if len(submissions) != len(request.submissions):
        raise ValueError("duplicate assessment submission")
    if set(submissions) - set(artifact_by_id):
        raise ValueError("assessment references artifact outside verified capture index")

    from eval.model.assessment_bridge import bridge_assessment

    receipts = []
    observations: list[PObservation] = []
    cases = []
    failures = []
    consumed = set()
    for key, authorized in authority_by_key.items():
        case_id = authorized.expected_case.case_id
        cases.append(authorized.expected_case)
        candidate_artifacts = [row for row in artifact_by_id.values()
            if row.case_id == key[0] and finding_key.get(row.finding_id) == key]
        if len(candidate_artifacts) != 1:
            failures.append({"case_id": case_id, "reason": "missing_or_ambiguous_capture_artifact"})
            continue
        artifact = candidate_artifacts[0]
        submission = submissions.get(artifact.artifact_id)
        outcome = outcome_by_finding.get(artifact.finding_id)
        if submission is None or outcome is None or outcome.artifact_id != artifact.artifact_id:
            failures.append({"case_id": case_id, "reason": "capture_or_assessment_missing"})
            continue
        if (artifact_digest(artifact) != authorized.artifact_sha256
                or artifact.raw_input_sha256 != authorized.expected_case.input_sha256
                or artifact.case_id != authorized.expected_case.case_id
                or artifact.decision.rule_id != authorized.expected_case.rule_id
                or artifact.build_sha256 != request.authority.global_pin.build_sha256
                or artifact.prompt_sha256 != authorized.prompt_sha256
                or submission.rubric.rubric_text_sha256 != text_digest(submission.rubric.rubric_text)
                or rubric_digest(submission.rubric) != authorized.rubric_sha256):
            failures.append({"case_id": case_id, "reason": "case_artifact_or_content_pin_mismatch"})
            continue
        case_ref = authorized.approval_reference
        if (case_ref.reference_sha256 != authorized.approval_reference_sha256
                or case_ref.case_id != authorized.expected_case.case_id
                or case_ref.case_sha256 != metadata_digest(authorized.expected_case)
                or case_ref.artifact_sha256 != artifact_digest(artifact)
                or case_ref.global_pin_sha256 != request.authority.global_pin_sha256
                or case_ref.rubric_sha256 != authorized.rubric_sha256
                or case_ref.prompt_sha256 != authorized.prompt_sha256):
            failures.append({"case_id": case_id, "reason": "external_case_approval_mismatch"})
            continue
        # Pin validation above is complete before invoking D7. The reference string
        # identifies an externally pinned approval record; it is not self-authenticating.
        receipt = bridge_assessment(
            artifact, submission.inventory, submission.rubric, submission.first,
            submission.second, catalogue=submission.catalogue, mapping=submission.mapping,
            expected_mapping_sha256=submission.expected_mapping_sha256,
            expected_case=authorized.expected_case,
            limitation_bindings=submission.limitation_bindings,
            adjudication=submission.adjudication, decision_row=submission.decision_row,
            attempts=tuple(row for row in (request.batch_attempts if request.batch_attempts is not None
                                           else producer.attempts)
                           if row.arm == "P"),
            pin=request.authority.global_pin,
            expected_pin_sha256=request.authority.global_pin_sha256,
            generated_words=submission.generated_words, baseline_words=submission.baseline_words,
            word_count_receipt_sha256=submission.word_count_receipt_sha256,
            case_rubric_sha256=authorized.rubric_sha256,
            case_prompt_sha256=authorized.prompt_sha256, case_approval_ref=case_ref,
            expected_case_approval_ref_sha256=authorized.approval_reference_sha256,
        )
        receipts.append(receipt)
        consumed.add(artifact.artifact_id)
        if (verified.status == "verified" and verified.assessment_inputs_complete
                and outcome.capture_state == "exact_private_response"
                and receipt.bookkeeping_complete and receipt.observation is not None):
            observations.append(receipt.observation)
        else:
            reason = ";".join(receipt.missing_or_incomplete) or "outer_bookkeeping_incomplete"
            if verified.status != "verified" or not verified.assessment_inputs_complete:
                reason += ";capture_index_incomplete"
            if outcome.capture_state != "exact_private_response":
                reason += ";capture_payload_incomplete"
            failures.append({"case_id": case_id, "reason": reason})

    extra = set(artifact_by_id) - consumed
    for artifact_id in sorted(extra):
        artifact = artifact_by_id[artifact_id]
        failures.append({"case_id": artifact.case_id, "reason": "unconsumed_capture_artifact"})
    if request.include_utility_summary and len(cases) < 24:
        failures.append({"case_id": None, "reason": "independent_denominator_below_24"})
    p_attempts = tuple(row for row in (request.batch_attempts if request.batch_attempts is not None
                                       else producer.attempts)
                       if row.arm == "P")
    utility = p_utility(
        tuple(cases), tuple(observations), request.authority.global_pin, p_attempts,
        request.authority.global_pin_sha256, set(request.authority.generator_authors),
        request.authority.appointed_assessors, request.authority.appointed_adjudicator,
    ) if request.include_utility_summary else None
    attempt_summary = producer.authoritative_accounting.model_dump(mode="json")
    return {
        "schema_version": 1, "private": True, "authority_sha256": request.authority_sha256,
        "global_pin_sha256": request.authority.global_pin_sha256,
        "capture_export_sha256": verified.export_sha256,
        "capture_index_sha256": verified.index_sha256,
        "capture_status": verified.status,
        "capture_reasons": list(verified.reasons),
        "case_content_pins": [{
            "case_id": row.expected_case.case_id,
            "case_sha256": metadata_digest(row.expected_case),
            "artifact_sha256": row.artifact_sha256,
            "rubric_sha256": row.rubric_sha256,
            "prompt_sha256": row.prompt_sha256,
            "approval_reference_sha256": row.approval_reference_sha256,
        } for row in request.authority.cases],
        "artifact_bindings": [{
            "artifact_id": artifact.artifact_id, "case_id": artifact.case_id,
            "finding_id": artifact.finding_id, "artifact_sha256": artifact_digest(artifact),
            "raw_input_sha256": artifact.raw_input_sha256,
            "projection_sha256": artifact.projection_sha256,
            "prompt_sha256": artifact.prompt_sha256, "build_sha256": artifact.build_sha256,
            "response_sha256": artifact.response_sha256, "prose_sha256": artifact.prose_sha256,
            "attempt_id": artifact.attempt_id, "origin": artifact.origin,
        } for artifact in verified.artifacts],
        "cases_expected": len(cases), "receipts_observed": len(receipts),
        "observations_eligible_for_rubric_scoring": len(observations),
        "cases_missing_or_incomplete": failures,
        "assessment_receipts": [row.model_dump(mode="json") for row in receipts],
        "observations": [row.model_dump(mode="json") for row in observations],
        "p_utility": utility,
        "all_attempt_accounting": attempt_summary,
        "attempt_snapshots": [row.model_dump(mode="json") for row in producer.snapshots],
        "per_arm_costs": producer.per_arm_costs,
        "unconverted_attempt_ids": list(producer.unconverted_attempt_ids),
        "live_eligible": False, "identity_authenticated": False,
        "semantic_assessment_complete": False, "product_acceptance": False,
    }


def text_digest(value: str) -> str:
    from eval.model.explanation_artifacts import text_digest as digest_text
    return digest_text(value)


def rubric_digest(value: Rubric) -> str:
    from eval.model.explanation_artifacts import digest as digest_wire
    return digest_wire(value)


def artifact_digest(value: ExplanationArtifact) -> str:
    from eval.model.explanation_artifacts import digest as digest_wire
    return digest_wire(value)
