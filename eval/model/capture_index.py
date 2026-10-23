"""Whole private capture verification against separately pinned producer snapshots.

Integrity/coverage only: no identity authentication, semantic labels or live admission.
No directory or payload is created; prose is excluded from default result serialization.
"""
from __future__ import annotations

import base64
from pathlib import Path
import re
from time import monotonic
from typing import Literal

from pydantic import Field

from iac_review.ingest import MAX_SECONDS, decode_source, read_source_bytes
from eval.model.experiment import canonical, digest
from eval.model.explanation_artifacts import Digest, OpaqueId, LimitId, ExplanationArtifact, Wire
from eval.model.explanation_artifacts import digest as artifact_digest
from eval.model.provenance import ExportBundle
from eval.runner.model_bridge import bridge_bundle

Status = Literal["ok", "invalid", "timeout", "error", "cancelled", "not_run"]
CaptureState = Literal["exact_private_response", "response_unavailable", "response_prefix_only",
                       "response_binding_incomplete", "artifact_wire_rejected"]


class CaptureOutcome(Wire):
    case_id: OpaqueId
    finding_id: OpaqueId
    generator_actor_ids: tuple[OpaqueId, ...] = Field(min_length=1, max_length=16)
    identity_authenticated: Literal[False]
    attempt_id: OpaqueId | None
    status: Status
    artifact_id: OpaqueId | None
    artifact_sha256: Digest | None
    diagnostic_id: OpaqueId | None
    live_eligible: Literal[False]
    semantic_assessment_complete: Literal[False]
    capture_state: CaptureState


class _Index(Wire):
    schema_version: Literal[1] = Field(alias="schema")
    private: Literal[True]
    untrusted: Literal[True]
    origin: Literal["mock", "unverified"]
    live_eligible: Literal[False]
    semantic_assessment_complete: Literal[False]
    baseline_sha256: Digest
    outcomes: tuple[CaptureOutcome, ...] = Field(max_length=10000)
    files: dict[str, Digest] = Field(max_length=10000)
    artifact_count: int = Field(ge=0, le=10000)
    diagnostic_count: int = Field(ge=0, le=10000)


class LReceipt(Wire):
    finding_id: OpaqueId
    attempt_id: OpaqueId | None
    status: Status
    baseline_words: int | None = Field(ge=0)
    rendered_words: int | None = Field(ge=0)
    render_source: Literal["validated_selection", "deterministic_fallback"] | None
    required_limitation_ids: tuple[LimitId, ...]
    selected_limitation_ids: tuple[LimitId, ...]
    word_counts_available: bool


class VerifiedCaptureIndex(Wire):
    private: Literal[True] = True
    status: Literal["verified", "incomplete"]
    export_sha256: Digest
    index_sha256: Digest | None = None
    baseline_sha256: Digest
    reasons: tuple[str, ...] = ()
    p_outcomes: tuple[CaptureOutcome, ...] = ()
    l_receipts: tuple[LReceipt, ...] = ()
    all_attempt_ids: tuple[OpaqueId, ...]
    file_hashes: tuple[tuple[str, str], ...] = ()
    artifacts: tuple[ExplanationArtifact, ...] = Field(default=(), repr=False, exclude=True)
    assessment_inputs_complete: bool = False
    origin_authenticated: Literal[False] = False
    identity_authenticated: Literal[False] = False
    semantic_assessment_complete: Literal[False] = False
    live_eligible: Literal[False] = False


def export_digest(bundle: ExportBundle) -> str:
    """Caller must pin this value separately; computing it is not authentication."""
    _require(len(bundle.rows) <= 160_000, "capture_export_row_limit")
    rows = []
    size = 0
    for row in bundle.rows:
        encoded = row.model_dump_json()
        size += len(encoded.encode("utf-8"))
        _require(size <= 16 * 1024 * 1024, "capture_export_row_byte_limit")
        rows.append(row.model_dump(mode="json"))
    _require(all(len(raw.encode("utf-8")) <= 16 * 1024 * 1024 for raw in (
        bundle.attempts_json, bundle.accounting_json, bundle.observations_json, bundle.provenance_json)),
        "capture_export_byte_limit")
    return digest(canonical({
        "rows": rows,
        "attempts": digest(bundle.attempts_json), "accounting": digest(bundle.accounting_json),
        "observations": digest(bundle.observations_json), "provenance": digest(bundle.provenance_json),
        "live_eligible": bundle.live_eligible,
    }))


def _require(value: bool, code: str) -> None:
    if not value:
        raise ValueError(code)


def _json(raw: str | bytes, deadline: float):
    data = raw.encode("utf-8") if isinstance(raw, str) else raw
    _require(len(data) <= 16 * 1024 * 1024, "capture_export_byte_limit")
    return decode_source(b'{"value":' + data + b'}', started=deadline - MAX_SECONDS)["value"]


def _read(path: Path, deadline: float, limit: int = 1024 * 1024) -> bytes:
    _require(monotonic() <= deadline, "capture_verify_time_limit")
    data = read_source_bytes(path)
    _require(len(data) <= limit, "capture_file_byte_limit")
    _require(monotonic() <= deadline, "capture_verify_time_limit")
    return data


def _wire(kind, data: str | bytes, code: str):
    try:
        return kind.model_validate_json(data)
    except ValueError:
        # Validation error details can contain the private generated response.
        raise ValueError(code) from None


def _inventory(path: Path, expected: set[str]) -> None:
    _require(not any(p.is_symlink() or (hasattr(p, "is_junction") and p.is_junction())
                     for p in (path, *path.parents)), "capture_link_rejected")
    _require(path.is_dir(), "capture_directory_required")
    names = set()
    for child in path.iterdir():
        names.add(child.name)
        _require(len(names) <= 10002, "capture_inventory_limit")
    _require(names == expected, "capture_inventory_mismatch")


def verify_capture_index(
    directory: Path | None, bundle: ExportBundle, *, expected_export_sha256: str,
    expected_index_sha256: str | None = None,
) -> VerifiedCaptureIndex:
    """No inferred pins, raw plan reads, claim curation, semantic approval or live promotion."""
    deadline = monotonic() + MAX_SECONDS
    actual_export = export_digest(bundle)
    _require(actual_export == expected_export_sha256, "capture_export_pin_mismatch")
    bridge = bridge_bundle(bundle, ())  # Authoritative D6 all-attempt validation, no invented links.
    provenance = _json(bundle.provenance_json, deadline)
    baseline = [row for row in bundle.rows if row.arm == "D"]
    baseline_hash = digest(canonical([row.model_dump(mode="json") for row in baseline]))
    _require(baseline_hash == provenance.get("baseline_sha256"), "capture_D_snapshot_mismatch")
    d_rows = {(row.case_id, row.resource_id, row.rule_id): row for row in baseline}
    _require(len(d_rows) == len(baseline), "capture_duplicate_D_row")
    snapshots = {row.attempt_id: row for row in bridge.snapshots}
    raw_attempts = {row["attempt_id"]: row for row in _json(bundle.attempts_json, deadline)}
    observations = _json(bundle.observations_json, deadline)
    _require(type(observations) is list and len(observations) <= 20001, "capture_observation_limit")
    common = dict(export_sha256=actual_export, baseline_sha256=baseline_hash,
                  all_attempt_ids=tuple(snapshots))
    # Earlier payload-free exports cannot prove the complete finding/fact joins.
    required = {"case_id", "resource_id", "rule_id", "D_row_sha256", "fact_ids"}
    if any(type(obs) is not dict or not required <= set(obs) for obs in observations):
        return VerifiedCaptureIndex(status="incomplete", reasons=("legacy_finding_catalog_missing",), **common)
    p_rows = {}
    l_receipts = []
    seen_observations = set()
    referenced_attempts = set()
    for obs in observations:
        _require(monotonic() <= deadline, "capture_verify_time_limit")
        arm, finding, attempt_id = obs.get("arm"), obs.get("finding_id"), obs.get("attempt_id")
        _require(arm in ("L", "P", "M") and obs.get("status") in (
                     "ok", "invalid", "timeout", "error", "cancelled", "not_run")
                 and (finding is None or type(finding) is str and re.fullmatch(r"[0-9a-f]{32}", finding))
                 and (attempt_id is None or type(attempt_id) is str and re.fullmatch(r"[0-9a-f]{32}", attempt_id)),
                 "capture_observation_identity_invalid")
        _require(arm in ("L", "P", "M") and (arm, finding) not in seen_observations,
                 "capture_duplicate_or_foreign_observation")
        seen_observations.add((arm, finding))
        if attempt_id is None:
            _require(obs.get("status") == "not_run", "capture_missing_attempt")
        else:
            attempt = snapshots.get(attempt_id)
            _require(attempt is not None and attempt_id not in referenced_attempts
                     and attempt.arm == arm and attempt.status == obs.get("status"), "capture_attempt_join_mismatch")
            referenced_attempts.add(attempt_id)
            _require(set(attempt.hashes) == {"build", "corpus", "projection", "prompt", "input", "model", "config"}
                     and attempt.hashes["build"] == provenance["build_sha256"]
                     and attempt.hashes["corpus"] == provenance["corpus_sha256"], "capture_attempt_provenance_mismatch")
            if attempt.status == "timeout":
                _require(attempt.requires_reconciliation and not attempt.billing_known, "capture_timeout_not_pending")
        if arm == "M":
            _require(finding is None and all(obs[key] is None for key in (
                "case_id", "resource_id", "rule_id", "D_row_sha256")) and obs["fact_ids"] == [],
                "capture_M_finding_contamination")
            continue
        base = d_rows.get((obs["case_id"], obs["resource_id"], obs["rule_id"]))
        _require(base is not None and digest(canonical(base.model_dump(mode="json"))) == obs["D_row_sha256"],
                 "capture_finding_D_join_mismatch")
        facts = obs["fact_ids"]
        _require(type(facts) is list and len(facts) <= 256
                 and all(type(v) is str and re.fullmatch(r"[0-9a-f]{32}", v) for v in facts)
                 and len(set(facts)) == len(facts)
                 and set(base.decision_fact_ids) <= set(facts), "capture_fact_catalog_mismatch")
        limits = obs.get("required_limitation_ids")
        _require(type(limits) is list and len(limits) <= 32 and all(type(v) is str for v in limits)
                 and len(set(limits)) == len(limits) and set(limits) == set(base.required_limitation_ids),
                 "capture_limitation_catalog_mismatch")
        if arm == "P":
            p_rows[finding] = obs
        else:
            receipt = _wire(LReceipt, canonical({
                "finding_id": finding, "attempt_id": attempt_id, "status": obs["status"],
                "baseline_words": obs.get("baseline_words"), "rendered_words": obs.get("rendered_words"),
                "render_source": obs.get("render_source"),
                "required_limitation_ids": obs["required_limitation_ids"],
                "selected_limitation_ids": obs.get("limitation_ids", []),
                "word_counts_available": obs.get("word_counts_available", False),
            }), "capture_L_receipt_invalid")
            _require(receipt.word_counts_available == (receipt.baseline_words is not None
                     and receipt.rendered_words is not None), "capture_L_count_availability_mismatch")
            if attempt_id is None:
                _require(receipt.rendered_words is None and receipt.render_source is None
                         and obs.get("selection_accepted") is False,
                         "capture_L_invented_render")
            elif receipt.rendered_words is not None:
                _require(receipt.render_source is not None
                         and set(receipt.selected_limitation_ids) == set(receipt.required_limitation_ids),
                         "capture_L_render_limitations_mismatch")
                _require((receipt.render_source == "validated_selection") == obs.get("selection_accepted")
                         and (not obs.get("selection_accepted") or obs["status"] == "ok"),
                         "capture_L_selection_state_mismatch")
            l_receipts.append(receipt)
    _require(referenced_attempts == set(snapshots), "capture_omitted_attempt")
    _require({r.finding_id for r in l_receipts} == set(p_rows), "capture_L_P_inventory_mismatch")
    common["l_receipts"] = tuple(l_receipts)
    if directory is None:
        return VerifiedCaptureIndex(status="incomplete", reasons=("private_capture_disabled",), **common)
    if expected_index_sha256 is None:
        return VerifiedCaptureIndex(status="incomplete", reasons=("external_index_pin_missing",), **common)
    path = Path(directory).absolute()
    state_bytes = _read(path / "capture-state.json", deadline, 4096)
    index_bytes = _read(path / "artifact-index.json", deadline)
    state = _json(state_bytes, deadline)
    index_hash = digest(index_bytes)
    _require(type(state) is dict and set(state) == {
                 "state", "private", "live_eligible", "semantic_truth_verified", "index_sha256"}
             and state["state"] == "WRITTEN" and state["private"] is True
             and state["live_eligible"] is False and state["semantic_truth_verified"] is False
             and state["index_sha256"] == index_hash == expected_index_sha256,
             "capture_state_or_index_pin_mismatch")
    index_raw = _json(index_bytes, deadline)
    _require(type(index_raw) is dict and type(index_raw.get("schema")) is int
             and index_raw.get("private") is True and index_raw.get("untrusted") is True
             and index_raw.get("live_eligible") is False
             and index_raw.get("semantic_assessment_complete") is False, "capture_index_flags_invalid")
    index = _wire(_Index, canonical(index_raw), "capture_index_schema_invalid")
    _require(index.baseline_sha256 == baseline_hash, "capture_index_D_mismatch")
    _require(len({row.finding_id for row in index.outcomes}) == len(index.outcomes)
             and {row.finding_id for row in index.outcomes} == set(p_rows), "capture_outcome_omission_or_foreign")
    expected_files = set()
    artifacts = []
    read_hashes = {"capture-state.json": digest(state_bytes), "artifact-index.json": index_hash}
    total_bytes = len(state_bytes) + len(index_bytes)
    for outcome in index.outcomes:
        obs = p_rows[outcome.finding_id]
        _require(outcome.case_id == obs["case_id"] and outcome.attempt_id == obs["attempt_id"]
                 and outcome.status == obs["status"], "capture_outcome_invocation_mismatch")
        _require(len(set(outcome.generator_actor_ids)) == len(outcome.generator_actor_ids), "capture_duplicate_generator")
        _require((outcome.artifact_id is None) != (outcome.diagnostic_id is None), "capture_outcome_file_choice_invalid")
        artifact_choice = outcome.artifact_id is not None
        name = ("artifact-" + outcome.artifact_id + ".json") if artifact_choice else (
            "diagnostic-" + outcome.diagnostic_id + ".json")
        _require(name not in expected_files and name in index.files, "capture_file_duplicate_or_missing")
        expected_files.add(name)
        data = _read(path / name, deadline)
        total_bytes += len(data)
        _require(total_bytes <= 64 * 1024 * 1024 and digest(data) == index.files[name], "capture_file_hash_or_total_limit")
        read_hashes[name] = digest(data)
        attempt = snapshots.get(outcome.attempt_id)
        if artifact_choice:
            _json(data, deadline)
            artifact = _wire(ExplanationArtifact, data, "capture_artifact_wire_invalid")
            _require(attempt is not None and outcome.capture_state == "exact_private_response"
                     and artifact.artifact_id == outcome.artifact_id
                     and artifact_digest(artifact) == outcome.artifact_sha256
                     and artifact.case_id == outcome.case_id and artifact.finding_id == outcome.finding_id
                     and artifact.attempt_id == outcome.attempt_id
                     and artifact.generator_actor_ids == outcome.generator_actor_ids
                     and artifact.origin == index.origin and artifact.explanation_withheld,
                     "capture_artifact_identity_mismatch")
            _require(artifact.raw_input_sha256 == provenance["source_sha256"]
                     and artifact.projection_sha256 == attempt.hashes["projection"]
                     and artifact.prompt_sha256 == attempt.hashes["prompt"]
                     and artifact.build_sha256 == provenance["build_sha256"]
                     and artifact.response_sha256 == attempt.response_sha256
                     and digest(artifact.prose) == attempt.response_sha256
                     and artifact.attempt_record_sha256 == digest(canonical(raw_attempts[attempt.attempt_id]))
                     and artifact.price_sha256 == attempt.price_sha256 and artifact.usage_sha256 == attempt.usage_sha256,
                     "capture_artifact_provenance_mismatch")
            _require(artifact.decision.immutable_outcome_sha256 == obs["D_row_sha256"]
                     and artifact.decision.rule_id == obs["rule_id"]
                     and artifact.decision.outcome == d_rows[(obs["case_id"], obs["resource_id"], obs["rule_id"])].outcome
                     and set(artifact.fact_ids) == set(obs["fact_ids"])
                     and set(artifact.limitation_ids) == set(obs["required_limitation_ids"]), "capture_artifact_catalog_mismatch")
            artifacts.append(artifact)
        else:
            _require(outcome.artifact_sha256 is None and outcome.capture_state != "exact_private_response",
                     "capture_diagnostic_claims_artifact")
            diagnostic = _json(data, deadline)
            _require(type(diagnostic) is dict and set(diagnostic) == {
                "schema", "private", "untrusted", "finding_id", "attempt_id", "status", "capture_state",
                "raw_input_sha256", "response_sha256", "response_capture_complete", "retained_bytes",
                "retained_prefix_sha256", "response_prefix_base64", "live_eligible", "semantic_assessment_complete"},
                "capture_diagnostic_schema_invalid")
            _require(diagnostic["schema"] == 1 and diagnostic["private"] is True and diagnostic["untrusted"] is True
                     and diagnostic["live_eligible"] is False and diagnostic["semantic_assessment_complete"] is False
                     and diagnostic["finding_id"] == outcome.finding_id and diagnostic["attempt_id"] == outcome.attempt_id
                     and diagnostic["status"] == outcome.status and diagnostic["capture_state"] == outcome.capture_state
                     and diagnostic["raw_input_sha256"] == provenance["source_sha256"]
                     and diagnostic["response_sha256"] == (attempt.response_sha256 if attempt else None),
                     "capture_diagnostic_invocation_mismatch")
            encoded = diagnostic["response_prefix_base64"]
            retained = base64.b64decode(encoded, validate=True) if type(encoded) is str else None
            _require((encoded is None or type(encoded) is str) and type(diagnostic["retained_bytes"]) is int
                     and type(diagnostic["response_capture_complete"]) is bool
                     and len(retained or b"") == diagnostic["retained_bytes"] <= 65_536
                     and diagnostic["retained_prefix_sha256"] == (digest(retained) if retained is not None else None),
                     "capture_diagnostic_prefix_invalid")
            if retained is None:
                _require(not diagnostic["response_capture_complete"], "capture_diagnostic_missing_bytes")
            elif diagnostic["response_capture_complete"] and attempt and attempt.response_sha256:
                _require(digest(retained) == attempt.response_sha256, "capture_diagnostic_response_mismatch")
            _require(attempt is not None or retained is None, "capture_diagnostic_without_attempt")
            if outcome.capture_state == "response_unavailable":
                _require(retained is None, "capture_diagnostic_false_unavailable")
            elif outcome.capture_state == "response_prefix_only":
                _require(retained is not None and not diagnostic["response_capture_complete"],
                         "capture_diagnostic_false_prefix")
            elif outcome.capture_state == "artifact_wire_rejected":
                _require(retained is not None and diagnostic["response_capture_complete"]
                         and attempt is not None and attempt.response_sha256 is not None,
                         "capture_diagnostic_false_wire_failure")
    _require(expected_files == set(index.files) and index.artifact_count == len(artifacts)
             and index.diagnostic_count == len(index.outcomes) - len(artifacts), "capture_index_count_mismatch")
    _inventory(path, expected_files | {"capture-state.json", "artifact-index.json"})
    for name, expected_hash in read_hashes.items():
        _require(digest(_read(path / name, deadline)) == expected_hash, "capture_changed_during_verification")
    reasons = []
    if any(row.diagnostic_id is not None or row.status != "ok" for row in index.outcomes):
        reasons.append("failed_missing_or_diagnostic_P_output")
    if any(not row.word_counts_available for row in l_receipts):
        reasons.append("L_render_receipts_missing")
    if not index.outcomes:
        reasons.append("no_P_outcomes")
    return VerifiedCaptureIndex(status="verified", index_sha256=index_hash, reasons=tuple(reasons),
        p_outcomes=index.outcomes, file_hashes=tuple(sorted(read_hashes.items())), artifacts=tuple(artifacts),
        assessment_inputs_complete=not reasons, **common)
