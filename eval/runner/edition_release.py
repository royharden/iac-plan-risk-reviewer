"""Explicit local consumed-synthetic edition preparation; never authors gold.

External pins are permission inputs, not authenticated by this module. Metadata
gate first, measurement validation second, input/oracle access last. No discovery.
"""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
from time import monotonic
from typing import Literal

from pydantic import Field

from iac_review.contracts.manifest import Digest, ManifestWire, OpaqueId, RunManifest, Arm
from eval.runner.bundle import (
    AssemblySelection, ReleaseAuthorization, _bytes, _check_root, _read_verified,
    root_digest, select_artifacts,
)
from eval.runner.custody import (
    CustodyAuthority, ExposureReceipt, Seal, metadata_digest,
)
from eval.runner.preflight import PreflightPins, _constant, _object, preflight, read_metadata
from eval.runner.scoring import (
    ARMS, ArmRow, EligibilityManifest, measurement_eligible,
)


class ArmCompletion(ManifestWire):
    arm: Arm
    artifact_id: OpaqueId
    artifact_sha256: Digest
    # Appointed external scorer outcome; failure is releasable, absence is not.
    score_status: Literal["RECORDED", "FAIL"]
    score_result_sha256: Digest
    expected_rows: int = Field(ge=1, le=100000)


class CompletionReference(ManifestWire):
    """Narrow external completion reference; no approval can be self-generated.

    The independent controller freezes this digest separately from the submitted
    bundle. It attests full scorer/failure coverage and actual execution. The
    existing ReleaseAuthorization separately authorizes exact payload disclosure.
    """
    schema_version: Literal[1] = 1
    run_manifest_sha256: Digest
    authority_sha256: Digest
    seal_sha256: Digest
    exposure_sha256: Digest
    eligibility_sha256: Digest
    rubric_sha256: Digest
    # Entire frozen oracle identity inventory, not favorable/supported rows only.
    row_inventory_sha256: Digest
    row_inventory: tuple[tuple[OpaqueId, OpaqueId, Literal["R1", "R2", "R3", "R4"]], ...] = Field(
        min_length=1, max_length=100000)
    arms: tuple[ArmCompletion, ...] = Field(min_length=7, max_length=7)
    consumed_at: datetime


def _row_hash(rows) -> str:
    return sha256(json.dumps(rows, separators=(",", ":"), ensure_ascii=True).encode("ascii")).hexdigest()


def check_completion(manifest: RunManifest, completion: CompletionReference,
                     expected_completion_sha256: str) -> None:
    """Pure first gate: no file reads and no favorable-score requirement."""
    if (metadata_digest(completion) != expected_completion_sha256
            or completion.run_manifest_sha256 != metadata_digest(manifest)
            or completion.authority_sha256 != manifest.authority_sha256
            or completion.eligibility_sha256 != manifest.eligibility_sha256
            or manifest.stage != "evaluation" or manifest.split != "heldout"
            or manifest.edition_state != "consumed_holdout"):
        raise ValueError("exact externally pinned consumed completion required")
    if (completion.consumed_at.tzinfo is None
            or completion.consumed_at.utcoffset() is None):
        raise ValueError("aware completion timestamp required")
    identities = completion.row_inventory
    if (len(set(identities)) != len(identities)
            or _row_hash(identities) != completion.row_inventory_sha256
            or {row[0] for row in identities} != {row.case_id for row in manifest.cases}):
        raise ValueError("whole consumed row/case inventory required")
    if len({row.arm for row in completion.arms}) != 7 or {row.arm for row in completion.arms} != set(ARMS):
        raise ValueError("all seven distinct completed arms required")
    refs = {row.artifact_id: row for row in manifest.artifacts}
    if len({row.artifact_id for row in completion.arms}) != 7:
        raise ValueError("separate exact arm measurement artifacts required")
    if len({row.score_result_sha256 for row in completion.arms}) != 1:
        raise ValueError("one complete unfiltered seven-arm score result required")
    invocations = {row.invocation_id: row for row in manifest.invocations}
    cases = {row.case_id: row for row in manifest.cases}
    for arm in completion.arms:
        ref = refs.get(arm.artifact_id)
        if (ref is None or ref.role != "measurements" or ref.sha256 != arm.artifact_sha256
                or arm.expected_rows != len(identities)):
            raise ValueError("arm completion inventory/artifact mismatch")
        covered = set()
        for invocation in manifest.invocations:
            if invocation.arm != arm.arm:
                continue
            kinds = {"live", "replay"} if arm.arm in {"L", "P", "M"} else {"executed"}
            if (invocation.kind not in kinds or not invocation.all_attempts_attested
                    or invocation.status in {"not_run", "pending", "unmapped"}):
                raise ValueError("unmeasured invocation cannot close edition")
            covered.update(invocation.case_ids)
        if covered != set(cases):
            raise ValueError("arm omits consumed cases")
        # Preflight authenticates neither these claims nor permission; it checks
        # actual eligibility records separately before any measurement is read.
        claims = [row for row in manifest.eligibility if row.arm == arm.arm and row.claimed_eligible]
        for case in cases.values():
            if not any(case.case_id in invocations[row.invocation_id].case_ids
                       and row.raw_source_sha256 == case.raw_source_sha256 for row in claims):
                raise ValueError("arm lacks genuine eligibility for a consumed case")


def prepare_consumed_edition(root: Path, out: Path, manifest: RunManifest,
                             pins: PreflightPins, selection: AssemblySelection,
                             expected_selection_sha256: str,
                             authorization: ReleaseAuthorization,
                             expected_authorization_sha256: str,
                             completion: CompletionReference,
                             expected_completion_sha256: str) -> dict:
    """Future explicit invocation only. No commands, inference or label creation.

    Exact output must be a fresh gold/editions/<32-hex opaque id> directory.
    Only externally approved consumed input/oracle bytes plus bounded non-prose
    control records are written. Original score artifacts stay private and pinned.
    """
    root, out = _check_root(root, exists=True), _check_root(out, exists=False)
    if (".." in root.parts or ".." in out.parts or str(root).startswith("\\\\")
            or str(out).startswith("\\\\") or root.is_relative_to(out) or out.is_relative_to(root)
            or out.parent.name != "editions" or out.parent.parent.name != "gold"
            or len(out.name) != 32 or any(c not in "0123456789abcdef" for c in out.name)):
        raise ValueError("fresh disjoint local gold/editions/opaque-id required")
    if (metadata_digest(selection) != expected_selection_sha256
            or selection.run_id != manifest.run_id
            or selection.run_manifest_sha256 != pins.run_manifest_sha256
            or selection.source_root_sha256 != root_digest(root)
            or selection.output_root_sha256 != root_digest(out)):
        raise ValueError("externally approved exact root selection required")
    deadline = monotonic() + selection.max_seconds

    def check():
        if monotonic() >= deadline:
            raise ValueError("edition preparation deadline")
        if not authorization.valid_from <= datetime.now(timezone.utc) <= authorization.valid_until:
            raise ValueError("release authorization outside approved interval")

    check_completion(manifest, completion, expected_completion_sha256)
    check()
    status = preflight(root, manifest, pins)  # ONLY fixed allowlisted metadata.
    if status["edition_state"] != "consumed_holdout" or status["missing_arms"]:
        raise ValueError("consumed seven-arm eligibility incomplete")
    # Reuse actual permission wire and allowlist; never invent a release approval.
    selected = select_artifacts(manifest, True, authorization,
                                expected_authorization_sha256, status["edition_state"])
    metadata = {ref.role: ref for ref in selected if ref.role in {
        "authority", "seal", "exposure", "eligibility"}}
    authority = CustodyAuthority.model_validate_json(json.dumps(read_metadata(root, metadata["authority"])))
    seal = Seal.model_validate_json(json.dumps(read_metadata(root, metadata["seal"])))
    exposure = tuple(ExposureReceipt.model_validate_json(json.dumps(row))
                     for row in read_metadata(root, metadata["exposure"]))
    eligible = EligibilityManifest.model_validate_json(json.dumps(read_metadata(root, metadata["eligibility"])))
    if (completion.seal_sha256 != metadata_digest(seal)
            or completion.exposure_sha256 != metadata["exposure"].sha256
            or completion.rubric_sha256 != authority.rubric_sha256
            or authorization.custodian != seal.custodian
            or authorization.exposure_artifact_sha256 != metadata["exposure"].sha256
            or {row.arm for row in exposure} != set(ARMS)
            or any(row.exposed_at > completion.consumed_at for row in exposure)):
        raise ValueError("completion custody/rubric/exposure binding mismatch")
    payloads = [ref for ref in selected if ref.role in {"case_input", "oracle", "measurements"}]
    inputs = [ref for ref in payloads if ref.role == "case_input"]
    oracles = [ref for ref in payloads if ref.role == "oracle"]
    measurements = [ref for ref in payloads if ref.role == "measurements"]
    case_hashes = [row.raw_source_sha256 for row in manifest.cases]
    if (sorted(ref.sha256 for ref in inputs) != sorted(case_hashes)
            or len(oracles) != 1 or oracles[0].sha256 != authority.oracle_sha256
            or {ref.artifact_id for ref in measurements} != {row.artifact_id for row in completion.arms}
            or len(measurements) != 7):
        raise ValueError("release must retain whole consumed inventory and all seven records only")
    if sum(ref.bytes_upper for ref in payloads) > selection.max_total_bytes:
        raise ValueError("declared payloads exceed edition byte bound")
    # Permission and all metadata gates are complete BEFORE measurement payloads;
    # measurement content is verified BEFORE any input or oracle payload is opened.
    by_id = {ref.artifact_id: ref for ref in measurements}
    cases = {row.case_id: row for row in manifest.cases}
    arm_controls = []
    for arm in completion.arms:
        raw = _read_verified(root, by_id[arm.artifact_id], check)
        value = json.loads(raw, object_pairs_hook=_object, parse_constant=_constant)
        if type(value) is not dict or set(value) != {"rows", "score_result"}:
            raise ValueError("closed measured rows and unfiltered score result required")
        if type(value["rows"]) is not list or len(value["rows"]) != arm.expected_rows:
            raise ValueError("measurement row inventory incomplete")
        # Do not re-score or access labels. Existing scorer result is retained by
        # hash and explicit FAIL status, never replaced with recomputed success.
        score_raw = json.dumps(value["score_result"], sort_keys=True, separators=(",", ":"),
                               ensure_ascii=True, allow_nan=False).encode("ascii")
        if sha256(score_raw).hexdigest() != arm.score_result_sha256:
            raise ValueError("external unfiltered score-result pin mismatch")
        from eval.runner.results import validate_score_result
        result = validate_score_result(value["score_result"])
        if (result["split"] != "heldout" or result["oracle_rows"] != len(completion.row_inventory)
                or any(result["arms"][name]["measurement_status"] != "RECORDED" for name in ARMS)):
            raise ValueError("score result has incomplete arms or denominator")
        if arm.arm == "D" and not result["deterministic_exact_gate"] and arm.score_status != "FAIL":
            raise ValueError("D exact FAIL must remain FAIL")
        rows = [ArmRow.model_validate_json(json.dumps(item)) for item in value["rows"]]
        keys = [(row.case_id, row.resource_id, row.rule_id) for row in rows]
        if len(set(keys)) != len(keys) or set(keys) != set(completion.row_inventory):
            raise ValueError("measurement dropped or added frozen rows")
        for row in rows:
            if (row.arm != arm.arm or row.build_sha256 != manifest.build_sha256
                    or row.source_sha256 != cases[row.case_id].raw_source_sha256
                    or row.status in {"not_run", "unmapped"} or not measurement_eligible(row, eligible)):
                raise ValueError("mock/missing/foreign measurement cannot release edition")
            claims = [claim for claim in manifest.eligibility
                      if claim.arm == row.arm and claim.claimed_eligible
                      and claim.measurement_ref == row.measurement_ref
                      and claim.raw_source_sha256 == row.source_sha256
                      and claim.eligibility_ref == row.eligibility_ref]
            if not claims:
                raise ValueError("measured row has no exact manifest eligibility binding")
        metric = result["arms"][arm.arm]
        if (type(metric["billing_fully_known"]) is not bool
                or type(metric["unresolved_upper_bounds_known"]) is not bool
                or metric["cost_completeness"] not in {
                    "MISSING_ALL_ATTEMPT_ACCOUNTING", "ROW_SUBTOTAL_ONLY"}):
            raise ValueError("unrecognized scorer cost wire; no free-text cost projection")
        if metric["failures"] and arm.score_status != "FAIL":
            raise ValueError("recorded score failures must remain FAIL")
        failed_keys = {(row["case_id"], row["resource_id"], row["rule_id"])
                       for row in metric["failures"]}
        if len(failed_keys) != len(metric["failures"]) or not failed_keys <= set(keys):
            raise ValueError("score failure identities differ from frozen row inventory")
        arm_controls.append({
            "arm": arm.arm, "score_status": arm.score_status,
            "measurement_sha256": arm.artifact_sha256, "score_result_sha256": arm.score_result_sha256,
            "row_count": len(rows), "failures": len(metric["failures"]),
            "failed_rows": sorted(failed_keys),
            "row_outcomes": [{"case_id": row.case_id, "resource_id": row.resource_id,
                              "rule_id": row.rule_id, "status": row.status,
                              "applicability": row.applicability, "outcome": row.outcome,
                              "prediction_target": row.prediction_target,
                              "introduced_prediction": row.introduced_prediction,
                              "known_usd": row.known_usd, "billing_known": row.billing_known,
                              "unresolved_usd_upper": row.unresolved_usd_upper}
                             for row in rows],
            "per_rule": metric["per_rule"],
            "cost": {key: metric[key] for key in (
                "known_usd", "all_attempt_cost", "billing_fully_known", "cost_completeness",
                "unresolved_upper_bounds_known", "unresolved_usd_upper",
                "row_known_usd_subtotal", "row_unresolved_usd_upper_subtotal")},
        })
    # Bounded byte-for-byte copy, no decode/scrubbing/label derivation.
    data = {}
    copied = []
    for ref in (*inputs, *oracles):
        raw = _read_verified(root, ref, check)
        # Artifact IDs may contain colons; output names use hashes instead.
        name = ("inputs/" if ref.role == "case_input" else "expected/") + sha256(ref.artifact_id.encode("ascii")).hexdigest() + ".json"
        data[name] = raw
        copied.append({"path": name, "sha256": ref.sha256, "bytes": len(raw), "role": ref.role})
    data["inventory.json"] = _bytes([row.model_dump(mode="json") for row in seal.inventory])
    data["row-inventory.json"] = _bytes(completion.row_inventory)
    receipt = {
        "schema_version": 1, "state": "LOCAL_CANDIDATE", "edition_id": manifest.edition_id,
        "source_run_manifest_sha256": pins.run_manifest_sha256,
        "authority_sha256": pins.authority_sha256, "seal_sha256": completion.seal_sha256,
        "completion_sha256": expected_completion_sha256,
        "release_authorization_sha256": expected_authorization_sha256,
        "selection_sha256": expected_selection_sha256,
        "build_sha256": manifest.build_sha256, "policy_sha256": manifest.policy_sha256,
        "prompt_sha256": authority.prompt_sha256, "rubric_sha256": authority.rubric_sha256,
        "corpus_sha256": authority.inventory_sha256, "oracle_sha256": authority.oracle_sha256,
        "semantic_suite_sha256": pins.semantic_suite_sha256, "eligibility_sha256": pins.eligibility_sha256,
        "exposure_sha256": completion.exposure_sha256,
        "exposure_measurement_pins": [{"arm": row.arm, "measurements_sha256": row.measurements_sha256}
                                      for row in exposure],
        "row_inventory_sha256": completion.row_inventory_sha256,
        "arms": arm_controls, "copied": copied, "attempt_accounting": status["costs"],
        "attempts": [{"attempt_id": row.attempt_id, "arm": row.arm, "status": row.status,
                      "known_usd": row.known_usd, "billing_known": row.billing_known,
                      "unresolved_usd_upper": row.unresolved_usd_upper,
                      "input_tokens": row.input_tokens, "output_tokens": row.output_tokens,
                      "elapsed_ms": row.elapsed_ms,
                      "start_receipt_sha256": row.start_receipt_sha256,
                      "terminal_receipt_sha256": row.terminal_receipt_sha256}
                     for row in manifest.attempts],
        "inventory_sha256": sha256(data["inventory.json"]).hexdigest(),
        "fresh_holdout": False, "product_acceptance": False,
        "authorization_authenticated": False, "publication_performed": False,
    }
    data["edition.json"] = _bytes(receipt)
    data["edition.sha256"] = (sha256(data["edition.json"]).hexdigest() + "\n").encode("ascii")
    if sum(len(raw) for raw in data.values()) + 1024 > selection.max_total_bytes:
        raise ValueError("edition controls exceed byte cap")
    check()
    # Re-read pinned metadata, not hidden inputs, before starting publication.
    preflight(root, manifest, pins)
    out.mkdir(exist_ok=False)
    state = out / "edition-state.json"
    created = []
    directories = []

    def write(path, raw):
        _check_root(out, exists=True)
        if not path.is_relative_to(out) or any(p.is_symlink() or (
                hasattr(p, "is_junction") and p.is_junction()) for p in (path, *path.parents)):
            raise ValueError("edition output path changed")
        with path.open("xb") as stream:
            created.append(path)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())

    write(state, _bytes({"state": "ABORTED"}))
    try:
        for name, raw in data.items():
            check()
            path = out.joinpath(*name.split("/"))
            if path.parent != out and not path.parent.exists():
                path.parent.mkdir(exist_ok=False)
                directories.append(path.parent)
            write(path, raw)
        # Finalization requires still-valid exact custody metadata and permission.
        preflight(root, manifest, pins)
        check()
        pending = out / ".edition-state.pending"
        write(pending, _bytes({"state": "COMPLETE", "mode": "local_consumed_synthetic_candidate"}))
        check()
        os.replace(pending, state)
    except BaseException:
        for path in reversed(created):
            if path != state:
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    pass
        for path in reversed(directories):
            try:
                path.rmdir()
            except OSError:
                pass
        raise
    return {"state": "COMPLETE", "mode": "local_consumed_synthetic_candidate",
            "arms": 7, "fresh_holdout": False, "publication_performed": False,
            "product_acceptance": False}
