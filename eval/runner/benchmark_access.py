"""Narrow future consumed-heldout INPUT access SOURCE; no automatic unblinding or execution.

Actual custody/preflight metadata gates, D6's committed pre-access
`InputExposureReceipt` rows (contract S1) and independent explicit access
permission. The external custodian commits input exposure BEFORE invoking this
controller. This permission covers case INPUTS only: the oracle is never readable
here. Scoring uses the separate post-measurement legacy `ExposureReceipt` path
(`eval/runner/scoring_handoff.py` / `scripts/eval.py`).
No inference/scorer orchestration, gold authoring, connector or credential access.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
from typing import Callable, Literal

from pydantic import Field, model_validator

from iac_review.contracts.manifest import ArtifactRef, Digest, ManifestWire, OpaqueId, RunManifest
from eval.model.experiment import canonical, digest
from eval.runner.bundle import PAYLOAD_PREFIXES, root_digest
from eval.runner.custody import CustodyAuthority, Seal, metadata_digest, validate_seal
from eval.runner.preflight import PreflightPins, checked_path, preflight, read_metadata
from eval.runner.scoring import ARMS


ACCESS_SCHEMA = "m4-heldout-input-access-v2"
# S1.6: sealed is admissible only together with a committed input-exposure journal.
INPUT_ACCESS_STATES = ("consumed_holdout", "sealed")


class PayloadPermission(ManifestWire):
    artifact_id: OpaqueId
    # Input access only (S1). Oracle bytes are never granted by this permission.
    role: Literal["case_input"]
    sha256: Digest
    case_id: OpaqueId


class HeldoutAuthorization(ManifestWire):
    """Versioned input-access permission (contract S1).

    v2 binds the per-arm pre-access measurement INTENTS committed by D6's input
    exposure journal. v1 documents (integer schema_version, legacy
    `measurements_sha256`/`exposure_artifact_sha256`, oracle payload rows) are
    refused by the closed schema and never reinterpreted.
    """
    schema_version: Literal["m4-heldout-input-access-v2"]
    purpose: Literal["consumed_heldout_evaluation"]
    run_id: OpaqueId
    edition_id: OpaqueId
    run_manifest_sha256: Digest
    source_root_sha256: Digest
    authority_sha256: Digest
    seal_sha256: Digest
    semantic_suite_sha256: Digest
    build_sha256: Digest
    inventory_sha256: Digest
    prompt_sha256: Digest
    rubric_sha256: Digest
    arm_inventory_sha256: Digest
    # Exact D6 InputExposureCommit identities (metadata/input-exposure*.json*).
    input_exposure_authorization_sha256: Digest
    input_exposure_commit_sha256: Digest
    input_exposure_receipt_file_sha256: Digest
    # Declared pre-access intent/config pins per arm; never result hashes.
    measurement_intents_sha256: dict[str, Digest] = Field(min_length=7, max_length=7)
    custodian: str = Field(min_length=1, max_length=160)
    authorized_by: str = Field(min_length=1, max_length=160)
    consumption_committed_before_access: Literal[True]
    tuning_forbidden: Literal[True]
    valid_from: datetime
    valid_until: datetime
    payloads: tuple[PayloadPermission, ...] = Field(min_length=1, max_length=512)

    @model_validator(mode="after")
    def bounded_permission(self):
        if (self.valid_from.tzinfo is None or self.valid_until.tzinfo is None
                or self.valid_from.utcoffset() is None or self.valid_until.utcoffset() is None
                or self.valid_until <= self.valid_from or set(self.measurement_intents_sha256) != set(ARMS)
                or len({row.artifact_id for row in self.payloads}) != len(self.payloads)
                or len({row.case_id for row in self.payloads}) != len(self.payloads)):
            raise ValueError("bounded_exact_all_arm_heldout_permission_required")
        return self


def arm_inventory_digest(manifest: RunManifest) -> str:
    """Bind actual all-arm version/config declarations; never hash payloads here."""
    components = {row.component_id: row for row in manifest.components}
    cases = {row.case_id for row in manifest.cases}
    result = []
    for arm in ARMS:
        invocations = [row for row in manifest.invocations if row.arm == arm]
        if not invocations or {case for row in invocations for case in row.case_ids} != cases:
            raise ValueError("frozen_all_arm_case_inventory_missing")
        result.append({"arm": arm, "bindings": [{
            "invocation_id": row.invocation_id, "case_ids": list(row.case_ids),
            "version": components[row.version_component_id].model_dump(mode="json"),
            "config": components[row.config_component_id].model_dump(mode="json")}
            for row in invocations]})
    return digest(canonical(result))


def _event(path: Path, run_id: str, status: str, code: str, artifact_id: str | None = None, *, create=False):
    """Future explicit call only: payload-free durable local denial/access journal.

    A log failure stops access. This log is NOT the external consumption receipt.
    Existing model/scanner journals are never changed, reset, copied or reconciled.
    """
    path = path.absolute()
    if any(p.is_symlink() or (hasattr(p, "is_junction") and p.is_junction()) for p in (path, *path.parents)):
        raise ValueError("access_journal_link_forbidden")
    raw = (canonical({"schema_version": 1, "run_id": run_id, "status": status,
                      "reason_code": code, "artifact_id": artifact_id,
                      "at": datetime.now(timezone.utc).isoformat(), "live_eligible": False}) + "\n").encode()
    with path.open("xb" if create else "ab") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def _gate(root: Path, manifest: RunManifest, pins: PreflightPins,
          permission: HeldoutAuthorization, expected_permission_sha256: str, exposure_authorization):
    # Lazy import: exposure_journal imports arm_inventory_digest from this module.
    from eval.runner.exposure_journal import (ExposureCommitAuthorization, InputExposureCommit,
                                              InputExposureReceipt, verify_committed_exposure)
    # External explicit permission gate comes BEFORE even custody metadata reads.
    if ".." in root.parts or str(root.absolute()).startswith("\\\\"):
        raise ValueError("local_exact_access_root_required")
    now = datetime.now(timezone.utc)
    if (type(permission) is not HeldoutAuthorization or type(manifest) is not RunManifest
            or type(exposure_authorization) is not ExposureCommitAuthorization
            or metadata_digest(permission) != expected_permission_sha256
            or metadata_digest(exposure_authorization) != permission.input_exposure_authorization_sha256
            or permission.run_id != manifest.run_id or permission.edition_id != manifest.edition_id
            or permission.run_manifest_sha256 != pins.run_manifest_sha256
            or permission.source_root_sha256 != root_digest(root)
            or manifest.stage != "evaluation" or manifest.split != "heldout"
            or manifest.edition_state not in INPUT_ACCESS_STATES
            or not permission.valid_from <= now <= permission.valid_until):
        raise ValueError("explicit_externally_pinned_consumed_access_required")
    status = preflight(root, manifest, pins)  # Actual metadata-only API, never permission.
    # Contract S1.6: (a) legacy consumed_holdout, or (b) sealed WITH a committed input-
    # exposure journal. Either way the pinned InputExposureCommit below is still required.
    # (b) is input permission only; never oracle/scoring or tuning permission.
    if (status["edition_state"] != manifest.edition_state or status["payloads_opened"] != 0
            or status["edition_state"] not in INPUT_ACCESS_STATES
            or (status["edition_state"] == "sealed" and status.get("input_exposure_committed") is not True)):
        raise ValueError("durable_consumption_required_before_payload")
    # D6 committed PRE-ACCESS input exposure (S1). Never oracle/scoring permission.
    commit = verify_committed_exposure(root, manifest, pins, exposure_authorization,
        expected_authorization_sha256=permission.input_exposure_authorization_sha256,
        expected_commit_sha256=permission.input_exposure_commit_sha256)
    if (type(commit) is not InputExposureCommit or commit.payload_permission_granted is not False
            or commit.oracle_permission_granted is not False or commit.scoring_permission_granted is not False
            or commit.commit_sha256 != permission.input_exposure_commit_sha256
            or commit.receipt_file_sha256 != permission.input_exposure_receipt_file_sha256
            or commit.authorization.measurement_intents_sha256 != permission.measurement_intents_sha256
            or len(commit.receipts) != len(ARMS) or {row.arm for row in commit.receipts} != set(ARMS)
            or any(type(row) is not InputExposureReceipt
                   or row.run_id != manifest.run_id or row.edition_id != manifest.edition_id
                   or row.measurement_intents_sha256 != permission.measurement_intents_sha256[row.arm]
                   for row in commit.receipts)):
        raise ValueError("committed_input_exposure_permission_mismatch")
    refs = {ref.role: ref for ref in manifest.artifacts if ref.role in {"authority", "seal"}}
    if set(refs) != {"authority", "seal"}:
        raise ValueError("persisted_custody_metadata_missing")
    authority = CustodyAuthority.model_validate_json(json.dumps(read_metadata(root, refs["authority"])))
    seal = Seal.model_validate_json(json.dumps(read_metadata(root, refs["seal"])))
    validate_seal(authority, seal, pins.authority_sha256)
    expected = {"authority_sha256": pins.authority_sha256, "seal_sha256": metadata_digest(seal),
                "semantic_suite_sha256": pins.semantic_suite_sha256, "build_sha256": manifest.build_sha256,
                "inventory_sha256": authority.inventory_sha256, "prompt_sha256": authority.prompt_sha256,
                "rubric_sha256": authority.rubric_sha256, "arm_inventory_sha256": arm_inventory_digest(manifest),
                "custodian": authority.custodian}
    if (any(getattr(permission, key) != value for key, value in expected.items())
            or permission.authorized_by != authority.custodian
            or any(row.seal_sha256 != expected["seal_sha256"] or row.custodian != authority.custodian
                   for row in commit.receipts)):
        raise ValueError("frozen_permission_custody_inventory_exposure_mismatch")
    by_id, selected = {ref.artifact_id: ref for ref in manifest.artifacts}, {}
    bindings = {case.case_id: case for case in manifest.cases}
    input_cases = []
    for allowed in permission.payloads:
        ref = by_id.get(allowed.artifact_id)
        if (ref is None or ref.role != "case_input" or allowed.role != "case_input"
                or ref.sha256 != allowed.sha256 or ref.visibility != "private"
                # Shared bundle namespace (bundle.PAYLOAD_PREFIXES); "synthetic" in the path is a
                # legacy layout name, NOT a scope claim. Heldout identity comes from the manifest
                # split/edition state and this v2 permission, never from the path.
                or not ref.path.startswith(PAYLOAD_PREFIXES["case_input"])
                or any(part in ref.path.casefold() for part in ("credential", "secret", "private_map", "private-map", "auth.json", "token"))):
            raise ValueError("exact_private_input_allowlist_required")
        checked_path(root, ref)  # Path validation only; no payload stat/open/read.
        case = bindings.get(allowed.case_id)
        if case is None or ref.sha256 != case.raw_source_sha256:
            raise ValueError("case_input_raw_identity_mismatch")
        input_cases.append(allowed.case_id)
        selected[ref.artifact_id] = ref
    if len(input_cases) != len(set(input_cases)) or set(input_cases) != set(bindings):
        raise ValueError("whole_frozen_input_inventory_required")
    return selected


class HeldoutAccess:
    """Private local INPUT accessor. The scoring-only oracle path is a separate module.

    It does NOT run coordinate or expose a provider Request. Core coordinate still
    denies heldout. A future externally approved orchestrator must preserve the
    existing inference projection boundary; this object is never a transport arg.
    """
    def __init__(self, root, manifest, pins, permission, expected_pin, event_path, exposure_authorization):
        self._root, self._manifest, self._pins = root.absolute(), manifest, pins
        self._permission, self._expected_pin, self._event_path = permission, expected_pin, event_path
        self._exposure_authorization = exposure_authorization
        self._used, self._halted = set(), False

    def check_authorized(self):
        if self._halted:
            raise ValueError("access_halted_no_retry")
        return _gate(self._root, self._manifest, self._pins, self._permission, self._expected_pin,
                     self._exposure_authorization)

    def _read(self, artifact_id: str, role: str) -> bytes:
        if self._halted:
            raise ValueError("access_halted_no_retry")
        try:
            selected = _gate(self._root, self._manifest, self._pins, self._permission, self._expected_pin,
                     self._exposure_authorization)
            ref = selected.get(artifact_id)
            if ref is None or ref.role != role or artifact_id in self._used:
                raise ValueError("wrong_role_or_reused_access")
            self._used.add(artifact_id)  # Failed reads cannot authorize a retry.
            _event(self._event_path, self._manifest.run_id, "pending", "authorized_payload_read", artifact_id)
            path = checked_path(self._root, ref)
            if datetime.now(timezone.utc) > self._permission.valid_until:
                raise ValueError("access_permission_expired")
            if not path.is_file() or path.stat().st_size > ref.bytes_upper:
                raise ValueError("authorized_payload_missing_or_oversized")
            with path.open("rb") as stream:
                raw = stream.read(ref.bytes_upper + 1)
            if len(raw) > ref.bytes_upper or digest(raw) != ref.sha256:
                raise ValueError("authorized_payload_hash_mismatch")
            _gate(self._root, self._manifest, self._pins, self._permission, self._expected_pin,
                     self._exposure_authorization)
            _event(self._event_path, self._manifest.run_id, "read", "verified_payload_read", artifact_id)
            return raw
        except (ValueError, OSError, TypeError, KeyError):
            self._halted = True
            _event(self._event_path, self._manifest.run_id, "not_run", "access_incomplete", None)
            raise ValueError("heldout_access_incomplete") from None

    def read_case_input(self, case_id: str) -> bytes:
        allowed = [row for row in self._permission.payloads if row.role == "case_input" and row.case_id == case_id]
        if len(allowed) != 1:
            self._halted = True
            _event(self._event_path, self._manifest.run_id, "not_run", "unknown_case_access")
            raise ValueError("unknown_case_access")
        return self._read(allowed[0].artifact_id, "case_input")

    def deliver_oracle_to_scoring(self, scoring_sink: Callable[[bytes], None]) -> None:
        """Refused by design (S1 item 4): input permission is never oracle permission.

        Scoring-only oracle access follows the post-measurement legacy ExposureReceipt
        path in `eval/runner/scoring_handoff.py`. No oracle byte is read here.
        """
        raise ValueError("input_access_is_not_oracle_permission")


def authorize_heldout_access(root: Path, manifest: RunManifest, pins: PreflightPins,
                             permission: HeldoutAuthorization, *, expected_permission_sha256: str,
                             event_path: Path, exposure_authorization) -> HeldoutAccess:
    """Explicit future caller only. No automatic controller/approval/consumption creation."""
    # Restrict the NEW event log away from input/oracle/metadata paths and existing
    # journals, preventing a denial write from mutating externally pinned evidence.
    log = event_path.absolute()
    base = root.absolute()
    if log.parent != base / "private" / "access-events" or log.exists():
        raise ValueError("fresh_separate_access_event_log_required")
    try:
        _gate(base, manifest, pins, permission, expected_permission_sha256, exposure_authorization)
        _event(log, manifest.run_id, "authorized", "consumed_metadata_and_permission_verified", create=True)
    except (ValueError, OSError, TypeError, KeyError):
        _event(log, manifest.run_id, "not_run", "authorization_incomplete", create=True)
        raise ValueError("heldout_access_not_authorized") from None
    return HeldoutAccess(base, manifest, pins, permission, expected_permission_sha256, log,
                         exposure_authorization)


class GuardedCaseReader:
    """Private, in-memory fixed-byte reader capability for the shared coordinator.

    Each payload is opened once through HeldoutAccess. Subsequent arm checks recheck
    permission/custody and the immutable byte identity, without reopening/copying it.
    No payload/private path enters public metadata or inference requests.
    """
    def __init__(self, access: HeldoutAccess):
        if type(access) is not HeldoutAccess:
            raise ValueError("actual_authorized_heldout_accessor_required")
        self._access, self._bytes = access, {}

    @property
    def manifest(self):
        return self._access._manifest

    def check_inventory(self, cases, build_sha256):
        selected = self._access.check_authorized()
        actual = {row.case_id: row for row in self.manifest.cases}
        if (build_sha256 != self.manifest.build_sha256 or {case.case_id for case in cases} != set(actual)
                or len(cases) != len(actual)):
            raise ValueError("guarded_frozen_inventory_mismatch")
        for case in cases:
            binding = actual[case.case_id]
            permitted = [row for row in self._access._permission.payloads if row.case_id == case.case_id]
            if (len(permitted) != 1 or case.plan_path != checked_path(self._access._root, selected[permitted[0].artifact_id])
                    or (case.plan_sha256, case.configuration_id, case.family_id, case.mutation_lineage) !=
                       (binding.raw_source_sha256, binding.configuration_id, binding.family_id, binding.mutation_lineage)):
                raise ValueError("guarded_case_raw_lineage_path_mismatch")

    def verify(self, case):
        self._access.check_authorized()
        if case.case_id not in self._bytes:
            self._bytes[case.case_id] = self._access.read_case_input(case.case_id)
        if digest(self._bytes[case.case_id]) != case.plan_sha256:
            raise ValueError("guarded_case_raw_identity_mismatch")

    def read(self, case) -> bytes:
        self.verify(case)
        return self._bytes[case.case_id]
