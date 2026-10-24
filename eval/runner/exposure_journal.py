"""Durable metadata-only all-arm pre-access input-exposure commit (contract S1).

This module records the PRE-ACCESS input-exposure event before a separate
controller may read heldout case inputs. It writes versioned
`InputExposureReceipt` rows that bind declared per-arm measurement INTENTS, never
result hashes. The legacy post-measurement, pre-oracle `custody.ExposureReceipt`
(whose `measurements_sha256` is the actual measured-results file hash checked by
scoring) is a different event: this module never constructs or writes it.

It is not input, oracle or scoring permission, authorship authentication, or an
evaluation runner. A partial commit is permanently blocked until an external
custodian resolves it; this source never rolls back or reuses an edition.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
from typing import Literal
from uuid import uuid4

from pydantic import AwareDatetime, Field

from iac_review.contracts.manifest import RunManifest
from eval.model.experiment import canonical
from eval.runner.benchmark_access import arm_inventory_digest
from eval.runner.bundle import root_digest
from eval.runner.custody import (
    CustodyAuthority, Digest, Identity, Record, Seal,
    SemanticReceipt, metadata_digest, validate_seal, validate_semantics,
)
from eval.runner.preflight import PreflightPins, preflight
from eval.runner.scoring import ARMS

INPUT_EXPOSURE_SCHEMA = "m4-input-exposure-v1"
MAX_LEDGER_BYTES = 1024 * 1024
MAX_RECEIPT_BYTES = 64 * 1024
# Distinct from the legacy post-measurement "exposure" metadata artifact read by
# preflight/scoring; the two records are never stored in the same file.
LEDGER_RELATIVE = Path("metadata") / "input-exposure-commit.jsonl"
RECEIPTS_RELATIVE = Path("metadata") / "input-exposure.json"
LOCK_RELATIVE = Path("metadata") / ".input-exposure-commit.lock"
# Earlier unaccepted WIP journal paths, which copied intents into legacy
# measurements_sha256. Never ignored: presence blocks status and commit.
LEGACY_WIP_RELATIVE = (Path("metadata") / "exposure-commit.jsonl",
                       Path("metadata") / ".exposure-commit.lock")
# Legacy post-measurement receipt file; must not pre-exist a pre-access commit.
POST_MEASUREMENT_RELATIVE = Path("metadata") / "exposure.json"


class ExposureCommitAuthorization(Record):
    """Externally frozen metadata intent, not payload permission or actor proof."""
    schema_version: Literal[1] = 1
    run_id: Identity
    edition_id: Identity
    run_manifest_sha256: Digest
    source_root_sha256: Digest
    authority_sha256: Digest
    seal_sha256: Digest
    policy_sha256: Digest
    semantic_suite_sha256: Digest
    eligibility_sha256: Digest
    build_sha256: Digest
    oracle_sha256: Digest
    inventory_sha256: Digest
    prompt_sha256: Digest
    rubric_sha256: Digest
    arm_inventory_sha256: Digest
    custodian: Identity
    # Externally frozen pre-access intent/reference identities. Never result hashes.
    measurement_intents_sha256: dict[str, Digest] = Field(min_length=7, max_length=7)
    approved_before_access: Literal[True]


class InputExposureReceipt(Record):
    """One arm's durable PRE-ACCESS input-exposure receipt.

    `measurement_intents_sha256` is the externally declared intent/config pin for
    this arm, frozen before any heldout input is read. It is never a result or
    artifact hash and is never copied into legacy `ExposureReceipt`.
    """
    schema_version: Literal["m4-input-exposure-v1"] = "m4-input-exposure-v1"
    event: Literal["pre_access_input_exposure"] = "pre_access_input_exposure"
    run_id: Identity
    edition_id: Identity
    authority_sha256: Digest
    seal_sha256: Digest
    build_sha256: Digest
    oracle_sha256: Digest
    arm: Literal["D", "L", "P", "M", "C", "C-custom", "T"]
    measurement_intents_sha256: Digest
    state: Literal["consumed_holdout"] = "consumed_holdout"
    custodian: Identity
    committed_at: AwareDatetime
    durable_receipt_id: Identity
    committed_before_access_attested: Literal[True]


class CommitEnvelope(Record):
    schema_version: Literal["m4-input-exposure-commit-v1"] = "m4-input-exposure-commit-v1"
    commit_id: Identity
    authorization_sha256: Digest
    authorization: ExposureCommitAuthorization
    run_id: Identity
    edition_id: Identity
    run_manifest_sha256: Digest
    source_root_sha256: Digest
    authority_sha256: Digest
    seal_sha256: Digest
    policy_sha256: Digest
    semantic_suite_sha256: Digest
    eligibility_sha256: Digest
    build_sha256: Digest
    oracle_sha256: Digest
    inventory_sha256: Digest
    prompt_sha256: Digest
    rubric_sha256: Digest
    arm_inventory_sha256: Digest
    receipt_file_sha256: Digest
    receipts: tuple[InputExposureReceipt, ...] = Field(min_length=7, max_length=7)


class InputExposureCommit(Record):
    """Verified committed pre-access record. Grants no input/oracle/scoring permission."""
    schema_version: Literal["m4-input-exposure-commit-v1"] = "m4-input-exposure-commit-v1"
    state: Literal["CONSUMED_HOLDOUT_INPUT"]
    commit_sha256: Digest
    receipt_file_sha256: Digest
    authorization: ExposureCommitAuthorization
    receipts: tuple[InputExposureReceipt, ...] = Field(min_length=7, max_length=7)
    payload_permission_granted: Literal[False] = False
    oracle_permission_granted: Literal[False] = False
    scoring_permission_granted: Literal[False] = False
    authorship_authenticated: Literal[False] = False
    product_acceptance: Literal[False] = False


class ExposureJournalStatus(Record):
    state: Literal["UNCONSUMED", "COMMITTED", "BLOCKED", "ABSENT"]
    reason_code: str
    commit_sha256: Digest | None = None
    receipt_file_sha256: Digest | None = None
    exposed_arms: tuple[str, ...] = ()
    payload_permission_granted: Literal[False] = False


def _strict_json(raw: bytes):
    if len(raw) > MAX_LEDGER_BYTES:
        raise ValueError("exposure journal exceeds byte limit")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate exposure journal key")
            result[key] = value
        return result
    def invalid(_value):
        raise ValueError("nonfinite exposure journal JSON")
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def _canonical_bytes(value: dict | list) -> bytes:
    return (canonical(value) + "\n").encode("utf-8")


def _safe_path(path: Path) -> None:
    absolute = path.absolute()
    for item in (absolute, *absolute.parents):
        if item.is_symlink() or (hasattr(item, "is_junction") and item.is_junction()):
            raise ValueError("exposure journal symlink/junction path forbidden")


@contextmanager
def _exclusive_lock(path: Path):
    """Kernel-released nonblocking lock; never stale-lock break or force-unlock."""
    _safe_path(path)
    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    stream = os.fdopen(fd, "r+b", buffering=0)
    acquired = False
    try:
        if os.fstat(stream.fileno()).st_size == 0:
            stream.write(b"\0")
            os.fsync(stream.fileno())
        stream.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            acquired = True
        except OSError as error:
            raise ValueError("exposure journal already locked; edition blocked") from error
        yield
    finally:
        if acquired:
            if os.name == "nt":
                import msvcrt
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
        stream.close()


def _append_durable(path: Path, event: dict) -> bytes:
    _safe_path(path)
    data = _canonical_bytes(event)
    if len(data) > MAX_RECEIPT_BYTES:
        raise ValueError("exposure commit record exceeds byte limit")
    flags = os.O_CREAT | os.O_APPEND | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short exposure journal append")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    _fsync_directory(path.parent)
    return data


def _write_exclusive_durable(path: Path, data: bytes) -> None:
    _safe_path(path)
    if len(data) > MAX_RECEIPT_BYTES:
        raise ValueError("exposure receipt file exceeds byte limit")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short exposure receipt write")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    _fsync_directory(path.parent)


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _read_bytes(path: Path, maximum: int) -> bytes:
    _safe_path(path)
    if not path.is_file() or path.stat().st_size > maximum:
        raise ValueError("bounded regular exposure journal file required")
    with path.open("rb") as stream:
        raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError("exposure journal file grew beyond limit")
    return raw


def _authorize(root: Path, manifest: RunManifest, pins: PreflightPins,
               authorization: ExposureCommitAuthorization,
               expected_authorization_sha256: str, *,
               allow_consumed: bool = False) -> tuple[CustodyAuthority, Seal, dict]:
    if metadata_digest(authorization) != expected_authorization_sha256:
        raise ValueError("external exposure authorization pin mismatch")
    allowed_states = {"sealed", "consumed_holdout"} if allow_consumed else {"sealed"}
    if (manifest.stage != "evaluation" or manifest.split != "heldout"
            or manifest.edition_state not in allowed_states
            or manifest.run_id != authorization.run_id
            or manifest.edition_id != authorization.edition_id
            or (not allow_consumed
                and pins.run_manifest_sha256 != authorization.run_manifest_sha256)
            or pins.authority_sha256 != authorization.authority_sha256
            or pins.semantic_suite_sha256 != authorization.semantic_suite_sha256
            or pins.eligibility_sha256 != authorization.eligibility_sha256
            or root_digest(root) != authorization.source_root_sha256
            or manifest.build_sha256 != authorization.build_sha256
            or manifest.policy_sha256 != authorization.policy_sha256
            or set(authorization.measurement_intents_sha256) != set(ARMS)):
        raise ValueError("frozen exposure run/root/build/intent pins mismatch")
    status = preflight(root, manifest, pins)
    expected_state = "consumed_holdout" if manifest.edition_state == "consumed_holdout" else "sealed"
    if (status.get("metadata_status") != "CONSISTENT"
            or status.get("payloads_opened") != 0
            or status.get("edition_state") != expected_state):
        raise ValueError("metadata-only frozen preflight state mismatch")
    metadata = {ref.role: ref for ref in manifest.artifacts
                if ref.role in {"authority", "seal", "semantic_receipt"}}
    if not {"authority", "seal", "semantic_receipt"} <= set(metadata):
        raise ValueError("custody seal and semantic metadata must be pinned")
    from eval.runner.preflight import read_metadata
    authority = CustodyAuthority.model_validate_json(json.dumps(
        read_metadata(root, metadata["authority"]), allow_nan=False))
    seal = Seal.model_validate_json(json.dumps(
        read_metadata(root, metadata["seal"]), allow_nan=False))
    semantic = SemanticReceipt.model_validate_json(json.dumps(
        read_metadata(root, metadata["semantic_receipt"]), allow_nan=False))
    validate_seal(authority, seal, pins.authority_sha256)
    validate_semantics(authority, semantic, pins.authority_sha256, pins.semantic_suite_sha256)
    if (metadata_digest(seal) != authorization.seal_sha256
            or authority.edition_id != authorization.edition_id
            or authority.frozen_build_sha256 != authorization.build_sha256
            or authority.oracle_sha256 != authorization.oracle_sha256):
        raise ValueError("frozen custody seal/build identity mismatch")
    if (authority.inventory_sha256 != authorization.inventory_sha256
            or authority.prompt_sha256 != authorization.prompt_sha256
            or authority.rubric_sha256 != authorization.rubric_sha256
            or authority.policy_sha256 != authorization.policy_sha256
            or authority.custodian != authorization.custodian
            or next((row.sha256 for row in manifest.components if row.kind == "prompt"), None)
               != authorization.prompt_sha256
            or arm_inventory_digest(manifest) != authorization.arm_inventory_sha256):
        raise ValueError("frozen inventory/prompt/rubric/arm authorization mismatch")
    return authority, seal, status


def _receipt_bytes(receipts: tuple[InputExposureReceipt, ...]) -> bytes:
    return _canonical_bytes([row.model_dump(mode="json") for row in receipts])


def _parse_receipts(raw: bytes) -> tuple[InputExposureReceipt, ...]:
    values = _strict_json(raw)
    if type(values) is not list or len(values) != len(ARMS):
        raise ValueError("all seven input-exposure receipts required")
    if any(type(row) is not dict or row.get("schema_version") != INPUT_EXPOSURE_SCHEMA
           for row in values):
        raise ValueError("unversioned or legacy exposure receipt refused")
    receipts = tuple(InputExposureReceipt.model_validate_json(json.dumps(row, allow_nan=False))
                     for row in values)
    if ({row.arm for row in receipts} != set(ARMS)
            or len({row.durable_receipt_id for row in receipts}) != len(receipts)):
        raise ValueError("exposure arm inventory is incomplete or duplicated")
    return receipts


def _ledger_events(raw: bytes) -> list[dict]:
    if not raw.endswith(b"\n"):
        raise ValueError("torn exposure ledger line")
    lines = raw.splitlines()
    if not 1 <= len(lines) <= 2:
        raise ValueError("ambiguous exposure ledger event count")
    events = [_strict_json(line) for line in lines]
    if any(type(row) is not dict for row in events):
        raise ValueError("invalid exposure ledger event")
    return events


def _receipt_set_matches(envelope: CommitEnvelope) -> bool:
    receipts = envelope.receipts
    return (
        {row.arm for row in receipts} == set(ARMS)
        and len({row.durable_receipt_id for row in receipts}) == len(ARMS)
        and len({row.committed_at for row in receipts}) == 1
        and all(row.committed_before_access_attested is True
            and row.schema_version == INPUT_EXPOSURE_SCHEMA
            and row.state == "consumed_holdout"
            and row.run_id == envelope.run_id
            and row.edition_id == envelope.edition_id
            and row.authority_sha256 == envelope.authority_sha256
            and row.seal_sha256 == envelope.seal_sha256
            and row.build_sha256 == envelope.build_sha256
            and row.oracle_sha256 == envelope.oracle_sha256
            and row.custodian == envelope.authorization.custodian
            and row.measurement_intents_sha256
                == envelope.authorization.measurement_intents_sha256.get(row.arm)
            for row in receipts)
    )


def _verify_committed(root: Path, expected_authorization_sha256: str,
                      expected_commit_sha256: str | None = None) -> InputExposureCommit:
    ledger = root / LEDGER_RELATIVE
    receipt_path = root / RECEIPTS_RELATIVE
    raw = _read_bytes(ledger, MAX_LEDGER_BYTES)
    events = _ledger_events(raw)
    if (len(events) != 2
            or set(events[0]) != {"event", "commit_sha256", "commit"}
            or set(events[1]) != {"event", "commit_sha256", "receipt_file_sha256"}
            or events[0].get("event") != "prepared"
            or events[1].get("event") != "committed"):
        raise ValueError("exposure commit is incomplete or ambiguous")
    envelope = CommitEnvelope.model_validate_json(json.dumps(events[0].get("commit"), allow_nan=False))
    commit_sha = metadata_digest(envelope)
    if (events[0].get("commit_sha256") != commit_sha
            or events[1].get("commit_sha256") != commit_sha
            or envelope.authorization_sha256 != expected_authorization_sha256
            or (expected_commit_sha256 is not None and expected_commit_sha256 != commit_sha)):
        raise ValueError("exposure commit authorization/hash conflict")
    if (metadata_digest(envelope.authorization) != envelope.authorization_sha256
            or any(getattr(envelope, name) != getattr(envelope.authorization, name)
                   for name in ("run_id", "edition_id", "run_manifest_sha256",
                       "source_root_sha256", "authority_sha256", "seal_sha256",
                       "policy_sha256", "semantic_suite_sha256", "eligibility_sha256",
                       "build_sha256", "oracle_sha256", "inventory_sha256", "prompt_sha256",
                       "rubric_sha256", "arm_inventory_sha256"))):
        raise ValueError("durable commit envelope differs from frozen authorization")
    if not _receipt_set_matches(envelope):
        raise ValueError("receipt set differs from frozen commit pins")
    receipt_raw = _read_bytes(receipt_path, MAX_RECEIPT_BYTES)
    if (hashlib.sha256(receipt_raw).hexdigest() != envelope.receipt_file_sha256
            or events[1].get("receipt_file_sha256") != envelope.receipt_file_sha256
            or receipt_raw != _receipt_bytes(envelope.receipts)
            or _parse_receipts(receipt_raw) != envelope.receipts):
        raise ValueError("exposure receipt readback does not match committed bytes")
    return InputExposureCommit(state="CONSUMED_HOLDOUT_INPUT", commit_sha256=commit_sha,
                               receipt_file_sha256=envelope.receipt_file_sha256,
                               authorization=envelope.authorization,
                               receipts=envelope.receipts)


def commit_exposure(root: Path, manifest: RunManifest, pins: PreflightPins,
                    authorization: ExposureCommitAuthorization, *,
                    expected_authorization_sha256: str) -> InputExposureCommit:
    """Durably commit all seven pre-access input-exposure receipts before any input read.

    This function does not return file bytes, paths to payloads, or permission.
    Exact replay returns the already committed receipts. Any partial, torn, or
    conflicting state fails closed and is never overwritten or unconsumed.
    """
    root = root.absolute()
    _safe_path(root)
    if os.name == "nt" and str(root).startswith("\\\\"):
        raise ValueError("local exposure journal root required")
    authority, seal, _status = _authorize(root, manifest, pins, authorization,
                                           expected_authorization_sha256)
    ledger, receipt_path = root / LEDGER_RELATIVE, root / RECEIPTS_RELATIVE
    lock_path = root / LOCK_RELATIVE
    if any(os.path.lexists(root / path) for path in LEGACY_WIP_RELATIVE):
        raise ValueError("legacy WIP exposure journal present; edition blocked")
    with _exclusive_lock(lock_path):
        if os.path.lexists(ledger) or os.path.lexists(receipt_path):
            return _verify_committed(root, expected_authorization_sha256)
        if os.path.lexists(root / POST_MEASUREMENT_RELATIVE):
            raise ValueError("post-measurement exposure precedes pre-access commit; edition blocked")
        if not ledger.parent.is_dir() or not receipt_path.parent.is_dir():
            raise ValueError("pre-existing metadata directory required")
        commit_id = uuid4().hex
        now = datetime.now(timezone.utc)
        if now < seal.sealed_at:
            raise ValueError("input exposure cannot precede the custody seal")
        # Pre-access intents only; no legacy ExposureReceipt is constructed here.
        receipts = tuple(InputExposureReceipt(
            run_id=authorization.run_id,
            edition_id=authority.edition_id, authority_sha256=pins.authority_sha256,
            seal_sha256=metadata_digest(seal), build_sha256=authority.frozen_build_sha256,
            oracle_sha256=authority.oracle_sha256, arm=arm,
            measurement_intents_sha256=authorization.measurement_intents_sha256[arm],
            custodian=authority.custodian, committed_at=now,
            durable_receipt_id=uuid4().hex, committed_before_access_attested=True)
            for arm in ARMS)
        receipt_raw = _receipt_bytes(receipts)
        envelope = CommitEnvelope(
            commit_id=commit_id, authorization_sha256=expected_authorization_sha256,
            authorization=authorization,
            run_id=authorization.run_id, edition_id=authorization.edition_id,
            run_manifest_sha256=authorization.run_manifest_sha256,
            source_root_sha256=authorization.source_root_sha256,
            authority_sha256=authorization.authority_sha256,
            seal_sha256=authorization.seal_sha256,
            policy_sha256=authorization.policy_sha256,
            semantic_suite_sha256=authorization.semantic_suite_sha256,
            eligibility_sha256=authorization.eligibility_sha256,
            build_sha256=authorization.build_sha256,
            oracle_sha256=authorization.oracle_sha256,
            inventory_sha256=authorization.inventory_sha256,
            prompt_sha256=authorization.prompt_sha256,
            rubric_sha256=authorization.rubric_sha256,
            arm_inventory_sha256=authorization.arm_inventory_sha256,
            receipt_file_sha256=hashlib.sha256(receipt_raw).hexdigest(), receipts=receipts)
        commit_sha = metadata_digest(envelope)
        prepared_event = {"event": "prepared", "commit_sha256": commit_sha,
                          "commit": envelope.model_dump(mode="json")}
        prepared_bytes = _canonical_bytes(prepared_event)
        if len(prepared_bytes) > MAX_RECEIPT_BYTES:
            raise ValueError("prepared exposure event exceeds byte limit")
        _append_durable(ledger, prepared_event)
        if _read_bytes(ledger, MAX_LEDGER_BYTES) != prepared_bytes:
            raise ValueError("prepared exposure event readback mismatch")
        _write_exclusive_durable(receipt_path, receipt_raw)
        if _read_bytes(receipt_path, MAX_RECEIPT_BYTES) != receipt_raw:
            raise ValueError("exposure receipt readback mismatch")
        _append_durable(ledger, {"event": "committed", "commit_sha256": commit_sha,
                                 "receipt_file_sha256": envelope.receipt_file_sha256})
        return _verify_committed(root, expected_authorization_sha256, commit_sha)


def verify_committed_exposure(root: Path, manifest: RunManifest, pins: PreflightPins,
                              authorization: ExposureCommitAuthorization, *,
                              expected_authorization_sha256: str,
                              expected_commit_sha256: str) -> InputExposureCommit:
    """Narrow metadata-only D4 seam; must run before separate permission-gated reads.

    Returns the committed `InputExposureReceipt` rows. D4 compares each row's
    `measurement_intents_sha256` with its own `HeldoutAuthorization` intents. Success
    is never input, oracle or scoring permission.
    """
    authority, seal, _status = _authorize(root.absolute(), manifest, pins, authorization,
        expected_authorization_sha256, allow_consumed=True)
    result = _verify_committed(root.absolute(), expected_authorization_sha256,
                               expected_commit_sha256)
    if any(row.seal_sha256 != metadata_digest(seal)
           or row.authority_sha256 != pins.authority_sha256
           or row.custodian != authority.custodian
           or row.committed_at < seal.sealed_at for row in result.receipts):
        raise ValueError("committed receipt differs from current frozen custody metadata")
    return result


def exposure_status(root: Path, expected_authorization_sha256: str | None = None) -> ExposureJournalStatus:
    """Read-only payload-free status; it never repairs or completes a partial journal.

    A lock file alone is not a commit: the lock is created before any journal byte
    and is never removed, so its presence without a ledger/receipt means nothing
    was written (or a writer is in progress) and the edition is still UNCONSUMED.
    """
    _safe_path(root)
    ledger, receipts = root / LEDGER_RELATIVE, root / RECEIPTS_RELATIVE
    if any(os.path.lexists(root / path) for path in LEGACY_WIP_RELATIVE):
        return ExposureJournalStatus(state="BLOCKED", reason_code="legacy_wip_exposure_journal_present")
    if not os.path.lexists(ledger) and not os.path.lexists(receipts):
        return ExposureJournalStatus(state="UNCONSUMED", reason_code="no_exposure_commit")
    try:
        raw = _read_bytes(ledger, MAX_LEDGER_BYTES)
        events = _ledger_events(raw)
        if len(events) != 2:
            raise ValueError("incomplete_commit")
        envelope = CommitEnvelope.model_validate_json(json.dumps(events[0].get("commit"), allow_nan=False))
        if expected_authorization_sha256 is not None and envelope.authorization_sha256 != expected_authorization_sha256:
            raise ValueError("authorization_conflict")
        result = _verify_committed(root, envelope.authorization_sha256)
        return ExposureJournalStatus(state="COMMITTED", reason_code="all_seven_input_exposures_committed",
            commit_sha256=result.commit_sha256, receipt_file_sha256=result.receipt_file_sha256,
            exposed_arms=tuple(row.arm for row in result.receipts))
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        return ExposureJournalStatus(state="BLOCKED", reason_code="incomplete_or_ambiguous_commit")
