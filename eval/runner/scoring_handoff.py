"""Post-run scoring handoff SOURCE (contract S1 item 4); never opens the oracle.

Turns one frozen-run private outcome into: (1) the immutable measured-results file
(LF-terminated canonical ArmRow JSONL, every row kept, including failed/unknown);
(2) a pinned `ScoringHandoff` inventory of every required case x arm status, error
and unknown state plus the cumulative journal accounting; (3) the seven legacy
post-measurement, pre-oracle `custody.ExposureReceipt` rows whose
`measurements_sha256` is the ACTUAL measured-results file hash. Oracle access then
happens only through the separately authorized `scripts/eval.py` path, which checks
these pins before decoding the oracle.

A committed pre-access input-exposure record (D6) is never scoring permission, and
nothing here is a favorable-score gate: incomplete arms stay INCOMPLETE. Source only
under Dirty Mode; nothing here was imported or run.
"""
from __future__ import annotations

from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
from typing import Literal

from pydantic import Field

from eval.runner.custody import (CustodyAuthority, Digest, ExposureReceipt, Identity, Seal,
                                 metadata_digest, validate_exposure)
from eval.runner.scoring import ARMS, ArmRow, Record

HANDOFF_SCHEMA = "m4-scoring-handoff-v1"
OUTCOME_SCHEMA = "m4-frozen-run-outcome-v1"
MAX_OUTCOME_BYTES = 64 * 1024 * 1024
MAX_ROWS = 100_000
MEASUREMENTS_NAME = "measurements.jsonl"
HANDOFF_NAME = "scoring-handoff.json"
RECEIPTS_NAME = "exposure-receipts.json"
# An arm/case is complete for scoring only with a genuinely recorded status.
COMPLETE_STATUSES = {"ok"}


class ArmCaseStatus(Record):
    case_id: Identity
    arm: Literal["D", "L", "P", "M", "C", "C-custom", "T"]
    status: Identity
    reason_code: Identity | None


class ScoringHandoff(Record):
    """Immutable post-run pins. Grants no oracle or scoring permission by itself."""
    schema_version: Literal["m4-scoring-handoff-v1"] = HANDOFF_SCHEMA
    run_id: Identity
    edition_id: Identity
    split: Literal["heldout"] = "heldout"
    frozen_outcome_sha256: Digest
    frozen_selection_sha256: Digest
    run_manifest_sha256: Digest
    input_exposure_commit_sha256: Digest
    access_authorization_sha256: Digest
    build_sha256: Digest
    case_records_sha256: Digest
    # ACTUAL measured-results file hash; becomes legacy ExposureReceipt.measurements_sha256.
    measurements_sha256: Digest
    measured_row_count: int = Field(ge=0, le=MAX_ROWS)
    case_count: int = Field(ge=1, le=256)
    statuses: tuple[ArmCaseStatus, ...] = Field(min_length=7, max_length=7 * 256)
    incomplete_arms: tuple[str, ...]
    missing: tuple[str, ...]
    journal_summary_json: str = Field(max_length=1024 * 1024)
    # Exact cumulative journal identity and unresolved state (all attempts stay in the
    # pinned frozen outcome; nothing is dropped or re-summed here).
    journal_sha256: Digest | None
    reservation_overrun: bool
    unresolved_attempts: int = Field(ge=0)
    all_attempts_retained: bool
    # v2 execution eligibility is external; its absence keeps every arm incomplete.
    eligibility_status: Literal["EXTERNAL_V2_ELIGIBILITY_REQUIRED"] = "EXTERNAL_V2_ELIGIBILITY_REQUIRED"
    oracle_opened: Literal[False] = False
    scoring_permission_granted: Literal[False] = False
    product_acceptance: Literal[False] = False


def _strict(raw: bytes):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate frozen outcome key")
            result[key] = value
        return result

    def constant(_value):
        raise ValueError("nonfinite frozen outcome value")
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def _canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def measured_results_bytes(rows: list) -> bytes:
    """Every row, strictly re-validated, in original order; nothing filtered or added."""
    if not isinstance(rows, list) or len(rows) > MAX_ROWS:
        raise ValueError("bounded measured row list required")
    lines = []
    for value in rows:
        row = ArmRow.model_validate_json(json.dumps(value, allow_nan=False))
        lines.append(_canonical(row.model_dump(mode="json")) + "\n")
    return "".join(lines).encode("utf-8")


def prepare_handoff(outcome_json: str, *, expected_outcome_sha256: str, edition_id: str,
                    input_commit) -> tuple[ScoringHandoff, bytes]:
    """Build pins from the exact frozen outcome; no oracle, label or payload read."""
    from eval.runner.exposure_journal import InputExposureCommit
    raw = outcome_json.encode("utf-8")
    if (len(raw) > MAX_OUTCOME_BYTES or hashlib.sha256(raw).hexdigest() != expected_outcome_sha256
            or type(input_commit) is not InputExposureCommit or input_commit.scoring_permission_granted is not False):
        raise ValueError("exact_frozen_outcome_and_committed_input_exposure_required")
    outcome = _strict(raw)
    if (not isinstance(outcome, dict) or outcome.get("schema_version") != OUTCOME_SCHEMA
            or outcome.get("split") != "heldout" or outcome.get("oracle_opened") is not False
            or outcome.get("product_acceptance") is not False
            or outcome.get("exposure_commit_sha256") != input_commit.commit_sha256
            or any(row.edition_id != edition_id or row.run_id != outcome.get("run_id")
                   for row in input_commit.receipts)):
        raise ValueError("frozen_outcome_profile_or_commit_mismatch")
    statuses = tuple(ArmCaseStatus.model_validate_json(json.dumps(row, allow_nan=False))
                     for row in outcome.get("statuses", ()))
    cases = sorted({row.case_id for row in statuses})
    pairs = [(row.case_id, row.arm) for row in statuses]
    # Full required inventory: every case has every arm exactly once (no silent drop).
    if (not cases or len(pairs) != len(set(pairs)) or len(pairs) != len(cases) * len(ARMS)
            or set(pairs) != {(case, arm) for case in cases for arm in ARMS}):
        raise ValueError("full_required_case_arm_inventory_missing")
    measurements = measured_results_bytes(outcome.get("rows", []))
    snapshot = outcome.get("journal_snapshot")
    if not isinstance(snapshot, dict) or not isinstance(snapshot.get("summary"), dict):
        raise ValueError("cumulative_journal_accounting_required")
    # Retained only with the actual read-only snapshot identity and attempt list.
    retained = (snapshot.get("snapshot_unavailable") is not True
                and snapshot.get("all_attempts_retained", True) is not False
                and isinstance(snapshot.get("journal_sha256"), str) and "attempts" in snapshot)
    attempts = snapshot.get("attempts", [])
    if not isinstance(attempts, list):
        raise ValueError("journal_attempt_inventory_invalid")
    # Interrupted attempts count as resolved only after explicit operator reconciliation.
    unresolved = sum(1 for row in attempts if not isinstance(row, dict)
                     or (row.get("status") == "interrupted" and row.get("reconciled") is not True)
                     or row.get("requires_reconciliation") is not False)
    overrun = snapshot.get("reservation_overrun") is not False
    journal_pin = snapshot.get("journal_sha256") if retained else None
    handoff_state = {"statuses": statuses, "all_attempts_retained": retained,
                     "reservation_overrun": overrun, "unresolved_attempts": unresolved}
    incomplete = tuple(sorted(required_incomplete_arms(**handoff_state), key=ARMS.index))
    missing = tuple(sorted({str(item) for item in outcome.get("missing", [])}
                           | ({"journal_snapshot_incomplete"} if not retained else set())
                           | ({"journal_reservation_overrun"} if overrun else set())
                           | ({"unresolved_or_interrupted_attempts"} if unresolved else set())
                           | {"external_v2_execution_eligibility_required"}))
    handoff = ScoringHandoff(run_id=outcome["run_id"], edition_id=edition_id,
        frozen_outcome_sha256=expected_outcome_sha256,
        frozen_selection_sha256=outcome["frozen_selection_sha256"],
        run_manifest_sha256=outcome["run_manifest_sha256"],
        input_exposure_commit_sha256=input_commit.commit_sha256,
        access_authorization_sha256=outcome["access_authorization_sha256"],
        build_sha256=outcome["build_sha256"], case_records_sha256=outcome["case_records_sha256"],
        measurements_sha256=hashlib.sha256(measurements).hexdigest(),
        measured_row_count=measurements.count(b"\n"), case_count=len(cases), statuses=statuses,
        incomplete_arms=incomplete, missing=missing,
        journal_summary_json=_canonical(snapshot["summary"]), journal_sha256=journal_pin,
        reservation_overrun=overrun, unresolved_attempts=unresolved, all_attempts_retained=retained)
    return handoff, measurements


def required_incomplete_arms(*, statuses, all_attempts_retained: bool, reservation_overrun: bool,
                             unresolved_attempts: int) -> set[str]:
    """Arms that MUST stay incomplete; recomputed at scoring, never trusted as written."""
    if not all_attempts_retained or reservation_overrun or unresolved_attempts:
        return set(ARMS)  # Lost/overrun/unresolved accounting: no arm is claimed complete.
    return {row.arm for row in statuses if row.status not in COMPLETE_STATUSES}


def post_measurement_receipts(handoff: ScoringHandoff, *, authority: CustodyAuthority, seal: Seal,
                              expected_authority_sha256: str, exposed_at: datetime,
                              receipt_ids: dict[str, str]) -> tuple[ExposureReceipt, ...]:
    """Seven legacy post-measurement, pre-ORACLE receipts with the actual results hash.

    `durable_before_access_attested` here means before ORACLE access (legacy meaning,
    unchanged). Receipt IDs come from the external custodian, never generated here.
    """
    if (type(handoff) is not ScoringHandoff or set(receipt_ids) != set(ARMS)
            or len(set(receipt_ids.values())) != len(ARMS)
            or handoff.build_sha256 != authority.frozen_build_sha256
            or handoff.edition_id != authority.edition_id):
        raise ValueError("exact_handoff_custody_and_receipt_identities_required")
    receipts = tuple(ExposureReceipt(edition_id=authority.edition_id,
        authority_sha256=expected_authority_sha256, seal_sha256=metadata_digest(seal),
        build_sha256=authority.frozen_build_sha256, oracle_sha256=authority.oracle_sha256,
        measurements_sha256=handoff.measurements_sha256, arm=arm, custodian=authority.custodian,
        exposed_at=exposed_at, durable_receipt_id=receipt_ids[arm], durable_before_access_attested=True)
        for arm in ARMS)
    validate_exposure(authority, seal, receipts, expected_authority_sha256)
    return receipts


def _write_new(path: Path, data: bytes) -> None:
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags, 0o600)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short scoring handoff write")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    with path.open("rb") as stream:
        if stream.read(len(data) + 1) != data:
            raise ValueError("scoring handoff readback mismatch")


def write_handoff(directory: Path, handoff: ScoringHandoff, measurements: bytes,
                  receipts: tuple[ExposureReceipt, ...]) -> dict:
    """Write once into a FRESH directory; never overwrite, repin or remove anything.

    Returns the pins the operator passes to `scripts/eval.py` (`--measurements`,
    `--scoring-handoff(-sha256)`, `--exposure-receipts`).
    """
    directory = directory.absolute()
    if (any(p.is_symlink() or (hasattr(p, "is_junction") and p.is_junction())
            for p in (directory, *directory.parents))
            or directory.exists() or not directory.parent.is_dir()):
        raise ValueError("fresh_handoff_directory_without_links_required")
    if (hashlib.sha256(measurements).hexdigest() != handoff.measurements_sha256
            or {row.arm for row in receipts} != set(ARMS) or len(receipts) != len(ARMS)
            or any(row.measurements_sha256 != handoff.measurements_sha256 for row in receipts)):
        raise ValueError("handoff_measurement_receipt_pin_mismatch")
    directory.mkdir(parents=False, exist_ok=False)
    handoff_bytes = (_canonical(handoff.model_dump(mode="json")) + "\n").encode("utf-8")
    receipt_bytes = (_canonical([row.model_dump(mode="json") for row in receipts]) + "\n").encode("utf-8")
    _write_new(directory / MEASUREMENTS_NAME, measurements)
    _write_new(directory / HANDOFF_NAME, handoff_bytes)
    _write_new(directory / RECEIPTS_NAME, receipt_bytes)
    return {"measurements_sha256": handoff.measurements_sha256,
            "scoring_handoff_sha256": metadata_digest(handoff),
            "exposure_receipts_file_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
            "oracle_opened": False, "scoring_permission_granted": False}


def check_handoff_for_scoring(handoff: ScoringHandoff, *, edition_id: str, build_sha256: str,
                              receipts: tuple[ExposureReceipt, ...], measurement_sha256: str,
                              measured: list[ArmRow]) -> dict:
    """Used by scripts/eval.py after measurement bytes are hashed, BEFORE oracle decode."""
    required = required_incomplete_arms(statuses=handoff.statuses,
        all_attempts_retained=handoff.all_attempts_retained,
        reservation_overrun=handoff.reservation_overrun,
        unresolved_attempts=handoff.unresolved_attempts) if type(handoff) is ScoringHandoff else None
    if (type(handoff) is not ScoringHandoff or handoff.edition_id != edition_id
            or handoff.build_sha256 != build_sha256
            or not required <= set(handoff.incomplete_arms)
            or handoff.measurements_sha256 != measurement_sha256
            or {row.arm for row in receipts} != set(ARMS) or len(receipts) != len(ARMS)
            or any(row.measurements_sha256 != measurement_sha256 for row in receipts)
            or len(measured) != handoff.measured_row_count
            or any(row.build_sha256 != handoff.build_sha256 for row in measured)):
        raise ValueError("scoring_handoff_pins_differ_from_measurements_or_receipts")
    return {"schema_version": HANDOFF_SCHEMA,
            "incomplete_arms": [arm for arm in ARMS if arm in required | set(handoff.incomplete_arms)],
            "missing": list(handoff.missing), "all_attempts_retained": handoff.all_attempts_retained,
            "journal_sha256": handoff.journal_sha256, "reservation_overrun": handoff.reservation_overrun,
            "unresolved_attempts": handoff.unresolved_attempts,
            "journal_summary": json.loads(handoff.journal_summary_json),
            "eligibility_status": handoff.eligibility_status}


def check_completion_reference(handoff: ScoringHandoff, completion, *,
                               expected_completion_sha256: str) -> dict:
    """End-to-end cross-check with D6's release `CompletionReference` (read-only).

    Where both records exist they must name the SAME pre-access input-exposure
    commit; otherwise scoring and release describe different runs. The completion
    type is D6-owned and only read here; nothing in it grants scoring permission.
    """
    from eval.runner.edition_release import CompletionReference  # Lazy, read-only D6 type.
    if (type(handoff) is not ScoringHandoff or type(completion) is not CompletionReference
            or not isinstance(expected_completion_sha256, str)
            or metadata_digest(completion) != expected_completion_sha256
            or completion.input_exposure_commit_sha256 != handoff.input_exposure_commit_sha256):
        raise ValueError("completion_reference_input_exposure_commit_mismatch")
    return {"completion_reference_sha256": expected_completion_sha256,
            "input_exposure_commit_sha256": completion.input_exposure_commit_sha256,
            "cross_checked": True}
