"""Fixed future frozen-heldout journey SOURCE; no automatic consumption or scoring.

Actual D6 committed exposure AND independent explicit payload permission precede
one in-memory input snapshot. Reuses the existing coordinator, transport and runner.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from iac_review.attempts import AttemptJournal
from iac_review.contracts.manifest import Digest, ManifestWire, RunManifest
from eval.model.experiment import canonical, digest
from eval.runner.benchmark import (ApprovedScanner, BenchmarkConfig, BenchmarkResult,
    FIXED_ARMS, SyntheticAuthority, benchmark_config_digest, coordinate, source_build_digest)
from eval.runner.benchmark_access import (INPUT_ACCESS_STATES, GuardedCaseReader, HeldoutAuthorization,
    arm_inventory_digest, authorize_heldout_access)
from eval.runner.bundle import root_digest
from eval.runner.custody import metadata_digest
from eval.runner.exposure_journal import (ExposureCommitAuthorization, InputExposureCommit,
    InputExposureReceipt, verify_committed_exposure)
from eval.runner.preflight import PreflightPins
from eval.runner.scoring import EligibilityManifest, record_digest


class FrozenRunPins(ManifestWire):
    """External frozen metadata selection; never labels, payloads or live evidence."""
    source_root_sha256: Digest
    run_manifest_sha256: Digest
    configuration_sha256: Digest
    config_file_sha256: Digest
    access_authorization_sha256: Digest
    exposure_authorization_sha256: Digest
    exposure_commit_sha256: Digest
    execution_authority_sha256: Digest
    build_sha256: Digest
    prompt_sha256: Digest
    rubric_sha256: Digest
    arm_inventory_sha256: Digest
    case_records_sha256: Digest


@dataclass(frozen=True)
class FrozenRuntime:
    """Explicit owner-injected actual objects; no CLI import/controller/key loader."""
    root: Path
    config: BenchmarkConfig
    manifest: RunManifest
    preflight_pins: PreflightPins
    access_permission: HeldoutAuthorization
    exposure_authorization: ExposureCommitAuthorization
    execution_authority: SyntheticAuthority
    journal: AttemptJournal = field(repr=False)
    transport: object = field(repr=False)
    scanners: dict[str, ApprovedScanner] = field(repr=False)
    access_event_path: Path
    # Optional EXTERNALLY pinned scanner execution eligibility (EligibilityManifest, pin).
    # Never derived from this run. Absent: heldout scanner arms stay
    # scanner_admission_incomplete (fail closed). Not part of FrozenRunPins, so existing
    # selection digests are unchanged; it is bound by its own pin and the edition.
    heldout_scanner_eligibility: tuple[EligibilityManifest, str] | None = field(default=None, repr=False)


@dataclass(frozen=True)
class FrozenRunResult:
    status: str
    benchmark: BenchmarkResult | None = field(repr=False)
    private_outcome_json: str = field(repr=False)
    outcome_sha256: str
    public_summary_json: str


def case_records_digest(config: BenchmarkConfig) -> str:
    return digest(canonical([{"case_id": case.case_id, "raw_input_sha256": case.plan_sha256,
                             "case_record_sha256": case.case_record_sha256} for case in config.cases]))


def _selection(runtime: FrozenRuntime, pins: FrozenRunPins, expected_pin: str):
    if (type(runtime) is not FrozenRuntime or type(pins) is not FrozenRunPins
            or metadata_digest(pins) != expected_pin or type(runtime.journal) is not AttemptJournal
            or runtime.config.input_scope != "heldout" or runtime.config.fake_only is not False
            # S1.6: sealed is allowed only because the access gate then requires the
            # committed input-exposure journal; it is never oracle/scoring permission.
            or runtime.manifest.split != "heldout"
            or runtime.manifest.edition_state not in INPUT_ACCESS_STATES
            or runtime.manifest.run_id != runtime.config.run_id
            or any(case.case_record_sha256 is None for case in runtime.config.cases)):
        raise ValueError("exact_frozen_external_selection_required")
    expected = {"source_root_sha256": root_digest(runtime.root),
        "run_manifest_sha256": metadata_digest(runtime.manifest),
        "configuration_sha256": benchmark_config_digest(runtime.config),
        "access_authorization_sha256": metadata_digest(runtime.access_permission),
        "exposure_authorization_sha256": metadata_digest(runtime.exposure_authorization),
        "execution_authority_sha256": runtime.execution_authority.approved_bytes_sha256,
        "build_sha256": runtime.config.build_sha256,
        "prompt_sha256": runtime.access_permission.prompt_sha256,
        "rubric_sha256": runtime.access_permission.rubric_sha256,
        "arm_inventory_sha256": arm_inventory_digest(runtime.manifest),
        "case_records_sha256": case_records_digest(runtime.config)}
    if (any(getattr(pins, key) != value for key, value in expected.items())
            or pins.run_manifest_sha256 != runtime.preflight_pins.run_manifest_sha256
            or pins.build_sha256 != source_build_digest()):
        raise ValueError("frozen_selection_metadata_or_source_mismatch")
    check_scanner_eligibility(runtime.heldout_scanner_eligibility, runtime.config.edition_id)


def check_scanner_eligibility(eligibility, edition_id: str) -> None:
    """None is allowed (fail-closed scanner arms); otherwise exact typed record, own pin, edition."""
    if eligibility is not None and (
            not isinstance(eligibility, tuple) or len(eligibility) != 2
            or type(eligibility[0]) is not EligibilityManifest or not isinstance(eligibility[1], str)
            or record_digest(eligibility[0]) != eligibility[1]
            or eligibility[0].edition_id != edition_id):
        raise ValueError("exact_external_heldout_scanner_eligibility_pin_required")


def run_frozen(runtime: FrozenRuntime, pins: FrozenRunPins, *, expected_pins_sha256: str) -> FrozenRunResult:
    """Future explicitly granted call. No gold read, relabeling, copies or second engine.

    Failed admission is a complete seven-arm NOT_RUN disposition, preserving the
    actual shared journal snapshot. It never starts a scanner/provider as fallback.
    """
    if type(runtime) is not FrozenRuntime or type(pins) is not FrozenRunPins:
        raise ValueError("actual_frozen_runtime_and_selection_required")
    benchmark, reason = None, None
    try:
        _selection(runtime, pins, expected_pins_sha256)
        # Contract S1: D6's PRE-ACCESS InputExposureCommit binds per-arm measurement
        # intents. It is not payload/oracle/scoring permission; the access gate
        # below re-verifies it on every read and adds the independent permission.
        commit = verify_committed_exposure(runtime.root, runtime.manifest, runtime.preflight_pins,
            runtime.exposure_authorization, expected_authorization_sha256=pins.exposure_authorization_sha256,
            expected_commit_sha256=pins.exposure_commit_sha256)
        permission = runtime.access_permission
        if (type(commit) is not InputExposureCommit or commit.payload_permission_granted is not False
                or commit.commit_sha256 != permission.input_exposure_commit_sha256
                or commit.receipt_file_sha256 != permission.input_exposure_receipt_file_sha256
                or pins.exposure_authorization_sha256 != permission.input_exposure_authorization_sha256
                or {row.arm for row in commit.receipts} != set(FIXED_ARMS)
                or any(type(row) is not InputExposureReceipt
                       or row.measurement_intents_sha256 != permission.measurement_intents_sha256[row.arm]
                       for row in commit.receipts)):
            raise ValueError("committed_input_exposure_permission_mismatch")
        accessor = authorize_heldout_access(runtime.root, runtime.manifest, runtime.preflight_pins,
            permission, expected_permission_sha256=pins.access_authorization_sha256,
            event_path=runtime.access_event_path, exposure_authorization=runtime.exposure_authorization)
        reader = GuardedCaseReader(accessor)
        benchmark = coordinate(runtime.config, journal=runtime.journal, transport=runtime.transport,
            manifest_context=runtime.manifest, expected_manifest_context_sha256=pins.run_manifest_sha256,
            build_verifier=source_build_digest, operator_config_sha256=pins.config_file_sha256,
            execution_mode="frozen_heldout", execution_authority=runtime.execution_authority,
            approved_scanners=runtime.scanners, _frozen_reader=reader,
            heldout_scanner_eligibility=runtime.heldout_scanner_eligibility)
    except (ValueError, OSError, TypeError, KeyError, RuntimeError, KeyboardInterrupt):
        reason = "frozen_admission_or_execution_incomplete"
    try:
        snapshot = AttemptJournal.snapshot(runtime.journal.path)
    except (ValueError, OSError):
        snapshot = {"snapshot_unavailable": True, "summary": runtime.journal.summary(),
                    "all_attempts_retained": False}
    statuses = ([{"case_id": row.case_id, "arm": row.arm, "status": row.status, "reason_code": row.reason_code}
                 for row in benchmark.statuses] if benchmark is not None else
                [{"case_id": case.case_id, "arm": arm, "status": "not_run", "reason_code": reason}
                 for case in runtime.config.cases for arm in FIXED_ARMS])
    outcome = {"schema_version": "m4-frozen-run-outcome-v1", "run_id": runtime.config.run_id,
        "split": "heldout", "frozen_selection_sha256": expected_pins_sha256,
        "run_manifest_sha256": pins.run_manifest_sha256, "exposure_commit_sha256": pins.exposure_commit_sha256,
        "access_authorization_sha256": pins.access_authorization_sha256,
        "case_records_sha256": pins.case_records_sha256, "build_sha256": pins.build_sha256,
        "prompt_sha256": pins.prompt_sha256, "rubric_sha256": pins.rubric_sha256,
        "arm_inventory_sha256": pins.arm_inventory_sha256,
        "statuses": statuses, "journal_snapshot": snapshot,
        "benchmark_provenance_json": benchmark.private_provenance_json if benchmark else None,
        "manifest_candidate_json": benchmark.manifest_candidate_json if benchmark else None,
        "rows": [row.model_dump(mode="json") for row in benchmark.rows] if benchmark else [],
        "heldout_scanner_eligibility_sha256": (runtime.heldout_scanner_eligibility[1]
                                               if runtime.heldout_scanner_eligibility is not None else None),
        "live_eligible": False, "product_acceptance": False, "oracle_opened": False,
        "missing": ([reason] if reason else ["external_execution_eligibility_and_scoring_required"])
                   + (["heldout_scanner_eligibility_absent"] if runtime.heldout_scanner_eligibility is None else [])}
    raw = canonical(outcome)
    public = canonical({"schema_version": "m4-frozen-run-summary-v1", "run_id": runtime.config.run_id,
        "split": "heldout", "status": "INCOMPLETE", "required_arms": list(FIXED_ARMS),
        "case_count": len(runtime.config.cases), "statuses": statuses, "oracle_opened": False,
        "measurement_status": "NOT_MEASURED", "product_acceptance": False})
    return FrozenRunResult("INCOMPLETE", benchmark, raw, digest(raw), public)
