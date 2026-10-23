"""Target-aware scanner import; externally approved attestations, never self-pins.

No scanners, labels, source inputs, product detectors, writers or subprocesses.
Hashes establish identity, not truth of a supplied execution attestation.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, fields
import hashlib
import json
import math

from eval.runner.scoring import (ArmRow, EligibilityManifest, measurement_eligible,
                                 record_digest)
from .driver import ARMS, OPAQUE, RULES, ComparisonRow
from .runner import CHECK_ID, SHA256, Limits, ScanArtifact


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def report_digest(report: dict) -> str:
    """Canonical JSON digest. The trusted scope owner supplies the expected pin."""
    return hashlib.sha256(_canonical(report)).hexdigest()


def _hash(value: object) -> str:
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        raise ValueError("exact SHA256 required")
    return value


def _identity(value: object) -> str:
    if not isinstance(value, str) or not OPAQUE.fullmatch(value):
        raise ValueError("opaque identity required")
    return value


def _row(value: dict) -> ComparisonRow:
    if not isinstance(value, dict):
        raise ValueError("comparison row must be an object")
    row = ComparisonRow(**value)
    for identifier in (row.case_id, row.resource_id):
        _identity(identifier)
    for pin in (row.plan_sha256, row.capture_sha256):
        _hash(pin)
    if row.mapping_sha256 is not None:
        _hash(row.mapping_sha256)
    if (row.arm not in ARMS or row.rule_id not in RULES
            or row.comparison_target != "introduced_risk"
            or row.status not in {"recorded", "not_run", "unmapped", "invalid", "timeout",
                                   "error", "simulated"}
            or type(row.live_eligible) is not bool
            or (row.introduced_prediction is not None and type(row.introduced_prediction) is not bool)
            or not isinstance(row.reasons, (tuple, list))
            or any(not isinstance(reason, str) or not reason or len(reason) > 128
                   for reason in row.reasons)):
        raise ValueError("invalid comparison identity/target/status")
    return row


def _receipt(value: dict) -> tuple[str, str, ScanArtifact]:
    if not isinstance(value, dict):
        raise ValueError("capture receipt must be an object")
    expected = {item.name for item in fields(ScanArtifact)} - {"observations"}
    if set(value) != expected | {"case_id", "capture_sha256"}:
        raise ValueError("unknown or missing capture metadata field")
    case_id, capture_sha256 = _identity(value["case_id"]), _hash(value["capture_sha256"])
    payload = {key: value[key] for key in expected}
    if not isinstance(payload["check_ids"], (list, tuple)) or not isinstance(payload["reasons"], (list, tuple)):
        raise ValueError("capture check/reason arrays required")
    payload["check_ids"] = tuple(payload["check_ids"])
    payload["reasons"] = tuple(payload["reasons"])
    artifact = ScanArtifact(**payload)
    if (artifact.arm not in ARMS or artifact.execution_kind not in {"fake", "live", "none"}
            or artifact.status not in {"ok", "invalid", "timeout", "error", "not_run"}
            or artifact.scanner_name != ("trivy" if artifact.arm == "T" else "checkov")
            or artifact.source_enrichment is not False
            or type(artifact.output_truncated) is not bool
            or artifact.mapping_status not in {"verified", "unverified", "unmapped", "incompatible"}
            or any(not isinstance(reason, str) or not reason or len(reason) > 128
                   for reason in artifact.reasons)
            or (artifact.scanner_version is not None and (
                not isinstance(artifact.scanner_version, str)
                or not 0 < len(artifact.scanner_version) <= 256))
            or any(not isinstance(check, str) or not CHECK_ID.fullmatch(check)
                   for check in artifact.check_ids)
            or len(artifact.check_ids) != len(set(artifact.check_ids))):
        raise ValueError("invalid scanner capture profile")
    if artifact.raw_exit_code is not None and type(artifact.raw_exit_code) is not int:
        raise ValueError("invalid raw exit code")
    if artifact.elapsed_seconds is not None and (
            type(artifact.elapsed_seconds) not in {int, float}
            or not math.isfinite(artifact.elapsed_seconds) or artifact.elapsed_seconds < 0):
        raise ValueError("invalid measured duration")
    for name in ("plan_sha256", "executable_sha256", "dependency_manifest_sha256",
                 "version_evidence_sha256", "config_sha256", "invocation_sha256",
                 "policy_sha256", "stdout_sha256", "stderr_sha256"):
        if getattr(artifact, name) is not None:
            _hash(getattr(artifact, name))
    return case_id, capture_sha256, artifact


def measurement_ref(row: ComparisonRow) -> str:
    key = {name: getattr(row, name) for name in ("case_id", "resource_id", "rule_id", "arm",
                                               "plan_sha256", "capture_sha256", "mapping_sha256")}
    return "scanner:" + hashlib.sha256(_canonical(key)).hexdigest()


def provenance_digest(row: ComparisonRow, receipt: dict, build_sha256: str,
                      bounds: Limits = Limits()) -> str:
    """Digest for the external executor/authority to attest, not a proof issuer.

    Bounds are the producer's declared invocation profile. The adapter recorded
    its invocation digest; actual OS enforcement still requires runtime evidence.
    Capture's full-observation hash is retained; receipts intentionally omit raw
    locators so this bridge cannot independently reconstruct those observations.
    """
    return report_digest({"schema_version": "m4-scanner-provenance-v1",
                          "comparison": asdict(row), "capture": receipt,
                          "build_sha256": _hash(build_sha256), "declared_bounds": asdict(bounds)})


@dataclass(frozen=True)
class AttemptRecord:
    case_id: str
    arm: str
    capture_sha256: str
    status: str
    execution_kind: str
    metadata_json: str
    # Immutable canonical metadata retains all failures, raw hashes and bounds;
    # it contains no raw stdout/stderr, address map, plan or oracle labels.


@dataclass(frozen=True)
class Disposition:
    case_id: str
    resource_id: str
    rule_id: str
    arm: str
    measurement_ref: str
    provenance_sha256: str | None
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class BridgeBatch:
    rows: tuple[ArmRow, ...]
    dispositions: tuple[Disposition, ...]
    attempts: tuple[AttemptRecord, ...]
    source_report_sha256: str
    eligibility_manifest_sha256: str | None
    binary_schema_available: bool
    product_acceptance: bool = False


def bridge_report(report: dict, *, expected_report_sha256: str, edition_id: str,
                  eligibility: EligibilityManifest | None = None,
                  expected_eligibility_sha256: str | None = None,
                  bounds: Limits = Limits()) -> BridgeBatch:
    """Consume current driver output and D6 wires without changing shared sources.

    Expected pins must come from the trusted owner, not from the imported report.
    Absence of externally pinned execution eligibility leaves every row incomplete.
    Preserve failed attempts separately, including captures with no usable row.
    """
    raw = _canonical(report)
    if len(raw) > 64 * 1024 * 1024 or hashlib.sha256(raw).hexdigest() != _hash(expected_report_sha256):
        raise ValueError("scanner report does not match external source pin")
    # Isolate later iteration from caller mutation. Source JSON was already
    # strict-parsed by its producer; serialized non-finite values are forbidden.
    source = json.loads(raw)
    if (not isinstance(source, dict)
            or source.get("schema_version") != "m4-scanner-comparison-v1"
            or source.get("input_scope") != "development_synthetic"
            or source.get("source_enrichment") is not False
            or type(source.get("fake_only")) is not bool
            or source.get("product_acceptance") is not False):
        raise ValueError("unsupported scanner source scope/profile")
    build = _hash(source.get("build_sha256"))
    _identity(edition_id)
    manifest_pin = None
    if (eligibility is None) != (expected_eligibility_sha256 is None):
        raise ValueError("eligibility and its external pin must be supplied together")
    if eligibility is not None:
        manifest_pin = _hash(expected_eligibility_sha256)
        if record_digest(eligibility) != manifest_pin or eligibility.edition_id != edition_id:
            raise ValueError("execution eligibility lacks matching external edition approval")
        signatures = [(m.arm, m.measurement_ref, m.source_sha256, m.build_sha256)
                      for m in eligibility.rows]
        if len(signatures) != len(set(signatures)):
            raise ValueError("duplicate execution eligibility")
    values, receipts = source.get("rows"), source.get("capture_receipts")
    if (not isinstance(values, list) or not isinstance(receipts, list)
            or len(values) > 100_000 or len(receipts) > 100_000):
        raise ValueError("bounded scanner rows and attempts required")
    indexed, attempts = {}, []
    for receipt in receipts:
        case, capture_hash, artifact = _receipt(receipt)
        key = case, artifact.arm, capture_hash
        if key in indexed:
            raise ValueError("duplicate scanner attempt receipt")
        indexed[key] = receipt, artifact
        attempts.append(AttemptRecord(case, artifact.arm, capture_hash, artifact.status,
                                      artifact.execution_kind,
                                      _canonical({"capture": receipt,
                                                  "declared_bounds": asdict(bounds)}).decode("ascii")))
    binary_available = {"prediction_target", "introduced_prediction"} <= set(ArmRow.model_fields)
    result, dispositions, seen = [], [], set()
    for value in values:
        row = _row(value)
        identity = row.arm, row.case_id, row.resource_id, row.rule_id
        if identity in seen:
            raise ValueError("duplicate scanner comparison cell")
        seen.add(identity)
        reference, reasons = measurement_ref(row), list(row.reasons)
        receipt_pair = indexed.get((row.case_id, row.arm, row.capture_sha256))
        provenance = None
        kind, eligible_ref, executed = "unverified", None, False
        artifact = None
        if receipt_pair is None:
            reasons.append("missing_scanner_attempt_receipt")
        else:
            receipt, artifact = receipt_pair
            if artifact.plan_sha256 not in (None, row.plan_sha256):
                raise ValueError("row/capture plan identity mismatch")
            provenance = provenance_digest(row, receipt, build, bounds)
            if source["fake_only"] or artifact.execution_kind == "fake" or row.status == "simulated":
                kind = "mock"
                reasons.append("mock_cannot_be_execution_evidence")
            elif eligibility is not None:
                matching = [m for m in eligibility.rows if m.arm == row.arm
                            and m.measurement_ref == reference and m.source_sha256 == row.plan_sha256
                            and m.build_sha256 == build]
                if len(matching) == 1:
                    meta = matching[0]
                    pins = (artifact.plan_sha256, artifact.executable_sha256,
                            artifact.dependency_manifest_sha256, artifact.version_evidence_sha256,
                            artifact.config_sha256, artifact.invocation_sha256,
                            artifact.policy_sha256, artifact.stdout_sha256, artifact.stderr_sha256)
                    executed = (meta.kind == "executed" and meta.actual_execution_attested
                                and meta.provenance_sha256 == provenance
                                and artifact.execution_kind == "live"
                                and bool(artifact.scanner_version)
                                and all(isinstance(pin, str) and SHA256.fullmatch(pin) for pin in pins))
                    if executed:
                        kind, eligible_ref = "executed", record_digest(meta)
            if not executed and kind != "mock":
                reasons.append("missing_external_genuine_execution_eligibility")
        status = row.status if row.status in {"invalid", "timeout", "error", "unmapped"} else "not_run"
        success = (executed and binary_available and artifact is not None
                   and artifact.live_eligible and row.live_eligible
                   and row.status == "recorded" and type(row.introduced_prediction) is bool
                   and row.mapping_sha256 is not None and not row.reasons)
        if not binary_available:
            reasons.append("shared_binary_scorer_schema_pending")
        if success:
            status = "ok"
        elif row.status == "recorded":
            reasons.append("scanner_cell_incomplete")
        kwargs = dict(schema_version=2, measurement_kind=kind, eligibility_ref=eligible_ref,
                      case_id=row.case_id, resource_id=row.resource_id, rule_id=row.rule_id,
                      arm=row.arm, status=status, applicability="supported" if success else None,
                      outcome=None, reason_code="scanner_binary_target" if success else (
                          "scanner_mock_ineligible" if kind == "mock" else "scanner_source_incomplete"),
                      source_sha256=row.plan_sha256, build_sha256=build, measurement_ref=reference,
                      elapsed_seconds=artifact.elapsed_seconds if artifact is not None else None)
        if binary_available:
            kwargs.update(prediction_target="introduced_risk",
                          introduced_prediction=row.introduced_prediction if success else None)
        arm_row = ArmRow(**kwargs)
        if success and not measurement_eligible(arm_row, eligibility):
            raise ValueError("shared eligibility checker rejected scanner row")
        result.append(arm_row)
        dispositions.append(Disposition(row.case_id, row.resource_id, row.rule_id, row.arm,
                                        reference, provenance, tuple(sorted(set(reasons)))))
    return BridgeBatch(tuple(result), tuple(dispositions), tuple(attempts), expected_report_sha256,
                       manifest_pin, binary_available)
