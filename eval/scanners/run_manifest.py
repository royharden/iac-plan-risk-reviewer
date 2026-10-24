"""Metadata-only adapter to the actual shared typed RunManifest.

No payload/source/gold discovery, scanner execution or eligibility issuance.
Unknown required pins yield an explicit draft, never placeholder component hashes.
Two scopes: development_synthetic (dev split, unchanged) and guarded heldout. Heldout
admission requires the exact heldout scanner manifest (bound to the v2 input-access
permission pin) and the externally pinned eligibility (Amendment A1); otherwise it
refuses, which the coordinator records as scanner_admission_incomplete.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import re

from iac_review.contracts.manifest import (ArtifactRef, AttemptMetadata, CaseBinding,
    ComponentVersion, EvaluationEligibility, InvocationMetadata, RunManifest)
from eval.runner.scoring import EligibilityManifest, measurement_eligible
from .driver import ComparisonRow
from .runner import SHA256, Limits, _heldout_manifest, digest, manifest_digest, strict_json
from .scoring_bridge import BridgeBatch, _receipt, bridge_report, measurement_ref

OPAQUE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")


@dataclass(frozen=True)
class ScannerComponents:
    """Optional explicit known metadata for an arm that did not run.

    These are caller-supplied shared records, not fabricated unknown versions.
    Their presence does not establish execution or compatibility.
    """
    arm: str
    scanner: ComponentVersion
    config: ComponentVersion


@dataclass(frozen=True)
class ScannerRunContext:
    run_id: str
    edition_id: str
    policy_sha256: str | None = None
    authority_sha256: str | None = None
    semantic_suite_sha256: str | None = None
    cases: tuple[CaseBinding, ...] = ()
    artifacts: tuple[ArtifactRef, ...] = ()
    known_components: tuple[ScannerComponents, ...] = ()
    # Guarded heldout only (all three required together; absent for development).
    edition_state: str = "development"
    heldout_access_authorization_sha256: str | None = None
    heldout_scanner_manifest_json: str | None = None


@dataclass(frozen=True)
class ScannerManifestResult:
    manifest: RunManifest | None
    bridge: BridgeBatch
    missing: tuple[str, ...]
    # Safe count/status JSON only; no raw hashes, artifact/source paths or labels.
    public_summary_json: str


def _opaque(value: str) -> None:
    if not isinstance(value, str) or not OPAQUE.fullmatch(value):
        raise ValueError("opaque run/component identity required")


def _pin(value: str | None, label: str, missing: set[str]) -> None:
    if value is None:
        missing.add(label + "_missing")
    elif not isinstance(value, str) or not SHA256.fullmatch(value):
        raise ValueError("invalid manifest context digest")


def _component(kind: str, name: str, sha: str, *, version: str | None = None) -> ComponentVersion:
    # A content-addressed config/policy version is an identity, not a tested release.
    return ComponentVersion(component_id=name + "_" + sha, kind=kind, name=name,
                            version=version or "content_" + sha[:24], sha256=sha,
                            compatibility="unverified")


def _heldout_scope(source: dict, context: ScannerRunContext,
                   expected_eligibility_sha256: str | None) -> None:
    """Bind a heldout report to its exact guarded manifest, access pin and eligibility."""
    pin, raw = context.heldout_access_authorization_sha256, context.heldout_scanner_manifest_json
    if (pin is None or raw is None or expected_eligibility_sha256 is None
            or context.edition_state not in {"sealed", "consumed_holdout"}):
        raise ValueError("heldout scanner admission pins missing")
    if not isinstance(raw, str) or len(raw.encode()) > 2 * 1024 * 1024:
        raise ValueError("bounded heldout scanner manifest required")
    manifest = strict_json(raw.encode())
    if (not isinstance(manifest, dict) or not _heldout_manifest(manifest, pin)
            or manifest_digest(manifest) != source.get("manifest_sha256")
            or manifest.get("build_sha256") != source.get("build_sha256")
            or [(row.case_id, row.raw_source_sha256) for row in context.cases]
               != [(manifest["cases"][0].get("case_id"), manifest["cases"][0].get("plan_sha256"))]):
        raise ValueError("heldout report differs from its guarded manifest/access pin")


def adapt_scanner_report(report: dict, *, expected_report_sha256: str, context: ScannerRunContext,
                         eligibility: EligibilityManifest | None = None,
                         expected_eligibility_sha256: str | None = None,
                         bounds: Limits = Limits()) -> ScannerManifestResult:
    """Build private reproducibility metadata plus a separate payload-free summary.

    Callers own all external approval pins, ancestry and actual artifact references.
    This validates metadata joins; it neither reads referenced payloads nor verifies
    that a supplied authority/execution narrative is truthful.
    """
    _opaque(context.run_id)
    _opaque(context.edition_id)
    source = json.loads(json.dumps(report, allow_nan=False))
    bridge = bridge_report(source, expected_report_sha256=expected_report_sha256,
                           edition_id=context.edition_id, eligibility=eligibility,
                           expected_eligibility_sha256=expected_eligibility_sha256, bounds=bounds)
    heldout = source.get("input_scope") == "heldout"
    if heldout:
        _heldout_scope(source, context, expected_eligibility_sha256)
    elif (context.edition_state != "development" or context.heldout_access_authorization_sha256 is not None
            or context.heldout_scanner_manifest_json is not None):
        raise ValueError("development report cannot carry heldout context")
    split = "heldout" if heldout else "dev"
    missing: set[str] = set()
    for name, value in (("policy", context.policy_sha256), ("authority", context.authority_sha256),
                        ("semantic_suite", context.semantic_suite_sha256),
                        ("eligibility", expected_eligibility_sha256)):
        _pin(value, name, missing)
    cases = {row.case_id: row for row in context.cases}
    if len(cases) != len(context.cases) or any(row.split != split for row in context.cases):
        # Dev wording preserved for existing callers/tests; heldout gets its own label.
        raise ValueError(("unique heldout" if heldout else "unique development-only")
                         + " typed case bindings of the report scope required")
    artifacts, paths, artifact_ids = {}, set(), set()
    for artifact in context.artifacts:
        if (artifact.visibility != "private" or not artifact.path.startswith("private/")
                or artifact.role in {"oracle", "private_map", "report_shareable"}
                or artifact.path in paths or artifact.artifact_id in artifact_ids):
            raise ValueError("unique private metadata references only; no hidden/public payload references")
        paths.add(artifact.path)
        artifact_ids.add(artifact.artifact_id)
        artifacts.setdefault(artifact.sha256, []).append(artifact)
    components = {}

    def add(component: ComponentVersion) -> None:
        previous = components.get(component.component_id)
        if previous is not None and previous != component:
            raise ValueError("conflicting component identity")
        components[component.component_id] = component

    add(_component("source", "scanner_source_build", source["build_sha256"]))
    known = {}
    for binding in context.known_components:
        if binding.arm not in {"C", "C-custom", "T"} or binding.arm in known:
            raise ValueError("unique scanner arm component bindings required")
        if binding.scanner.kind != "scanner" or binding.config.kind != "config":
            raise ValueError("scanner/config component kinds required")
        known[binding.arm] = binding
    invocations, attempts, evaluations, joins, kinds = [], [], [], {}, set()
    receipt_owners, captured_cases = {}, set()
    for attempt in bridge.attempts:
        payload = json.loads(attempt.metadata_json)["capture"]
        case_id, capture_sha, captured = _receipt(payload)
        captured_cases.add(case_id)
        case = cases.get(case_id)
        source_sha = captured.plan_sha256 or (case.raw_source_sha256 if case is not None else None)
        if case is None or source_sha is None:
            missing.add("case_binding_missing")
            continue  # Original attempt remains in result.bridge, never discarded.
        if source_sha != case.raw_source_sha256:
            raise ValueError("capture/case raw source digest mismatch")
        key = (case_id, captured.arm, capture_sha)
        suffix = digest(json.dumps(key, separators=(",", ":")).encode())
        invocation_id, attempt_id = "scan_" + suffix, "attempt_" + suffix
        scanner = config = None
        declared = known.get(captured.arm)
        if declared is not None:
            scanner, config = declared.scanner, declared.config
            if ((captured.executable_sha256 is not None and scanner.sha256 != captured.executable_sha256)
                    or (captured.config_sha256 is not None and config.sha256 != captured.config_sha256)
                    or (captured.scanner_version is not None and scanner.version != captured.scanner_version)):
                raise ValueError("declared scanner components disagree with actual capture metadata")
        else:
            if captured.executable_sha256 is not None and captured.scanner_version is not None:
                if OPAQUE.fullmatch(captured.scanner_version):
                    scanner = _component("scanner", captured.scanner_name + "_binary",
                                         captured.executable_sha256, version=captured.scanner_version)
                else:
                    missing.add("scanner_version_not_portable")
            if captured.config_sha256 is not None:
                config = _component("config", "scanner_config", captured.config_sha256)
        if scanner is None or config is None:
            missing.add("scanner_or_config_component_missing")
        for component in (scanner, config):
            if component is not None:
                add(component)
        for label, pin, kind in (("scanner_policy", captured.policy_sha256, "rules"),
                                 ("scanner_dependencies", captured.dependency_manifest_sha256, "source"),
                                 ("scanner_version_receipt", captured.version_evidence_sha256, "scanner")):
            if pin is not None:
                add(_component(kind, label, pin))
        proof = (captured.operator_grant_sha256, captured.start_receipt_sha256,
                 captured.terminal_receipt_sha256)
        nonempty = [pin for pin in proof if pin is not None]
        if len(nonempty) != len(set(nonempty)):
            raise ValueError("grant/start/terminal receipts must be distinct")
        for pin in proof:
            if pin is not None and (not isinstance(pin, str) or not SHA256.fullmatch(pin)):
                raise ValueError("invalid execution receipt digest")
        for pin in (captured.start_receipt_sha256, captured.terminal_receipt_sha256):
            if pin is not None and captured.execution_kind != "fake":
                if pin in receipt_owners and receipt_owners[pin] != key:
                    raise ValueError("execution receipt reused across attempts")
                receipt_owners[pin] = key
        proof_bound = all(pin is not None and any(ref.role == "producer" for ref in artifacts.get(pin, ()))
                          for pin in proof)
        if source["fake_only"] or captured.execution_kind == "fake":
            kind = "mock"
        elif captured.execution_kind == "live" and proof_bound:
            kind = "executed"
        else:
            kind = "unverified"
            if captured.execution_kind == "live":
                missing.add("private_execution_receipt_references_missing")
        kinds.add(kind)
        status = captured.status
        if status == "ok" and kind != "executed":
            status = "not_run"
        attempts.append(AttemptMetadata(attempt_id=attempt_id, invocation_id=invocation_id,
                         arm=captured.arm, status=status, kind=kind, raw_source_sha256=source_sha,
                         start_receipt_sha256=captured.start_receipt_sha256,
                         terminal_receipt_sha256=captured.terminal_receipt_sha256,
                         elapsed_ms=int(captured.elapsed_seconds * 1000) if captured.elapsed_seconds is not None else None))
        if scanner is not None and config is not None:
            invocations.append(InvocationMetadata(invocation_id=invocation_id, arm=captured.arm,
                               status=status, kind=kind, case_ids=(case_id,),
                               config_component_id=config.component_id, version_component_id=scanner.component_id,
                               attempt_ids=(attempt_id,), all_attempts_attested=False))
            joins[key] = invocation_id, kind
    original_rows = {}
    for value in source["rows"]:
        row = ComparisonRow(**value)
        original_rows[measurement_ref(row)] = row
    for row in bridge.rows:
        original = original_rows[row.measurement_ref]
        joined = joins.get((row.case_id, row.arm, original.capture_sha256))
        if joined is None:
            missing.add("invocation_binding_missing")
            continue
        invocation_id, kind = joined
        evaluations.append(EvaluationEligibility(arm=row.arm, invocation_id=invocation_id,
                           measurement_ref=row.measurement_ref, raw_source_sha256=row.source_sha256,
                           eligibility_ref=row.eligibility_ref,
                           claimed_eligible=(kind == "executed" and row.status == "ok"
                                             and measurement_eligible(row, eligibility))))
    if set(cases) - captured_cases:
        missing.add("case_without_capture")
    if len(components) > 128 or len(invocations) > 4096 or len(attempts) > 10000 or len(context.artifacts) > 512:
        missing.add("shared_manifest_inventory_bound_exceeded")
    manifest = None
    if not missing:
        manifest = RunManifest(run_id=context.run_id, edition_id=context.edition_id,
                   edition_state=context.edition_state, split=split, build_sha256=source["build_sha256"],
                   policy_sha256=context.policy_sha256, authority_sha256=context.authority_sha256,
                   semantic_suite_sha256=context.semantic_suite_sha256, eligibility_sha256=expected_eligibility_sha256,
                   components=tuple(components.values()), cases=context.cases, invocations=tuple(invocations),
                   attempts=tuple(attempts), artifacts=context.artifacts, eligibility=tuple(evaluations))
    public = {"schema_version": "m4-scanner-manifest-summary-v1", "run_id": context.run_id,
              "status": "DRAFT_INCOMPLETE" if manifest is None else "METADATA_ONLY",
              "case_count": len(context.cases), "invocation_count": len(invocations),
              "attempt_count": len(bridge.attempts), "scorer_row_count": len(bridge.rows),
              "artifact_count": len(context.artifacts), "kinds": sorted(kinds),
              "missing_reasons": sorted(missing), "all_attempts_authenticated": False,
              "product_acceptance": False}
    return ScannerManifestResult(manifest, bridge, tuple(sorted(missing)),
                                 json.dumps(public, sort_keys=True, separators=(",", ":")))
