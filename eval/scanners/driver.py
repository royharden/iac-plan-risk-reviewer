"""Scanner comparison source driver; no oracle/product detector imports.

Two explicit input scopes. `development_synthetic` reads declared public synthetic
plan paths. `heldout` (guarded) reads ONLY a permission-gated in-memory snapshot
supplied as `GuardedScannerInput`, stages it explicitly per arm into the operator's
scratch workspace and removes it afterwards; the private source path never appears
in the manifest or the scanner argv. Heldout requires a heldout-scoped operator grant
and the existing BoundedSubprocessRunner; there is no fake or second runner for it.
No runner is selected implicitly. Source constructed under Dirty Mode; no
invocation, import or tests executed during that construction.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Callable, Literal

from . import checkov_adapter, trivy_adapter
from .artifacts import Mapping
from .bundle_inventory import load_bundle_inventory
from .runner import (
    SHA256,
    BoundedSubprocessRunner,
    FakeRunner,
    Limits,
    Runner,
    ScanArtifact,
    ScannerPin,
    _attempt_clock,
    _check_deadline,
    bounded_read,
    cell_status,
    digest,
    remove_guarded_input,
    simulate_capture,
    stage_guarded_input,
    strict_json,
)

SCOPES = ("development_synthetic", "heldout")


@dataclass(frozen=True)
class GuardedScannerInput:
    """One case's permission-gated byte provider (e.g. GuardedCaseReader.read).

    `read` rechecks access permission/custody on every call and returns the same
    immutable snapshot; the driver re-verifies the pin on every use.
    """
    case_id: str
    plan_sha256: str
    read: Callable[[], bytes] = field(repr=False)

    def verified(self, cap: int) -> bytes:
        data = self.read()
        if type(data) is not bytes or len(data) > cap or digest(data) != self.plan_sha256:
            raise ValueError("guarded heldout input differs from its permitted pin")
        return data

ARMS = ("C", "C-custom", "T")
RULES = ("R1", "R2", "R3", "R4")
OPAQUE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z")


@dataclass(frozen=True)
class ComparisonRow:
    case_id: str
    resource_id: str
    rule_id: str
    arm: str
    status: Literal["recorded", "not_run", "unmapped", "invalid", "timeout", "error", "simulated"]
    comparison_target: Literal["introduced_risk"]
    introduced_prediction: bool | None
    live_eligible: bool
    plan_sha256: str
    mapping_sha256: str | None
    capture_sha256: str
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class Case:
    case_id: str
    plan_path: Path | None  # None for guarded heldout: no private path is carried.
    plan_sha256: str
    resources: tuple[tuple[str, dict], ...]
    guarded: GuardedScannerInput | None = field(default=None, repr=False)


def _case_bytes(case: Case, limits: Limits) -> bytes:
    if case.guarded is not None:
        return case.guarded.verified(limits.plan_bytes)
    return bounded_read(case.plan_path, limits.plan_bytes)


def _opaque(value: object) -> str:
    if not isinstance(value, str) or not OPAQUE.fullmatch(value):
        raise ValueError("opaque ID required")
    return value


def _hash(value: object) -> str:
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        raise ValueError("exact SHA256 required")
    return value


def _path(value: object) -> Path:
    if not isinstance(value, str) or not Path(value).is_absolute():
        raise ValueError("absolute path required")
    return Path(value)


def _load_cases(manifest: dict, limits: Limits,
                guarded: GuardedScannerInput | None = None) -> tuple[Case, ...]:
    scope = manifest.get("input_scope")
    if (manifest.get("schema_version") not in {"m4-scanner-run-v1", "m4-scanner-run-v2"}
            or scope not in SCOPES
            or (manifest.get("schema_version") == "m4-scanner-run-v2" and scope != "development_synthetic")):
        raise ValueError("only declared development synthetic or guarded heldout inputs are authorized")
    heldout = scope == "heldout"
    if heldout != (guarded is not None) or (guarded is not None and type(guarded) is not GuardedScannerInput):
        raise ValueError("guarded heldout input and heldout scope are required together")
    if heldout and (manifest.get("guarded_input") is not True
                    or manifest.get("synthetic_input_attested") is True):
        raise ValueError("heldout manifest must declare guarded input and no synthetic attestation")
    _hash(manifest.get("build_sha256"))
    cases = manifest.get("cases")
    if not isinstance(cases, list) or not 0 < len(cases) <= (1 if heldout else 256):
        raise ValueError("bounded nonempty case inventory required")
    result, seen_cases = [], set()
    for item in cases:
        if not isinstance(item, dict):
            raise ValueError("case must be an object")
        case_id = _opaque(item.get("case_id"))
        if case_id in seen_cases:
            raise ValueError("duplicate case identity")
        seen_cases.add(case_id)
        expected = _hash(item.get("plan_sha256"))
        if heldout:
            # Private source path is never declared, reopened or passed to a scanner.
            if "plan_path" in item or guarded.case_id != case_id or guarded.plan_sha256 != expected:
                raise ValueError("guarded heldout case identity/pin mismatch")
            path, raw = None, guarded.verified(limits.plan_bytes)
        else:
            path = _path(item.get("plan_path"))
            raw = bounded_read(path, limits.plan_bytes)
        if digest(raw) != expected:
            raise ValueError("case input differs from frozen plan bytes")
        plan = strict_json(raw)
        if (not isinstance(plan, dict) or plan.get("format_version") not in {"1.0", "1.1", "1.2"}
                or not isinstance(plan.get("resource_changes"), list)):
            raise ValueError("supported saved-plan JSON required")
        by_address = {}
        for resource in plan["resource_changes"]:
            if (not isinstance(resource, dict) or not isinstance(resource.get("address"), str)
                    or resource.get("deposed") is not None
                    or resource["address"] in by_address):
                raise ValueError("scanner resource identity is ambiguous")
            by_address[resource["address"]] = resource
        bindings = item.get("resources")
        if not isinstance(bindings, list) or len(bindings) != len(by_address):
            raise ValueError("explicit complete resource-ID bindings required")
        resources, seen_ids, bound_addresses = [], set(), set()
        for binding in bindings:
            if not isinstance(binding, dict):
                raise ValueError("resource binding must be an object")
            resource_id = _opaque(binding.get("resource_id"))
            address = binding.get("address")
            if (not isinstance(address, str) or resource_id in seen_ids
                    or address not in by_address or address in bound_addresses):
                raise ValueError("duplicate/missing/foreign private identity binding")
            seen_ids.add(resource_id)
            bound_addresses.add(address)
            resources.append((resource_id, by_address[address]))
        result.append(Case(case_id, path, expected, tuple(resources), guarded if heldout else None))
    if sum(len(case.resources) for case in result) * len(ARMS) * len(RULES) > 100_000:
        raise ValueError("comparison row budget exceeded")
    return tuple(result)


def _pin(settings: dict) -> ScannerPin:
    value = settings.get("pin")
    if not isinstance(value, dict):
        raise ValueError("missing scanner pin")
    optional_path = lambda key: _path(value[key]) if value.get(key) is not None else None
    return ScannerPin(_path(value.get("executable")), value.get("version"),
                      value.get("executable_sha256"), value.get("dependency_manifest_sha256"),
                      value.get("version_evidence_sha256"),
                      optional_path("dependency_manifest_path"),
                      optional_path("version_evidence_path"))


def _files(settings: dict, key: str) -> tuple[tuple[Path, str, int], ...]:
    values = settings.get(key, [])
    if not isinstance(values, list) or len(values) > 256:
        raise ValueError("bounded pinned file inventory required")
    files = []
    names = set()
    for value in values:
        if not isinstance(value, dict):
            raise ValueError("pinned file must be an object")
        path = _path(value["path"])
        cap = value.get("max_bytes", 16 * 1024 * 1024)
        if type(cap) is not int or not 0 < cap <= 16 * 1024 * 1024 or path.name in names:
            raise ValueError("invalid file bound or duplicate artifact name")
        names.add(path.name)
        files.append((path, _hash(value["sha256"]), cap))
    return tuple(files)


def _mappings(settings: dict) -> tuple[Mapping, ...]:
    values = settings.get("mappings", [])
    if not isinstance(values, list) or len(values) > 4:
        raise ValueError("invalid mapping inventory")
    result = tuple(Mapping.model_validate_json(json.dumps(value)) for value in values)
    if len({item.rule_id for item in result}) != len(result):
        raise ValueError("duplicate rule mappings")
    return result


def _mapping_digest(mapping: Mapping | None) -> str | None:
    return digest(mapping.model_dump_json().encode()) if mapping is not None else None


def _capture_digest(artifact: ScanArtifact) -> str:
    # Hash private raw locators, never publish them; digest is artifact identity,
    # not a low-entropy raw value hash promoted to a shareable product report.
    return digest(json.dumps(asdict(artifact), sort_keys=True, separators=(",", ":")).encode())


def _absent(arm: str, reason: str) -> ScanArtifact:
    return ScanArtifact(arm, "trivy" if arm == "T" else "checkov", "not_run", "none",
                        None, None, None, None, None, None, None, None, "unverified", (),
                        reasons=(reason,))


def _seal_arm(case_id: str, artifact: ScanArtifact, arm_rows: list[ComparisonRow], *,
              started_at: float | None, deadline: float | None,
              tree_mode: bool) -> tuple[list[dict], dict]:
    # Materialize the whole arm before its last eligibility check. In particular,
    # a later cell or row cannot leave an earlier row from this arm eligible.
    rows = [asdict(row) for row in arm_rows]
    receipt = asdict(artifact)
    receipt.pop("observations")
    receipt = dict(case_id=case_id, capture_sha256="", **receipt)

    def seal(now: float | None) -> None:
        nonlocal artifact
        if now is not None:
            if now >= deadline:
                reason = ("complete_tree_attempt_timeout" if tree_mode and artifact.arm == "T"
                          else "scanner_timeout")
                artifact = replace(artifact, status="timeout", observations=(),
                                   reasons=tuple(sorted(set((*artifact.reasons, reason)))))
                for row in rows:
                    row.update(status="timeout", introduced_prediction=None, live_eligible=False,
                               reasons=tuple(sorted(set((*row["reasons"], reason)))))
            # This is the whole owner's elapsed snapshot, including final cell
            # mapping and row/receipt materialization, not capture's subduration.
            artifact = replace(artifact, elapsed_seconds=now - started_at)
            receipt.update(status=artifact.status, reasons=artifact.reasons,
                           elapsed_seconds=artifact.elapsed_seconds)
        capture_hash = _capture_digest(artifact)
        receipt["capture_sha256"] = capture_hash
        for row in rows:
            row["capture_sha256"] = capture_hash

    seal(time.monotonic() if deadline is not None else None)
    if deadline is not None:
        finished = time.monotonic()
        if finished >= deadline:
            # A hash or final materialization may itself return late. Permanently
            # reject this arm and reseal all links with that observed elapsed.
            # The snapshot cannot attest the future time hashing itself takes;
            # this recovery never restores eligibility or renews the deadline.
            seal(finished)
    return rows, receipt


def _collect(case: Case, arm: str, settings: dict | None, runner: Runner | None,
             fake_only: bool, limits: Limits, *, tree_mode: bool = False,
             attempt_deadline: float | None = None,
             attempt_started_at: float | None = None) -> tuple[ScanArtifact, tuple[Mapping, ...]]:
    if settings is None:
        return _absent(arm, "missing_arm_configuration"), ()
    check_ids = settings.get("check_ids", [])
    if not isinstance(check_ids, list) or not all(isinstance(v, str) for v in check_ids):
        return _absent(arm, "invalid_check_inventory"), ()
    adapter = trivy_adapter if arm == "T" else checkov_adapter
    if fake_only:
        fixtures = settings.get("fake_fixtures", {})
        if not isinstance(fixtures, dict) or case.case_id not in fixtures:
            return _absent(arm, "missing_explicit_fake_fixture"), ()
        fixture = fixtures[case.case_id]
        if not isinstance(fixture, dict):
            raise ValueError("fake fixture must be an object")
        raw = bounded_read(_path(fixture["stdout_path"]), limits.stdout_bytes)
        if digest(raw) != _hash(fixture.get("stdout_sha256")):
            raise ValueError("fake fixture hash mismatch")
        fake = FakeRunner(raw, b"", fixture.get("exit_code", 0), fixture.get("timed_out", False))
        return simulate_capture(arm=arm, plan_path=case.plan_path, runner=fake,
                                parser=adapter.parse_output, check_ids=tuple(check_ids),
                                limits=limits), ()
    if runner is None:
        return _absent(arm, "no_explicit_authorized_runtime_runner"), ()
    staged = None
    attempt_started_at, attempt_deadline = _attempt_clock(limits, attempt_deadline, attempt_started_at)
    try:
        _check_deadline(attempt_deadline)
        mappings = _mappings(settings)
        _check_deadline(attempt_deadline)
        workspace = _path(settings.get("workspace"))
        plan_path = case.plan_path
        if case.guarded is not None:
            if type(runner) is not BoundedSubprocessRunner:
                return _absent(arm, "guarded_heldout_requires_granted_bounded_runner"), mappings
            # Explicit per-arm staging of the verified in-memory snapshot only.
            staged = stage_guarded_input(workspace, case.guarded.verified(limits.plan_bytes),
                                         case.plan_sha256, limits.plan_bytes)
            plan_path = staged
        common = dict(plan_path=plan_path, pin=_pin(settings),
                      config_path=_path(settings.get("config_path")),
                      workspace=workspace, runner=runner,
                      check_ids=tuple(check_ids), mappings=mappings,
                      policy_sha256=settings.get("policy_sha256"),
                      policy_manifest_path=_path(settings["policy_manifest_path"])
                      if settings.get("policy_manifest_path") else None, limits=limits,
                      attempt_deadline=attempt_deadline, attempt_started_at=attempt_started_at)
        if arm == "T":
            if tree_mode:
                binding = load_bundle_inventory(settings.get("bundle_inventory"), workspace,
                                                deadline=attempt_deadline)
                artifact = adapter.scan(**common, bundle_inventory=binding)
            else:
                artifact = adapter.scan(**common, checks_bundle_files=_files(settings, "bundle_files"))
        elif arm == "C-custom":
            if not settings.get("custom_policy_dir"):
                return _absent(arm, "missing_custom_policy_directory"), mappings
            artifact = adapter.scan(**common,
                                    custom_policy_dir=_path(settings["custom_policy_dir"]),
                                    custom_policy_files=_files(settings, "custom_policy_files"))
        else:
            artifact = adapter.scan(**common)
        if artifact.arm != arm:
            raise ValueError("adapter arm mismatch")
    except TimeoutError:
        return replace(_absent(arm, "complete_tree_attempt_timeout" if tree_mode and arm == "T"
                               else "scanner_timeout"), status="timeout",
                       elapsed_seconds=time.monotonic() - attempt_started_at), ()
    except (OSError, ValueError, TypeError, KeyError, RecursionError, UnicodeError):
        return _absent(arm, "unavailable_or_unverified_activation_inputs"), ()
    finally:
        if staged is not None and not remove_guarded_input(staged, case.plan_sha256, limits.plan_bytes):
            # Never silently leave heldout bytes behind: the comparison aborts.
            raise ValueError("guarded heldout staging cleanup failed")
    # Staging cleanup cannot turn a late attempt into an eligible capture.
    if time.monotonic() >= attempt_deadline:
        artifact = replace(artifact, status="timeout", observations=(),
                           reasons=("complete_tree_attempt_timeout" if tree_mode and arm == "T"
                                    else "scanner_timeout",))
    return replace(artifact, elapsed_seconds=time.monotonic() - attempt_started_at), mappings


def compare(manifest: dict, *, runner: Runner | None = None, fake_only: bool = False,
            limits: Limits = Limits(), guarded_input: GuardedScannerInput | None = None) -> dict:
    """No default process execution. Fake mode ignores/rejects runtime runners.

    Preserve one row per resource/rule/required arm, including missing observations.
    Never emits scorer ArmRows, and never interprets absent rows as true negatives.
    Guarded heldout scope refuses fake mode and any runner other than a heldout-granted
    BoundedSubprocessRunner; missing scanners stay NOT_RUN/incomplete, never measured.
    """
    # Freeze caller-owned mutable configuration before checking the operator pin.
    manifest = json.loads(json.dumps(manifest, allow_nan=False))
    if fake_only and runner is not None:
        raise ValueError("fake-only mode cannot accept a runtime runner")
    if guarded_input is not None and (fake_only or type(runner) is not BoundedSubprocessRunner
                                      or runner.execution_grant is None
                                      or runner.execution_grant.input_scope != "heldout"):
        raise ValueError("guarded heldout input requires its heldout-scoped granted runner")
    if type(runner) is BoundedSubprocessRunner:
        runner.verify_manifest(manifest)
    cases = _load_cases(manifest, limits, guarded_input)
    scope = manifest["input_scope"]
    arms = manifest.get("arms", {})
    if not isinstance(arms, dict) or set(arms) - set(ARMS):
        raise ValueError("unknown comparison arm")
    if any(not isinstance(settings, dict) for settings in arms.values()):
        raise ValueError("arm settings must be objects")
    tree_mode = manifest["schema_version"] == "m4-scanner-run-v2"
    for arm, settings in arms.items():
        if "bundle_inventory" in settings and (not tree_mode or arm != "T"):
            raise ValueError("complete-tree binding requires explicit v2 T arm")
        if tree_mode and arm == "T" and ("bundle_inventory" not in settings or "bundle_files" in settings):
            raise ValueError("v2 requires complete-tree descriptor without legacy bundle_files")
    rows, receipts = [], []
    for case in cases:
        for arm in ARMS:
            # Batch admission is separate. Ownership precedes this arm's raw
            # verification and follows it through every nested preparation.
            started_at, deadline = (_attempt_clock(limits) if runner is not None and not fake_only
                                    and arms.get(arm) is not None else (None, None))
            if digest(_case_bytes(case, limits)) != case.plan_sha256:
                raise ValueError("plan mutation between arms aborts comparison")
            artifact, mappings = _collect(case, arm, arms.get(arm), runner, fake_only, limits,
                                          tree_mode=tree_mode, attempt_deadline=deadline,
                                          attempt_started_at=started_at)
            if artifact.plan_sha256 not in (None, case.plan_sha256):
                raise ValueError("scanner capture used different plan bytes")
            arm_rows = []
            by_rule = {mapping.rule_id: mapping for mapping in mappings}
            for resource_id, resource in case.resources:
                for rule in RULES:
                    mapping = by_rule.get(rule)
                    status, prediction = "not_run", None
                    reasons = artifact.reasons
                    if artifact.status in {"timeout", "error", "invalid"}:
                        status = artifact.status
                    elif fake_only and artifact.execution_kind == "fake":
                        status = "simulated"
                    elif artifact.status == "not_run":
                        status = "not_run"
                    elif mapping is None:
                        status, reasons = "unmapped", reasons + ("missing_exact_rule_mapping",)
                    else:
                        cell = cell_status(artifact, mapping, resource)
                        if cell == "eligible":
                            # Frozen mapping asserts these checks detect introduced
                            # risk; only binary target is represented, not full D labels.
                            matches = [row for row in artifact.observations
                                       if row.resource_locator == resource["address"]
                                       and row.check_id in mapping.check_ids]
                            prediction = any(row.status == "failed" for row in matches)
                            status = "recorded"
                        elif cell in {"unmapped", "not_applicable"}:
                            status, reasons = "unmapped", reasons + (cell,)
                        else:
                            reasons = reasons + ("capture_or_cell_incomplete",)
                    arm_rows.append(ComparisonRow(case.case_id, resource_id, rule, arm, status,
                                                  "introduced_risk", prediction,
                                                  status == "recorded" and not fake_only,
                                                  case.plan_sha256, _mapping_digest(mapping),
                                                  "", tuple(sorted(set(reasons)))))
            # Finish this owner's serialization and eligibility before beginning
            # an unrelated arm; later arms cannot taint an on-time sealed arm.
            sealed_rows, receipt = _seal_arm(case.case_id, artifact, arm_rows,
                                             started_at=started_at, deadline=deadline,
                                             tree_mode=tree_mode)
            rows.extend(sealed_rows)
            receipts.append(receipt)
    for case in cases:
        if digest(_case_bytes(case, limits)) != case.plan_sha256:
            raise ValueError("plan mutation invalidates comparison")
    return {"schema_version": "m4-scanner-comparison-v1", "build_sha256": manifest["build_sha256"],
            "manifest_sha256": digest(json.dumps(manifest, sort_keys=True,
                                                 separators=(",", ":")).encode()),
            "input_scope": scope, "fake_only": fake_only,
            "measurement_status": "SIMULATED_INELIGIBLE" if fake_only else (
                "RECORDED" if rows and all(row["live_eligible"] for row in rows) else "INCOMPLETE"),
            "source_enrichment": False, "product_acceptance": False,
            "rows": rows, "capture_receipts": receipts,
            "limitations": ["No gold, confusion counts or product acceptance computed.",
                            "Binary introduced-risk predictions cannot recover unchanged/clear labels.",
                            "No direct ArmRow success conversion is provided."]}


def load_manifest(path: Path) -> dict:
    value = strict_json(bounded_read(path, 2 * 1024 * 1024))
    if not isinstance(value, dict):
        raise ValueError("scanner manifest must be an object")
    return value
