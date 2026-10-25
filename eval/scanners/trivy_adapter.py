"""Trivy config/terraformplan-json adapter; compatibility is never assumed."""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from .bundle_inventory import BundleInventory, plain_directory
from .runner import Limits, Observation, Runner, ScanArtifact, ScannerPin, capture

if TYPE_CHECKING:
    from .artifacts import Mapping


def parse_output(payload: object) -> tuple[Observation, ...]:
    if not isinstance(payload, dict) or payload.get("SchemaVersion") != 2:
        raise ValueError("unsupported Trivy output schema")
    results = payload.get("Results")
    if not isinstance(results, list):
        raise ValueError("missing Trivy results")
    rows = []
    states = {"PASS": "passed", "FAIL": "failed", "EXCEPTION": "skipped",
              "UNKNOWN": "unknown"}
    for result in results:
        if not isinstance(result, dict) or result.get("Type") != "terraformplan-json":
            raise ValueError("unexpected/non-plan scanner result")
        values = result.get("Misconfigurations")
        if not isinstance(values, list):
            raise ValueError("missing explicit misconfiguration records")
        for row in values:
            if not isinstance(row, dict):
                raise ValueError("invalid Trivy record")
            cause = row.get("CauseMetadata")
            if (not isinstance(cause, dict) or not isinstance(cause.get("Resource"), str)
                    or not isinstance(row.get("ID"), str) or row.get("Status") not in states):
                raise ValueError("unmapped or unknown Trivy check/resource status")
            rows.append(Observation(row["ID"], cause["Resource"], states[row["Status"]]))
    return tuple(rows)


def scan(*, plan_path: Path, pin: ScannerPin, config_path: Path, workspace: Path,
         runner: Runner, check_ids: tuple[str, ...], mappings: tuple[Mapping, ...] = (),
         policy_sha256: str | None = None, limits: Limits = Limits(),
         policy_manifest_path: Path | None = None,
         checks_bundle_files: tuple[tuple[Path, str, int], ...] = (),
         bundle_inventory: BundleInventory | None = None,
         attempt_deadline: float | None = None) -> ScanArtifact:
    # Flags follow upstream source, not a claimed tested release. Caller pins and
    # verifies that exact release/profile before any record can be scored.
    argv = (str(pin.executable), "config", "--format", "json", "--config", str(config_path),
            "--misconfig-scanners", "terraformplan-json", "--include-non-failures",
            "--skip-check-update", "--disable-telemetry", "--skip-version-check", "--exit-code", "1",
            "--ignorefile", "",
            "--timeout", f"{limits.timeout_seconds:g}s", "--cache-dir", str(workspace),
            "--", str(plan_path))
    if bundle_inventory is not None:
        if type(bundle_inventory) is not BundleInventory or checks_bundle_files:
            raise ValueError("complete-tree and legacy bundle modes are exclusive")
        plain_directory(workspace, deadline=attempt_deadline)
        if bundle_inventory.root != workspace / "policy":
            raise ValueError("complete-tree root must be exact workspace/policy")
    if not checks_bundle_files and bundle_inventory is None:
        from .runner import ScanArtifact
        return ScanArtifact("T", "trivy", "not_run", "none", None, pin.version,
                            pin.executable_sha256, pin.dependency_manifest_sha256,
                            pin.version_evidence_sha256, None, None, policy_sha256,
                            "unverified", check_ids, reasons=("missing_pinned_local_checks_bundle",))
    if any(not path.resolve().is_relative_to(workspace.resolve())
           for path, _, _ in checks_bundle_files):
        raise ValueError("pinned checks bundle must be in the scanner's exact cache directory")
    return capture(arm="T", pin=pin, plan_path=plan_path, config_path=config_path,
                   workspace=workspace, runner=runner, argv_builder=lambda: argv,
                   parser=parse_output, check_ids=check_ids, mappings=mappings,
                   policy_sha256=policy_sha256, limits=limits,
                   policy_manifest_path=policy_manifest_path,
                   extra_files=checks_bundle_files, bundle_inventory=bundle_inventory,
                   attempt_deadline=attempt_deadline)
