"""Checkov plan-only adapter. No Checkov imports, downloads or implicit execution."""
from __future__ import annotations

import time
from pathlib import Path
from typing import TYPE_CHECKING

from .runner import (
    BoundedSubprocessRunner,
    Limits,
    Observation,
    Runner,
    ScanArtifact,
    ScannerPin,
    _attempt_clock,
    _check_deadline,
    capture,
)

if TYPE_CHECKING:
    from .artifacts import Mapping


def parse_output(payload: object) -> tuple[Observation, ...]:
    # One selected framework has one report. Some upstream versions wrap it in a list.
    if isinstance(payload, list) and len(payload) == 1:
        payload = payload[0]
    if not isinstance(payload, dict) or payload.get("check_type") != "terraform_plan":
        raise ValueError("expected one terraform_plan report")
    results = payload.get("results")
    if not isinstance(results, dict) or results.get("parsing_errors") != []:
        raise ValueError("missing or failed scanner parse evidence")
    rows = []
    for key, state in (("passed_checks", "passed"), ("failed_checks", "failed"),
                       ("skipped_checks", "skipped")):
        values = results.get(key)
        if not isinstance(values, list):
            raise ValueError("incomplete scanner result categories")
        for row in values:
            if (not isinstance(row, dict) or not isinstance(row.get("check_id"), str)
                    or not isinstance(row.get("resource"), str)):
                raise ValueError("invalid check/resource record")
            expected = {"passed": "PASSED", "failed": "FAILED", "skipped": "SKIPPED"}[state]
            check_result = row.get("check_result")
            if not isinstance(check_result, dict) or check_result.get("result") != expected:
                raise ValueError("check category/result contradiction")
            rows.append(Observation(row["check_id"], row["resource"], state))
    return tuple(rows)


def scan(*, plan_path: Path, pin: ScannerPin, config_path: Path, workspace: Path,
         runner: Runner, check_ids: tuple[str, ...], mappings: tuple[Mapping, ...] = (),
         policy_sha256: str | None = None, limits: Limits = Limits(),
         policy_manifest_path: Path | None = None,
         custom_policy_files: tuple[tuple[Path, str, int], ...] = (),
         custom_policy_dir: Path | None = None,
         attempt_deadline: float | None = None,
         attempt_started_at: float | None = None) -> ScanArtifact:
    arm = "C-custom" if custom_policy_dir is not None else "C"
    if (type(runner) is BoundedSubprocessRunner or attempt_deadline is not None
            or attempt_started_at is not None):
        attempt_started_at, attempt_deadline = _attempt_clock(limits, attempt_deadline, attempt_started_at)
    # No flags/paths originate in submitted plan content. No source enrichment.
    argv = (str(pin.executable), "--file", str(plan_path), "--framework", "terraform_plan",
            "--output", "json", "--compact", "--check", ",".join(check_ids),
            "--config-file", str(config_path), "--skip-download", "--skip-results-upload",
            "--download-external-modules", "false")
    extra_env = ()
    try:
        _check_deadline(attempt_deadline)
        if custom_policy_dir is not None:
            if (not custom_policy_dir.is_absolute() or not custom_policy_dir.is_dir()
                    or custom_policy_dir.is_symlink() or not custom_policy_files):
                raise ValueError("custom policies require absolute pinned local source directory")
            # All loadable files must be pinned, including helper modules.
            actual = set()
            for path in custom_policy_dir.iterdir():
                _check_deadline(attempt_deadline)
                if path.suffix in {".py", ".yaml", ".yml"}:
                    actual.add(path.resolve())
            supplied = {path.resolve() for path, _, _ in custom_policy_files}
            if actual != supplied or any(path.is_dir() for path in custom_policy_dir.iterdir()):
                raise ValueError("custom policy inventory mismatch or nested unpinned source")
            _check_deadline(attempt_deadline)
            argv += ("--external-checks-dir", str(custom_policy_dir))
            from .runner import _attempt_read, digest
            plan_hash = digest(_attempt_read(plan_path, limits.plan_bytes, attempt_deadline))
            extra_env = (("IAC_CUSTOM_PLAN_JSON", str(plan_path)),
                         ("IAC_CUSTOM_PLAN_SHA256", plan_hash))
        _check_deadline(attempt_deadline)
    except TimeoutError:
        return ScanArtifact(arm, "checkov", "timeout", "none", None, pin.version,
                            pin.executable_sha256, pin.dependency_manifest_sha256,
                            pin.version_evidence_sha256, None, None, policy_sha256,
                            "unverified", check_ids, reasons=("scanner_timeout",),
                            elapsed_seconds=time.monotonic() - attempt_started_at)
    return capture(arm=arm, pin=pin, plan_path=plan_path, config_path=config_path,
                   workspace=workspace, runner=runner, argv_builder=lambda: argv,
                   parser=parse_output, check_ids=check_ids, mappings=mappings,
                   policy_sha256=policy_sha256, limits=limits,
                   policy_manifest_path=policy_manifest_path,
                   extra_files=custom_policy_files, extra_environment=extra_env,
                   attempt_deadline=attempt_deadline, attempt_started_at=attempt_started_at)
