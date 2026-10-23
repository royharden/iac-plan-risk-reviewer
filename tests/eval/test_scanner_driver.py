"""Regression SOURCE only during Dirty Mode; not imported or run in construction.

These public synthetic fixtures test plumbing, not an oracle or scanner quality.
"""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import hashlib
import json

import pytest

from eval.scanners.driver import compare
from eval.scanners.artifacts import Mapping
from eval.scanners.runner import (FakeRunner, Limits, Observation, ScanArtifact,
                                 cell_status, simulate_capture)
from eval.scanners.checkov_adapter import parse_output


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def setup_case(tmp_path: Path) -> tuple[dict, dict, Path]:
    resource = {"address": "aws_db_instance.synthetic", "mode": "managed",
                "provider_name": "registry.terraform.io/hashicorp/aws",
                "type": "aws_db_instance", "change": {"actions": ["create"],
                "before": None, "after": {"publicly_accessible": True}}}
    raw = json.dumps({"format_version": "1.2", "resource_changes": [resource]}).encode()
    path = tmp_path / "plan.json"
    path.write_bytes(raw)
    manifest = {"schema_version": "m4-scanner-run-v1", "input_scope": "development_synthetic",
                "build_sha256": "a" * 64, "cases": [{"case_id": "case_1",
                "plan_path": str(path), "plan_sha256": sha(raw),
                "resources": [{"resource_id": "resource_1", "address": resource["address"]}]}],
                "arms": {}}
    return manifest, resource, path


def output(resource: str, state: str = "FAILED") -> bytes:
    results = {"passed_checks": [], "failed_checks": [], "skipped_checks": [],
               "parsing_errors": []}
    key = "failed_checks" if state == "FAILED" else "passed_checks"
    results[key].append({"check_id": "CKV_M4_R2", "resource": resource,
                         "check_result": {"result": state}})
    return json.dumps({"check_type": "terraform_plan", "results": results}).encode()


def add_fake(tmp_path: Path, manifest: dict, raw: bytes, **extra) -> None:
    path = tmp_path / "fixture.json"
    path.write_bytes(raw)
    manifest["arms"]["C-custom"] = {"check_ids": ["CKV_M4_R2"], "fake_fixtures": {
        "case_1": {"stdout_path": str(path), "stdout_sha256": sha(raw), "exit_code": 1, **extra}}}


def test_missing_arms_are_not_true_negatives(tmp_path: Path) -> None:
    """what_bug_this_catches: absent scanner results previously looked like clear checks."""
    manifest, _, _ = setup_case(tmp_path)
    report = compare(manifest)
    assert report["measurement_status"] == "INCOMPLETE"
    assert len(report["rows"]) == 12
    assert {row["arm"] for row in report["rows"]} == {"C", "C-custom", "T"}
    assert all(row["introduced_prediction"] is None and not row["live_eligible"]
               for row in report["rows"])


def test_successful_fake_can_never_be_live_evidence(tmp_path: Path) -> None:
    """what_bug_this_catches: valid mock JSON promoted to measured live comparison rows."""
    manifest, resource, path = setup_case(tmp_path)
    raw = output(resource["address"])
    add_fake(tmp_path, manifest, raw)
    report = compare(manifest, fake_only=True)
    assert report["measurement_status"] == "SIMULATED_INELIGIBLE"
    assert any(row["status"] == "simulated" for row in report["rows"])
    assert all(row["introduced_prediction"] is None and not row["live_eligible"]
               for row in report["rows"])
    artifact = simulate_capture(arm="C-custom", plan_path=path,
                               runner=FakeRunner(raw, b"", 1), parser=parse_output,
                               check_ids=("CKV_M4_R2",))
    assert artifact.status == "ok" and not artifact.live_eligible
    with pytest.raises(ValueError, match="simulated"):
        artifact.as_capture()


def test_fake_only_rejects_supplied_runtime_runner(tmp_path: Path) -> None:
    """what_bug_this_catches: a live runner injected into supposedly offline fake mode."""
    manifest, _, _ = setup_case(tmp_path)
    with pytest.raises(ValueError, match="runtime runner"):
        compare(manifest, runner=FakeRunner(), fake_only=True)


def test_changed_plan_digest_aborts_before_capture(tmp_path: Path) -> None:
    """what_bug_this_catches: arms compare different plan bytes under one case label."""
    manifest, _, path = setup_case(tmp_path)
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(ValueError, match="frozen plan bytes"):
        compare(manifest)


def test_foreign_scanner_identity_is_invalid(tmp_path: Path) -> None:
    """what_bug_this_catches: valid scanner check attached to the wrong plan resource."""
    manifest, _, _ = setup_case(tmp_path)
    add_fake(tmp_path, manifest, output("aws_db_instance.other"))
    report = compare(manifest, fake_only=True)
    rows = [row for row in report["rows"] if row["arm"] == "C-custom"]
    assert rows and all(row["status"] == "invalid" for row in rows)
    assert all(row["introduced_prediction"] is None for row in rows)


def test_timeout_is_preserved_even_with_empty_json(tmp_path: Path) -> None:
    """what_bug_this_catches: timeout omitted from missing/failed-attempt denominators."""
    manifest, _, _ = setup_case(tmp_path)
    add_fake(tmp_path, manifest, b"{}", timed_out=True)
    report = compare(manifest, fake_only=True)
    rows = [row for row in report["rows"] if row["arm"] == "C-custom"]
    assert all(row["status"] == "timeout" and row["introduced_prediction"] is None for row in rows)
    receipt = next(row for row in report["capture_receipts"] if row["arm"] == "C-custom")
    assert receipt["stdout_sha256"] == sha(b"{}")


def test_truncated_output_is_never_parsed_as_success(tmp_path: Path) -> None:
    """what_bug_this_catches: capped valid-prefix output treated as a full scanner report."""
    _, resource, path = setup_case(tmp_path)
    artifact = simulate_capture(arm="C", plan_path=path,
                               runner=FakeRunner(output(resource["address"]), b"", 1),
                               parser=parse_output, check_ids=("CKV_M4_R2",),
                               limits=Limits(stdout_bytes=16))
    assert artifact.status == "invalid" and artifact.output_truncated


def verified_mapping() -> Mapping:
    # Artificial wire metadata for pure gate tests, never a measured scanner pin.
    return Mapping(arm="C-custom", scanner_name="checkov", version="synthetic-gate-only",
                   executable_sha256="b" * 64, policy_sha256="c" * 64,
                   rule_id="R2", check_ids=("CKV_M4_R2",),
                   supported_actions=(("create",),), supported_types=("aws_db_instance",),
                   compatibility="verified", compatibility_evidence_sha256="d" * 64)


def test_mapping_cannot_qualify_wrong_type_action_provider_or_absent_check(tmp_path: Path) -> None:
    """what_bug_this_catches: Cartesian/absent-check overlap silently reported as eligible."""
    _, resource, _ = setup_case(tmp_path)
    mapping = verified_mapping()
    artifact = ScanArtifact("C-custom", "checkov", "ok", "live", "a" * 64,
                            "synthetic-gate-only", "b" * 64, "e" * 64, "f" * 64,
                            "1" * 64, "2" * 64, "c" * 64, "verified", ("CKV_M4_R2",),
                            (Observation("CKV_M4_R2", resource["address"], "passed"),),
                            raw_exit_code=0, stdout_sha256="3" * 64,
                            stderr_sha256="4" * 64, elapsed_seconds=0.01)
    assert cell_status(artifact, mapping, resource) == "eligible"
    assert cell_status(artifact, mapping, dict(resource, type="aws_s3_bucket")) == "unmapped"
    assert cell_status(artifact, mapping, dict(resource, provider_name="other")) == "unmapped"
    assert cell_status(artifact, mapping, dict(resource, change={"actions": ["delete"]})) == "unmapped"
    assert cell_status(replace(artifact, observations=()), mapping, resource) == "incomplete"
    assert cell_status(replace(artifact, execution_kind="fake"), mapping, resource) == "incomplete"
    assert cell_status(replace(artifact, stdout_sha256=None), mapping, resource) == "incomplete"


def test_missing_real_pins_never_selects_or_calls_a_runner(tmp_path: Path) -> None:
    """what_bug_this_catches: empty activation settings triggering a scanner process."""
    manifest, _, _ = setup_case(tmp_path)
    manifest["arms"] = {"C": {"check_ids": ["CKV_M4_R2"]}}

    def forbidden_runner(_):
        raise AssertionError("missing pins must not invoke any runner")

    report = compare(manifest, runner=forbidden_runner)
    assert all(row["introduced_prediction"] is None for row in report["rows"])


def test_hidden_scope_is_not_read_by_development_driver(tmp_path: Path) -> None:
    """what_bug_this_catches: convenience scanner command exposing a sealed holdout."""
    manifest, _, _ = setup_case(tmp_path)
    manifest["input_scope"] = "heldout"
    with pytest.raises(ValueError, match="development synthetic"):
        compare(manifest)
