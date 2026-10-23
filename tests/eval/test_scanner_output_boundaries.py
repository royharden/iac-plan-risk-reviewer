"""Targeted adversarial regression SOURCE, not run or imported in Dirty Mode.

Complements existing driver/bridge tests. All stdout and installation metadata are
artificial plumbing fixtures; none is an oracle label or real execution receipt.
"""
from __future__ import annotations

import hashlib
import json

import pytest

from eval.runner.scoring import ArmRow
from eval.scanners.checkov_adapter import parse_output as parse_checkov
from eval.scanners.trivy_adapter import parse_output as parse_trivy
from eval.scanners.runner import (FakeRunner, Limits, RunResult, ScannerPin,
                                 capture, simulate_capture)


ADDRESS = "aws_db_instance.boundary_fixture"
CHECK = "CKV_ARTIFICIAL_BOUNDARY"


def plan() -> dict:
    resource = {"address": ADDRESS, "mode": "managed", "type": "aws_db_instance",
                "provider_name": "registry.terraform.io/hashicorp/aws",
                "change": {"actions": ["update"], "before": {"publicly_accessible": False},
                           "after": {"publicly_accessible": True}}}
    return {"format_version": "1.2", "resource_changes": [resource]}


def scanner_output() -> dict:
    return {"check_type": "terraform_plan", "results": {"passed_checks": [
        {"check_id": CHECK, "resource": ADDRESS, "check_result": {"result": "PASSED"}}],
        "failed_checks": [], "skipped_checks": [], "parsing_errors": []}}


def encoded(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, allow_nan=False).encode()


def simulate(tmp_path, *, raw: bytes | None = None, source: dict | None = None,
             stderr: bytes = b"", timeout: bool = False, limits: Limits = Limits()):
    path = tmp_path / "input.json"
    path.write_bytes(encoded(plan() if source is None else source))
    return simulate_capture(arm="C", plan_path=path,
                            runner=FakeRunner(encoded(scanner_output()) if raw is None else raw,
                                              stderr, 0, timeout),
                            parser=parse_checkov, check_ids=(CHECK,), limits=limits)


@pytest.mark.parametrize("raw", [b"\xff", b'{"check_type":"terraform_plan","check_type":"terraform_plan"}'])
def test_duplicate_key_or_non_utf8_scanner_output_is_invalid(tmp_path, raw) -> None:
    """what_bug_this_catches: scanner result duplicate keys/encoding errors silently normalized."""
    result = simulate(tmp_path, raw=raw)
    assert result.status == "invalid" and not result.live_eligible
    assert result.observations == ()


def test_quiet_checkov_shape_cannot_supply_missing_pass_or_parse_categories() -> None:
    """what_bug_this_catches: quiet JSON's absent categories inferred as empty successful checks."""
    with pytest.raises(ValueError):
        parse_checkov({"check_type": "terraform_plan", "results": {"failed_checks": []}})


def test_checkov_category_and_record_result_cannot_disagree() -> None:
    """what_bug_this_catches: failed record under passed_checks becomes a negative observation."""
    payload = scanner_output()
    payload["results"]["passed_checks"][0]["check_result"]["result"] = "FAILED"
    with pytest.raises(ValueError, match="contradiction"):
        parse_checkov(payload)


def test_reported_parse_error_cannot_hide_behind_complete_passed_records() -> None:
    """what_bug_this_catches: valid-looking success records conceal scanner parser failures."""
    payload = scanner_output()
    payload["results"]["parsing_errors"] = ["synthetic_private_input"]
    with pytest.raises(ValueError, match="parse evidence"):
        parse_checkov(payload)


def test_stderr_overflow_invalidates_otherwise_complete_json(tmp_path) -> None:
    """what_bug_this_catches: only stdout cap enforced while stderr capture is incomplete."""
    result = simulate(tmp_path, stderr=b"x" * 17, limits=Limits(stderr_bytes=16))
    assert result.status == "invalid" and result.output_truncated
    assert result.observations == () and not result.live_eligible


def test_timeout_wins_over_well_formed_completed_looking_stdout(tmp_path) -> None:
    """what_bug_this_catches: late valid JSON rescues an attempt that exceeded its deadline."""
    result = simulate(tmp_path, timeout=True)
    assert result.status == "timeout" and result.stdout_sha256 is not None
    assert result.observations == () and not result.live_eligible


def test_input_byte_cap_applies_before_any_output_interpretation(tmp_path) -> None:
    """what_bug_this_catches: accepted stdout promotes a plan too large for scanner admission."""
    result = simulate(tmp_path, limits=Limits(plan_bytes=64))
    assert result.status == "invalid" and result.stdout_sha256 is None
    assert not result.live_eligible


@pytest.mark.parametrize("identity_mode", ["deposed", "duplicate_address"])
def test_lossy_resource_identity_is_rejected_before_output(tmp_path, identity_mode) -> None:
    """what_bug_this_catches: scanner's address-only identity merges different change instances."""
    source = plan()
    if identity_mode == "deposed":
        source["resource_changes"][0]["deposed"] = "synthetic_deposed"
    else:
        source["resource_changes"].append(dict(source["resource_changes"][0]))
    result = simulate(tmp_path, source=source)
    assert result.status == "invalid" and result.stdout_sha256 is None
    assert not result.live_eligible


def test_duplicate_check_resource_observations_are_not_deduplicated_to_success(tmp_path) -> None:
    """what_bug_this_catches: conflicting/repeated scanner output collapsed to a convenient row."""
    payload = scanner_output()
    payload["results"]["passed_checks"] *= 2
    result = simulate(tmp_path, raw=encoded(payload))
    assert result.status == "invalid" and result.observations == ()


def test_same_address_different_plan_during_capture_aborts(tmp_path) -> None:
    """what_bug_this_catches: matching address/output hides changed raw input during a runner call."""
    # Complete artificial pin metadata lets only our injected Python fake run.
    # The .fixture file is data, never a real or executed scanner binary.
    path, executable = tmp_path / "plan.json", tmp_path / "not-executable.fixture"
    path.write_bytes(encoded(plan()))
    original_sha = hashlib.sha256(path.read_bytes()).hexdigest()
    executable.write_bytes(b"artificial nonexecutable pin data")
    dependencies, version, config, policy = (tmp_path / name for name in (
        "dependencies.json", "version.json", "config.json", "policy.json"))
    dependencies.write_bytes(b"artificial dependency inventory")
    exe_sha = hashlib.sha256(executable.read_bytes()).hexdigest()
    deps_sha = hashlib.sha256(dependencies.read_bytes()).hexdigest()
    version.write_bytes(encoded({"scanner_name": "checkov", "version": "artificial-only",
                                 "executable_sha256": exe_sha, "dependency_manifest_sha256": deps_sha}))
    config.write_bytes(b"{}")
    policy.write_bytes(encoded({"scanner_name": "checkov", "check_ids": [CHECK], "files": []}))
    pin = ScannerPin(executable, "artificial-only", exe_sha, deps_sha,
                     hashlib.sha256(version.read_bytes()).hexdigest(), dependencies, version)

    def mutating_fake(_):
        changed = plan()
        changed["resource_changes"][0]["change"]["after"]["publicly_accessible"] = False
        path.write_bytes(encoded(changed))
        return RunResult("fake", 0, encoded(scanner_output()), b"", 0.0)

    result = capture(arm="C", pin=pin, plan_path=path, config_path=config, workspace=tmp_path,
                     runner=mutating_fake, argv_builder=lambda: (str(executable), "--fixture-only"),
                     parser=parse_checkov, check_ids=(CHECK,), policy_manifest_path=policy,
                     policy_sha256=hashlib.sha256(policy.read_bytes()).hexdigest())
    assert result.status == "invalid" and result.plan_sha256 == original_sha
    assert result.observations == () and not result.live_eligible


def test_trivy_unknown_status_remains_unknown_and_unrecognized_status_rejects() -> None:
    """what_bug_this_catches: unrecognized/unknown scanner status silently treated as a pass."""
    payload = {"SchemaVersion": 2, "Results": [{"Type": "terraformplan-json", "Misconfigurations": [
        {"ID": "AVD_ARTIFICIAL", "CauseMetadata": {"Resource": ADDRESS}, "Status": "UNKNOWN"}]}]}
    assert parse_trivy(payload)[0].status == "unknown"
    payload["Results"][0]["Misconfigurations"][0]["Status"] = "SILENT_SUCCESS"
    with pytest.raises(ValueError):
        parse_trivy(payload)


def test_shared_binary_wire_rejects_smuggled_full_outcome() -> None:
    """what_bug_this_catches: binary negative acquires an invented full clear/unchanged label."""
    with pytest.raises(ValueError, match="must not invent"):
        ArmRow(schema_version=2, case_id="fixture_case", resource_id="fixture_resource", rule_id="R2",
               arm="C", status="not_run", prediction_target="introduced_risk",
               introduced_prediction=False, outcome="clear", source_sha256="a" * 64,
               build_sha256="b" * 64, measurement_ref="artificial-boundary-only")
