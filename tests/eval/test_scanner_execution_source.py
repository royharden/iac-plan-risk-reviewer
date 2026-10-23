"""Pinned-execution regression SOURCE only; no runner/tests executed in Dirty Mode.

All grants, files, digests and version strings below are artificial unit fixtures.
Tests exercise approval/parsing with no subprocess; none is real execution proof.
"""
from __future__ import annotations

from dataclasses import asdict, replace
import json

import pytest

from eval.scanners.runner import (ApprovedInvocation, BoundedSubprocessRunner, Invocation,
                                 Limits, RunResult, ScannerPin, capture, digest,
                                 fixed_environment, invocation_digest, load_execution_grant,
                                 manifest_digest)


def fixture(tmp_path):
    def write(name, raw):
        path = tmp_path / name
        path.write_bytes(raw)
        return path, digest(raw)

    plan = {"format_version": "1.2", "resource_changes": [{"address": "aws_db_instance.fixture",
            "mode": "managed", "type": "aws_db_instance", "provider_name": "registry.terraform.io/hashicorp/aws",
            "change": {"actions": ["create"], "before": None, "after": {"publicly_accessible": True}}}]}
    source, source_sha = write("plan.json", json.dumps(plan).encode())
    executable, executable_sha = write("scanner.fixture", b"nonexecutable unit fixture")
    dependencies, deps_sha = write("dependencies.json", b"artificial dependency metadata")
    version, version_sha = write("version.json", json.dumps({"scanner_name": "checkov", "version": "fixture-only",
        "executable_sha256": executable_sha, "dependency_manifest_sha256": deps_sha}).encode())
    config, config_sha = write("config.json", b"{}")
    policy, policy_sha = write("policy.json", json.dumps({"scanner_name": "checkov",
                                                       "check_ids": ["CKV_FIXTURE"], "files": []}).encode())
    argv = (str(executable), "--file", str(source), "--framework", "terraform_plan", "--output", "json",
            "--compact", "--check", "CKV_FIXTURE", "--config-file", str(config), "--skip-download",
            "--skip-results-upload", "--download-external-modules", "false")
    pins = ((source, source_sha, 16 * 1024 * 1024), (config, config_sha, 4096),
            (executable, executable_sha, 256 * 1024 * 1024), (dependencies, deps_sha, 1024 * 1024),
            (version, version_sha, 64 * 1024), (policy, policy_sha, 1024 * 1024))
    invocation = Invocation(argv, tmp_path, fixed_environment(tmp_path), Limits(), pins)
    approval = ApprovedInvocation("C", "checkov", "fixture-only", source_sha, executable_sha, deps_sha,
                                  version_sha, config_sha, policy_sha, invocation_digest(invocation), ("CKV_FIXTURE",))
    manifest = {"input_scope": "development_synthetic", "synthetic_input_attested": True,
                "build_sha256": "a" * 64, "cases": []}
    grant = {"schema_version": "m4-local-scanner-execution-grant-v1", "grant_id": "fixture_grant",
             "operator_id": "fixture_operator", "build_sha256": "a" * 64,
             "comparison_manifest_sha256": manifest_digest(manifest), "invocations": [asdict(approval)],
             "dirty_mode_closed": True, "local_only": True, "network_denied": True,
             "descendants_confined": True, "no_provider_credentials": True, "synthetic_input_attested": True}
    return invocation, approval, manifest, grant, (source, executable, dependencies, version, config, policy)


def load(tmp_path, manifest, grant):
    raw = json.dumps(grant).encode()
    path = tmp_path / "operator-grant.json"
    path.write_bytes(raw)
    return load_execution_grant(path, expected_sha256=digest(raw), manifest=manifest)


def test_boolean_alone_cannot_authorize_scanner_execution(tmp_path) -> None:
    """what_bug_this_catches: old activation Boolean starts a process without an exact operator grant."""
    invocation, _, _, _, _ = fixture(tmp_path)
    with pytest.raises(PermissionError, match="pinned operator grant"):
        BoundedSubprocessRunner(activation_authorized=True).approval(invocation)


def test_grant_requires_external_digest_and_closed_scope(tmp_path) -> None:
    """what_bug_this_catches: embedded/self-chosen grant digest or extra command scope accepted."""
    _, _, manifest, grant, _ = fixture(tmp_path)
    path = tmp_path / "grant.json"
    path.write_bytes(json.dumps(grant).encode())
    with pytest.raises(ValueError, match="external pin"):
        load_execution_grant(path, expected_sha256="0" * 64, manifest=manifest)
    grant["arbitrary_command"] = ["terraform", "apply"]
    with pytest.raises(ValueError, match="scope"):
        load(tmp_path, manifest, grant)


@pytest.mark.parametrize("flag", ["dirty_mode_closed", "network_denied", "synthetic_input_attested"])
def test_required_operator_attestation_cannot_be_omitted(tmp_path, flag) -> None:
    """what_bug_this_catches: mode/environment/synthetic obligations downgraded by partial grant."""
    _, _, manifest, grant, _ = fixture(tmp_path)
    grant[flag] = False
    with pytest.raises(ValueError, match="attestation"):
        load(tmp_path, manifest, grant)


def test_exact_approval_parses_without_executing_anything(tmp_path) -> None:
    """what_bug_this_catches: approval matching loses exact input/config/version identity."""
    invocation, expected, manifest, grant, _ = fixture(tmp_path)
    runner = BoundedSubprocessRunner(True, load(tmp_path, manifest, grant))
    runner.verify_manifest(manifest)
    assert runner.approval(invocation) == expected
    assert not list(tmp_path.glob(".scanner-start-*"))


def test_grant_cannot_be_reused_for_changed_manifest(tmp_path) -> None:
    """what_bug_this_catches: same build label permits different cases/arm configuration."""
    _, _, manifest, grant, _ = fixture(tmp_path)
    runner = BoundedSubprocessRunner(True, load(tmp_path, manifest, grant))
    with pytest.raises(PermissionError, match="exact synthetic manifest"):
        runner.verify_manifest(dict(manifest, cases=[{"case_id": "different"}]))


def test_forwarded_provider_environment_rejected_even_with_matching_fingerprint(tmp_path) -> None:
    """what_bug_this_catches: an approval hash alone allows forwarding inherited provider keys."""
    invocation, _, manifest, grant, _ = fixture(tmp_path)
    changed = replace(invocation, environment=invocation.environment + (("AWS_SECRET_ACCESS_KEY", "synthetic_canary"),))
    grant["invocations"][0]["invocation_sha256"] = invocation_digest(changed)
    runner = BoundedSubprocessRunner(True, load(tmp_path, manifest, grant))
    with pytest.raises(PermissionError, match="credential-free"):
        runner.approval(changed)


def test_arbitrary_plugin_or_apply_flag_not_enabled_by_grant_hash(tmp_path) -> None:
    """what_bug_this_catches: generic grant turns the runner into an arbitrary command launcher."""
    invocation, _, manifest, grant, _ = fixture(tmp_path)
    changed = replace(invocation, argv=invocation.argv + ("--external-checks-git", "synthetic-invalid"))
    grant["invocations"][0]["invocation_sha256"] = invocation_digest(changed)
    runner = BoundedSubprocessRunner(True, load(tmp_path, manifest, grant))
    with pytest.raises(PermissionError, match="unapproved"):
        runner.approval(changed)


def test_approved_config_pin_must_resolve_to_invocation_file(tmp_path) -> None:
    """what_bug_this_catches: binary grant matches while actual config/policy identity changes."""
    invocation, _, manifest, grant, _ = fixture(tmp_path)
    grant["invocations"][0]["config_sha256"] = "b" * 64
    runner = BoundedSubprocessRunner(True, load(tmp_path, manifest, grant))
    with pytest.raises(PermissionError, match="files differ"):
        runner.approval(invocation)


def test_protocol_cannot_manufacture_live_receipts(tmp_path) -> None:
    """what_bug_this_catches: injected fake/protocol labels its response live and creates executed evidence."""
    invocation, _, _, _, paths = fixture(tmp_path)
    source, executable, dependencies, version, config, policy = paths
    file_pins = {str(path): sha for path, sha, _ in invocation.pinned_files}
    pin = ScannerPin(executable, "fixture-only", file_pins[str(executable)], file_pins[str(dependencies)],
                     file_pins[str(version)], dependencies, version)

    def forged(_):
        return RunResult("live", 0, b"{}", b"", 0.0,
                         operator_grant_sha256="c" * 64, start_receipt_sha256="d" * 64,
                         terminal_receipt_sha256="e" * 64)

    result = capture(arm="C", pin=pin, plan_path=source, config_path=config, workspace=tmp_path,
                     runner=forged, argv_builder=lambda: invocation.argv, parser=lambda _: (),
                     check_ids=("CKV_FIXTURE",), policy_sha256=file_pins[str(policy)], policy_manifest_path=policy)
    assert result.status == "invalid" and result.execution_kind == "none"
    assert result.operator_grant_sha256 is None and result.terminal_receipt_sha256 is None
    assert not result.live_eligible
