"""Independent v2 identity plumbing using mocked scanner Popen exclusively.

All approvals are artificial test grants; passing these tests attests no genuine
scanner/policy execution, compatibility, or benchmark eligibility.
"""

from __future__ import annotations

import hashlib
import io
import json
import time
from dataclasses import asdict, replace
from pathlib import Path, PurePosixPath

import pytest
from eval.scanners.bundle_inventory import load_bundle_inventory
from test_trivy_bundle_inventory import FIXTURES, SMALL_SHA, canonical, small_tree

from eval.runner.scoring import EligibilityManifest, record_digest
from eval.scanners import bundle_inventory, trivy_adapter
from eval.scanners.driver import compare
from eval.scanners.run_manifest import ScannerComponents, ScannerRunContext, adapt_scanner_report
from eval.scanners.runner import (
    ApprovedInvocation,
    BoundedSubprocessRunner,
    Invocation,
    Limits,
    RunResult,
    ScannerPin,
    invocation_digest,
    load_execution_grant,
    manifest_digest,
)
from eval.scanners.scoring_bridge import bridge_report, report_digest
from iac_review.contracts.manifest import ArtifactRef, CaseBinding, ComponentVersion, RunManifest


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


@pytest.fixture(autouse=True)
def scanner_processes_are_mocked(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("real scanner process forbidden in reviewer tests")

    monkeypatch.setattr("subprocess.Popen", forbidden)


class MockProcess:
    pid = 424242
    returncode = 1

    def __init__(self, raw):
        self.stdout = io.BytesIO(raw)
        self.stderr = io.BytesIO(b"owned synthetic stderr")

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        assert timeout is not None
        return self.returncode

    def kill(self):
        self.returncode = -9


class RecordInvocation:
    def __init__(self):
        self.calls = []

    def __call__(self, invocation):
        self.calls.append(invocation)
        return RunResult("none", None, b"", b"", 0.0)


def binding_fixture(tmp_path):
    descriptor, root, tree = small_tree(tmp_path)
    binding = load_bundle_inventory(descriptor, tmp_path)

    def write(name, raw):
        path = tmp_path / name
        path.write_bytes(raw)
        return path

    resource = {
        "address": "aws_db_instance.synthetic",
        "mode": "managed",
        "type": "aws_db_instance",
        "provider_name": "registry.terraform.io/hashicorp/aws",
        "change": {"actions": ["create"], "before": None, "after": {"publicly_accessible": True}},
    }
    plan = write("plan.json", canonical({"format_version": "1.2", "resource_changes": [resource]}))
    executable = write("scanner.fixture", b"NOT AN EXECUTABLE: public test payload")
    deps = write("dependencies.json", b"synthetic dependencies")
    version = write(
        "version.json",
        canonical(
            {
                "scanner_name": "trivy",
                "version": "test-only",
                "executable_sha256": sha(executable.read_bytes()),
                "dependency_manifest_sha256": sha(deps.read_bytes()),
            }
        ),
    )
    config = write("config.json", b"{}")
    policy = write(
        "policy-receipt.json",
        canonical(
            {
                "schema_version": "m4-scanner-policy-manifest-v2",
                "scanner_name": "trivy",
                "check_ids": ["TEST_R2"],
                "bundle_tree_sha256": SMALL_SHA,
            }
        ),
    )
    mapping = {
        "arm": "T",
        "scanner_name": "trivy",
        "version": "test-only",
        "executable_sha256": sha(executable.read_bytes()),
        "policy_sha256": sha(policy.read_bytes()),
        "rule_id": "R2",
        "check_ids": ["TEST_R2"],
        "supported_actions": [["create"]],
        "supported_types": ["aws_db_instance"],
        "compatibility": "verified",
        "compatibility_evidence_sha256": "b" * 64,
    }
    pin = ScannerPin(
        executable,
        "test-only",
        sha(executable.read_bytes()),
        sha(deps.read_bytes()),
        sha(version.read_bytes()),
        deps,
        version,
    )
    settings = {
        "workspace": str(tmp_path),
        "check_ids": ["TEST_R2"],
        "pin": {
            "executable": str(executable),
            "version": "test-only",
            "executable_sha256": pin.executable_sha256,
            "dependency_manifest_sha256": pin.dependency_manifest_sha256,
            "version_evidence_sha256": pin.version_evidence_sha256,
            "dependency_manifest_path": str(deps),
            "version_evidence_path": str(version),
        },
        "config_path": str(config),
        "policy_manifest_path": str(policy),
        "policy_sha256": sha(policy.read_bytes()),
        "bundle_inventory": descriptor,
        "mappings": [mapping],
    }
    manifest = {
        "schema_version": "m4-scanner-run-v2",
        "input_scope": "development_synthetic",
        "synthetic_input_attested": True,
        "build_sha256": "a" * 64,
        "cases": [
            {
                "case_id": "case_1",
                "plan_path": str(plan),
                "plan_sha256": sha(plan.read_bytes()),
                "resources": [{"resource_id": "resource_1", "address": resource["address"]}],
            }
        ],
        "arms": {"T": settings},
    }
    kwargs = {
        "plan_path": plan,
        "pin": pin,
        "config_path": config,
        "workspace": tmp_path,
        "check_ids": ("TEST_R2",),
        "policy_sha256": sha(policy.read_bytes()),
        "policy_manifest_path": policy,
        "bundle_inventory": binding,
    }
    return manifest, kwargs, root, tree


def artificial_granted_runner(tmp_path, manifest, kwargs):
    recorder = RecordInvocation()
    trivy_adapter.scan(**kwargs, runner=recorder)
    assert len(recorder.calls) == 1, "valid v2 binding never reached trusted runner boundary"
    invocation = recorder.calls[0]
    pin = kwargs["pin"]
    approved = ApprovedInvocation(
        "T",
        "trivy",
        pin.version,
        sha(kwargs["plan_path"].read_bytes()),
        pin.executable_sha256,
        pin.dependency_manifest_sha256,
        pin.version_evidence_sha256,
        sha(kwargs["config_path"].read_bytes()),
        kwargs["policy_sha256"],
        invocation_digest(invocation),
        kwargs["check_ids"],
    )
    grant = {
        "schema_version": "m4-local-scanner-execution-grant-v1",
        "grant_id": "test_only_grant",
        "operator_id": "synthetic_test_operator",
        "build_sha256": manifest["build_sha256"],
        "comparison_manifest_sha256": manifest_digest(manifest),
        "invocations": [asdict(approved)],
        "dirty_mode_closed": True,
        "local_only": True,
        "network_denied": True,
        "descendants_confined": True,
        "no_provider_credentials": True,
        "synthetic_input_attested": True,
    }
    path = tmp_path / "test-only-grant.json"
    raw = canonical(grant)
    path.write_bytes(raw)
    parsed = load_execution_grant(path, expected_sha256=sha(raw), manifest=manifest)
    return BoundedSubprocessRunner(True, parsed), invocation, approved, grant


def mocked_popen(monkeypatch, kwargs, mutate=None):
    calls = []
    output = canonical(
        {
            "SchemaVersion": 2,
            "Results": [
                {
                    "Type": "terraformplan-json",
                    "Misconfigurations": [
                        {
                            "ID": "TEST_R2",
                            "Status": "FAIL",
                            "CauseMetadata": {"Resource": "aws_db_instance.synthetic"},
                        }
                    ],
                }
            ],
        }
    )

    def popen(argv, **options):
        calls.append((argv, options))
        assert options["shell"] is False and options["cwd"] == kwargs["workspace"]
        if mutate is not None:
            mutate()
        return MockProcess(output)

    monkeypatch.setattr("subprocess.Popen", popen)
    return calls, output


def test_v2_binding_reaches_adapter_invocation_and_manifest_pin(tmp_path):
    """what_bug_this_catches: descriptor accepted but omitted from actual invocation."""
    manifest, kwargs, _, tree = binding_fixture(tmp_path)
    _, invocation, _, _ = artificial_granted_runner(tmp_path, manifest, kwargs)
    assert invocation.bundle_inventory == kwargs["bundle_inventory"]
    assert (tree, SMALL_SHA, 524288) in invocation.pinned_files
    assert invocation_digest(replace(invocation, bundle_inventory=None)) != invocation_digest(
        invocation
    )
    assert invocation_digest(
        replace(invocation, attempt_deadline=time.monotonic() + 1)
    ) == invocation_digest(invocation)


@pytest.mark.parametrize(
    "field,value",
    [
        ("tree_sha256", "0" * 64),
        ("root", Path("C:/different/policy")),
        ("manifest_path", Path("C:/different/manifest.json")),
    ],
)
def test_each_typed_binding_field_changes_invocation_identity(tmp_path, field, value):
    manifest, kwargs, _, _ = binding_fixture(tmp_path)
    _, invocation, _, _ = artificial_granted_runner(tmp_path, manifest, kwargs)
    changed = replace(invocation.bundle_inventory, **{field: value})
    assert invocation_digest(replace(invocation, bundle_inventory=changed)) != invocation_digest(
        invocation
    )


def test_typed_binding_cannot_select_another_profile(tmp_path):
    _, kwargs, _, _ = binding_fixture(tmp_path)
    with pytest.raises(ValueError):
        replace(kwargs["bundle_inventory"], profile="different")


def test_all_effective_caps_bound_in_invocation_identity(tmp_path, monkeypatch):
    """what_bug_this_catches: same grant survives a source-side cap change."""
    manifest, kwargs, _, _ = binding_fixture(tmp_path)
    _, invocation, _, _ = artificial_granted_runner(tmp_path, manifest, kwargs)
    expected = (
        ("max_regular_files", 1024),
        ("max_directories_excluding_root", 256),
        ("max_all_entries_excluding_root", 1280),
        ("max_file_bytes", 65536),
        ("max_aggregate_file_bytes", 2097152),
        ("max_relative_path_bytes", 256),
        ("max_relative_depth", 12),
        ("max_canonical_manifest_bytes", 524288),
    )
    assert type(bundle_inventory.CAPS) is tuple and bundle_inventory.CAPS == expected
    original = invocation_digest(invocation)
    for key, value in expected:
        changed = tuple((name, amount + 1 if name == key else amount) for name, amount in expected)
        monkeypatch.setattr(bundle_inventory, "CAPS", changed)
        assert invocation_digest(invocation) != original, key
    monkeypatch.setattr(bundle_inventory, "CAPS", expected)


def test_mocked_success_closure_and_report_scoring_roundtrip(tmp_path, monkeypatch):
    """what_bug_this_catches: tree identity is lost in grant/capture/report joins."""
    manifest, kwargs, _, _ = binding_fixture(tmp_path)
    runner, _, approval, _ = artificial_granted_runner(tmp_path, manifest, kwargs)
    calls, output = mocked_popen(monkeypatch, kwargs)
    report = compare(manifest, runner=runner)
    assert len(calls) == 1
    terminal_path = tmp_path / f".scanner-terminal-{approval.invocation_sha256}.json"
    raw = terminal_path.read_bytes()
    terminal = json.loads(raw)
    evidence = terminal["bundle_inventory"]
    assert set(evidence) == {"expected_tree_sha256", "before", "after", "closure_error"}
    assert evidence["expected_tree_sha256"] == SMALL_SHA and evidence["closure_error"] is None
    for phase in ("before", "after"):
        assert set(evidence[phase]) == {
            "tree_sha256",
            "files",
            "directories",
            "aggregate_file_bytes",
            "elapsed_seconds",
        }
        assert {k: v for k, v in evidence[phase].items() if k != "elapsed_seconds"} == {
            "tree_sha256": SMALL_SHA,
            "files": 3,
            "directories": 3,
            "aggregate_file_bytes": 26,
        }
        assert evidence[phase]["elapsed_seconds"] >= 0
    receipt = next(row for row in report["capture_receipts"] if row["arm"] == "T")
    assert receipt["terminal_receipt_sha256"] == sha(raw)
    assert receipt["stdout_sha256"] == sha(output)
    assert receipt["invocation_sha256"] == approval.invocation_sha256
    rows = [row for row in report["rows"] if row["arm"] == "T" and row["rule_id"] == "R2"]
    assert len(rows) == 1 and rows[0]["introduced_prediction"] is True
    decoded = json.loads(json.dumps(report))
    batch = bridge_report(
        decoded, expected_report_sha256=report_digest(report), edition_id="test_edition"
    )
    assert len(batch.rows) == 12
    # Even a mock-success transport requires separate external execution evidence.
    assert all(row.eligibility_ref is None for row in batch.rows)
    case = CaseBinding(
        case_id="case_1",
        split="dev",
        configuration_id="test_cfg",
        family_id="test_family",
        mutation_lineage="test_mutation",
        raw_source_sha256=sha(kwargs["plan_path"].read_bytes()),
    )
    refs = tuple(
        ArtifactRef(
            artifact_id=name,
            role="producer",
            path="private/" + name + ".json",
            sha256=receipt[key],
            bytes_upper=1048576,
        )
        for name, key in (
            ("grant", "operator_grant_sha256"),
            ("start", "start_receipt_sha256"),
            ("terminal", "terminal_receipt_sha256"),
        )
    )
    known = tuple(
        ScannerComponents(
            arm,
            ComponentVersion(
                component_id="test_scanner_" + arm.replace("-", "_"),
                kind="scanner",
                name="checkov",
                version="test-only",
                sha256="c" * 64,
            ),
            ComponentVersion(
                component_id="test_config_" + arm.replace("-", "_"),
                kind="config",
                name="test-config",
                version="test-only",
                sha256="d" * 64,
            ),
        )
        for arm in ("C", "C-custom")
    )
    context = ScannerRunContext(
        "test_run",
        "test_edition",
        kwargs["policy_sha256"],
        "e" * 64,
        "f" * 64,
        (case,),
        refs,
        known,
    )
    eligibility = EligibilityManifest(edition_id="test_edition", rows=())
    adapted = adapt_scanner_report(
        decoded,
        expected_report_sha256=report_digest(report),
        context=context,
        eligibility=eligibility,
        expected_eligibility_sha256=record_digest(eligibility),
    )
    assert adapted.manifest is not None, adapted.missing
    roundtrip = RunManifest.model_validate_json(adapted.manifest.model_dump_json())
    assert roundtrip == adapted.manifest
    assert len(roundtrip.attempts) == 3 and not any(
        row.claimed_eligible for row in roundtrip.eligibility
    )


@pytest.mark.parametrize("drift", ["same-size", "extra-empty-dir", "metadata", "manifest"])
def test_closure_drift_keeps_every_failure_row_null_and_raw_evidence(tmp_path, monkeypatch, drift):
    """what_bug_this_catches: preflight success masks mutation during scanner attempt."""
    manifest, kwargs, root, tree = binding_fixture(tmp_path)
    runner, _, approval, _ = artificial_granted_runner(tmp_path, manifest, kwargs)

    def mutate():
        if drift == "same-size":
            (root / "a/check.rego").write_bytes(b"ALPHA\n")
        elif drift == "extra-empty-dir":
            (root / "surprise").mkdir()
        elif drift == "metadata":
            (root / "metadata.json").write_bytes(b'{"local":false}')
        else:
            tree.write_bytes(tree.read_bytes() + b" ")

    calls, output = mocked_popen(monkeypatch, kwargs, mutate)
    report = compare(manifest, runner=runner)
    assert len(calls) == 1 and len(report["rows"]) == 12
    assert all(
        row["introduced_prediction"] is None and not row["live_eligible"] for row in report["rows"]
    )
    receipt = next(row for row in report["capture_receipts"] if row["arm"] == "T")
    assert receipt["status"] in {"invalid", "error", "timeout"}
    terminal_raw = (tmp_path / f".scanner-terminal-{approval.invocation_sha256}.json").read_bytes()
    terminal = json.loads(terminal_raw)
    assert terminal["bundle_inventory"]["after"] is None
    assert terminal["bundle_inventory"]["closure_error"] == "complete_tree_verification_failed"
    assert receipt["terminal_receipt_sha256"] == sha(terminal_raw)
    assert (tmp_path / terminal["stdout_file"]).read_bytes() == output
    assert terminal["retained_output_complete"] is True
    batch = bridge_report(
        json.loads(json.dumps(report)),
        expected_report_sha256=report_digest(report),
        edition_id="test_edition",
    )
    assert len(batch.rows) == 12 and len(batch.attempts) == 3
    assert all(
        row.introduced_prediction is None and row.eligibility_ref is None for row in batch.rows
    )


def test_preflight_tree_drift_starts_no_process(tmp_path, monkeypatch):
    manifest, kwargs, root, _ = binding_fixture(tmp_path)
    runner, _, _, _ = artificial_granted_runner(tmp_path, manifest, kwargs)
    calls, _ = mocked_popen(monkeypatch, kwargs)
    (root / "extra").mkdir()
    report = compare(manifest, runner=runner)
    assert calls == [] and len(report["rows"]) == 12
    assert not list(tmp_path.glob(".scanner-start-*"))
    assert all(
        row["introduced_prediction"] is None and not row["live_eligible"] for row in report["rows"]
    )


@pytest.mark.parametrize(
    "confusion", ["legacy-with-tree", "v2-with-files", "v2-missing-tree", "heldout-v2"]
)
def test_schema_mode_confusion_fails_before_process(tmp_path, monkeypatch, confusion):
    manifest, kwargs, _, _ = binding_fixture(tmp_path)
    calls, _ = mocked_popen(monkeypatch, kwargs)
    if confusion == "legacy-with-tree":
        manifest["schema_version"] = "m4-scanner-run-v1"
    elif confusion == "v2-with-files":
        manifest["arms"]["T"]["bundle_files"] = []
    elif confusion == "v2-missing-tree":
        del manifest["arms"]["T"]["bundle_inventory"]
    else:
        manifest["input_scope"] = "heldout"
    recorder = RecordInvocation()
    try:
        report = compare(manifest, runner=recorder)
    except ValueError:
        pass
    else:
        assert len(report["rows"]) == 12
        assert all(
            row["introduced_prediction"] is None and not row["live_eligible"]
            for row in report["rows"]
        )
    assert calls == [] and recorder.calls == []


def test_old_grant_cannot_authorize_omitted_bundle_identity(tmp_path):
    manifest, kwargs, _, _ = binding_fixture(tmp_path)
    runner, invocation, _, _ = artificial_granted_runner(tmp_path, manifest, kwargs)
    with pytest.raises(PermissionError):
        runner.approval(replace(invocation, bundle_inventory=None))


def test_no_external_grant_pin_is_accepted(tmp_path):
    manifest, kwargs, _, _ = binding_fixture(tmp_path)
    artificial_granted_runner(tmp_path, manifest, kwargs)
    path = tmp_path / "test-only-grant.json"
    with pytest.raises(ValueError):
        load_execution_grant(path, expected_sha256="0" * 64, manifest=manifest)


def test_attempt_deadline_cannot_reset_at_capture_entry(tmp_path, monkeypatch):
    _, kwargs, _, _ = binding_fixture(tmp_path)
    recorder = RecordInvocation()
    calls, _ = mocked_popen(monkeypatch, kwargs)
    try:
        artifact = trivy_adapter.scan(
            **kwargs, runner=recorder, attempt_deadline=time.monotonic() - 1
        )
    except TimeoutError:
        pass
    else:
        assert artifact.status in {"timeout", "error", "invalid", "not_run"}
        assert not artifact.live_eligible
    assert recorder.calls == [] and calls == []


def test_legacy_v1_invocation_digest_exact_independent_golden():
    """what_bug_this_catches: adding serialized null/deadline/caps changes v1 digest."""
    raw = (FIXTURES / "legacy-invocation.json").read_bytes()
    assert (
        len(raw) == 315
        and sha(raw) == "9d7156d69ec15b3f7c2d43542aac6cbb57c0954b3c723cb5c70b1653f290d75c"
    )
    invocation = Invocation(
        ("/m4/scanner.fixture", "config"),
        PurePosixPath("/m4/workspace"),
        (("A", "B"),),
        Limits(),
        ((PurePosixPath("/m4/input.json"), "a" * 64, 123),),
    )
    assert invocation_digest(invocation) == sha(raw)
    assert invocation_digest(replace(invocation, attempt_deadline=1234.5)) == sha(raw)


def test_legacy_v1_closed_grant_golden_roundtrip(tmp_path):
    """what_bug_this_catches: v2 changes old closed grant wire or external fingerprint."""
    raw = (FIXTURES / "legacy-grant.json").read_bytes()
    assert (
        len(raw) == 1169
        and sha(raw) == "c66f94ca83a234cc9ce2c20892a041ed4506d7d0b2494f11d6ac24913544b89d"
    )
    path = tmp_path / "legacy-grant.json"
    path.write_bytes(raw)
    manifest = {
        "input_scope": "development_synthetic",
        "synthetic_input_attested": True,
        "build_sha256": "a" * 64,
        "cases": [],
    }
    parsed = load_execution_grant(path, expected_sha256=sha(raw), manifest=manifest)
    assert parsed.approved_bytes_sha256 == sha(raw)
    assert (
        parsed.invocations[0].invocation_sha256
        == "9d7156d69ec15b3f7c2d43542aac6cbb57c0954b3c723cb5c70b1653f290d75c"
    )
    assert asdict(parsed.invocations[0]) == {
        **json.loads(raw)["invocations"][0],
        "check_ids": ("GOLDEN_TEST",),
    }
