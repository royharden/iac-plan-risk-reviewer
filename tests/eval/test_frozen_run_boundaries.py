"""Frozen-run boundary regression SOURCE (authored under Dirty Mode, NOT run).

Artificial public bytes only; no heldout corpus, oracle, scanner binary or provider.
Covers contract S1 (input exposure intents), the guarded heldout scanner scope and
Amendment A1 (heldout scanner reports need pinned eligibility).
"""
from dataclasses import replace
import json

import pytest

from iac_review.attempts import AttemptJournal
from eval.model.experiment import digest
from eval.model.transport import FakeTransport
from eval.runner.benchmark import load_synthetic_authority
from eval.runner.custody import metadata_digest
from eval.runner.frozen_run import FrozenRunPins, FrozenRuntime, run_frozen
from eval.scanners import driver
from eval.scanners.runner import (BoundedSubprocessRunner, LocalExecutionGrant, guarded_input_path,
                                  remove_guarded_input, stage_guarded_input)
from eval.scanners.scoring_bridge import bridge_report
from test_benchmark_access import committed, metadata_with_exposure
from test_benchmark_coordination import fixture

RAW = b'{"format_version":"1.2","resource_changes":[]}'
PIN = digest(RAW)


def heldout_manifest(access_pin="a" * 64, **case):
    item = {"case_id": "fixture_case", "plan_sha256": PIN, "resources": []}
    item.update(case)
    return {"schema_version": "m4-scanner-run-v1", "input_scope": "heldout", "guarded_input": True,
            "access_authorization_sha256": access_pin, "build_sha256": "a" * 64,
            "cases": [item], "arms": {}}


def guarded(data=RAW):
    return driver.GuardedScannerInput("fixture_case", PIN, lambda: data)


def granted_runner(scope, manifest, access_pin=None):
    from eval.scanners.runner import manifest_digest
    grant = LocalExecutionGrant("fixture_grant", "fixture_operator", "a" * 64, manifest_digest(manifest),
                                (), "b" * 64, scope, access_pin)
    return BoundedSubprocessRunner(activation_authorized=True, execution_grant=grant)


def test_heldout_manifest_without_guarded_input_is_refused(tmp_path):
    """what_bug_this_catches: heldout scope falls back to reading a declared raw path."""
    manifest = heldout_manifest()
    with pytest.raises(ValueError, match="guarded heldout"):
        driver.compare(manifest, runner=granted_runner("heldout", manifest, "a" * 64))


def test_guarded_input_refuses_fake_mode_and_synthetic_scoped_grant(tmp_path):
    """what_bug_this_catches: a fake fixture or development grant is relabelled as a heldout scan."""
    manifest = heldout_manifest()
    with pytest.raises(ValueError, match="heldout-scoped granted runner"):
        driver.compare(manifest, fake_only=True, guarded_input=guarded())
    with pytest.raises(ValueError, match="heldout-scoped granted runner"):
        driver.compare(manifest, runner=granted_runner("development_synthetic", manifest), guarded_input=guarded())


def test_heldout_manifest_declaring_private_plan_path_is_refused(tmp_path):
    """what_bug_this_catches: the private source path leaks into the scanner manifest/argv."""
    manifest = heldout_manifest(plan_path=str(tmp_path / "private.json"))
    with pytest.raises(PermissionError):
        granted_runner("heldout", manifest, "a" * 64).verify_manifest(manifest)
    with pytest.raises(ValueError, match="identity/pin mismatch"):
        driver._load_cases(manifest, driver.Limits(), guarded())


def test_heldout_grant_bound_to_different_access_permission_is_refused():
    """what_bug_this_catches: a scanner grant issued for another access permission scans these inputs."""
    manifest = heldout_manifest(access_pin="a" * 64)
    with pytest.raises(PermissionError):
        granted_runner("heldout", manifest, "c" * 64).verify_manifest(manifest)


def test_synthetic_grant_never_admits_heldout_manifest():
    """what_bug_this_catches: development_synthetic grants cover a heldout manifest by digest alone."""
    manifest = heldout_manifest()
    with pytest.raises(PermissionError):
        granted_runner("development_synthetic", manifest).verify_manifest(manifest)


def test_guarded_snapshot_change_between_arms_aborts(tmp_path):
    """what_bug_this_catches: a changed in-memory snapshot is scanned under the permitted pin."""
    reads = iter((RAW, b"changed"))
    changing = driver.GuardedScannerInput("fixture_case", PIN, lambda: next(reads))
    case = driver._load_cases(heldout_manifest(), driver.Limits(), changing)[0]
    with pytest.raises(ValueError, match="differs from its permitted pin"):
        driver._case_bytes(case, driver.Limits())


def test_staging_is_explicit_exclusive_and_removes_only_its_own_file(tmp_path):
    """what_bug_this_catches: staging overwrites/reuses a file or cleanup deletes a foreign file."""
    with pytest.raises(ValueError, match="pre-existing"):
        stage_guarded_input(tmp_path, RAW, PIN, 1024)
    (tmp_path / "guarded-input").mkdir()
    with pytest.raises(ValueError, match="differ from the permitted pin"):
        stage_guarded_input(tmp_path, b"other", PIN, 1024)
    staged = stage_guarded_input(tmp_path, RAW, PIN, 1024)
    assert staged == guarded_input_path(tmp_path, PIN) and staged.read_bytes() == RAW
    with pytest.raises(FileExistsError):
        stage_guarded_input(tmp_path, RAW, PIN, 1024)
    foreign = tmp_path / "guarded-input" / ("0" * 64 + ".json")
    foreign.write_bytes(b"foreign")
    assert remove_guarded_input(foreign, PIN, 1024) is False and foreign.exists()
    assert remove_guarded_input(staged, PIN, 1024) is True and not staged.exists()


def test_frozen_authority_schema_cannot_claim_synthetic_scope():
    """what_bug_this_catches: a heldout run is approved through the synthetic-only authority."""
    keys = ("run_id", "edition_id")
    value = {key: "fixture" for key in keys}
    value.update({key: "a" * 64 for key in ("build_sha256", "config_file_sha256", "corpus_sha256",
        "arm_inventory_sha256", "provider_sha256", "price_sha256", "budget_sha256", "model_limits_sha256",
        "configuration_sha256", "data_transfer_sha256", "access_authorization_sha256")})
    value.update(schema_version="m4-approved-frozen-heldout-benchmark-v1", scanner_grants={"fixture": "a" * 64},
                 dirty_mode_closed=True, execution_explicitly_approved=True, synthetic_only=True)
    raw = json.dumps(value).encode()
    with pytest.raises(ValueError, match="closed_explicit"):
        load_synthetic_authority(raw, expected_sha256=digest(raw))


def test_heldout_scanner_report_without_pinned_eligibility_is_refused():
    """what_bug_this_catches: Amendment A1 - heldout scanner rows are bridged without execution eligibility."""
    report = {"schema_version": "m4-scanner-comparison-v1", "input_scope": "heldout", "source_enrichment": False,
              "fake_only": False, "product_acceptance": False, "build_sha256": "a" * 64, "rows": [],
              "capture_receipts": []}
    from eval.scanners.scoring_bridge import _canonical
    import hashlib
    pin = hashlib.sha256(_canonical(report)).hexdigest()
    with pytest.raises(ValueError, match="pinned execution eligibility"):
        bridge_report(report, expected_report_sha256=pin, edition_id="fixture_edition")


def sealed_gate_inputs(tmp_path, monkeypatch, committed_flag):
    from eval.runner.custody import metadata_digest as pin_of
    manifest, pins, permission, exposure = metadata_with_exposure(tmp_path)
    manifest = manifest.model_copy(update={"edition_state": "sealed"})
    status = {"edition_state": "sealed", "payloads_opened": 0}
    if committed_flag is not None:
        status["input_exposure_committed"] = committed_flag
    monkeypatch.setattr("eval.runner.benchmark_access.preflight", lambda *a: status)
    return manifest, pins, permission, exposure, pin_of(permission)


def test_sealed_edition_without_committed_input_exposure_is_refused(tmp_path, monkeypatch):
    """what_bug_this_catches: S1.6 path (b) admits a sealed edition with no committed input-exposure journal."""
    from eval.runner.benchmark_access import _gate
    for flag in (None, False):
        manifest, pins, permission, exposure, pin = sealed_gate_inputs(tmp_path, monkeypatch, flag)
        monkeypatch.setattr("eval.runner.exposure_journal.verify_committed_exposure",
                            lambda *a, **k: pytest.fail("journal verify reached"))
        with pytest.raises(ValueError, match="durable_consumption"):
            _gate(tmp_path, manifest, pins, permission, pin, exposure)


def test_sealed_edition_with_committed_flag_still_requires_pinned_commit(tmp_path, monkeypatch):
    """what_bug_this_catches: preflight's read-only committed flag alone substitutes for the pinned commit check."""
    from eval.runner.benchmark_access import _gate
    manifest, pins, permission, exposure, pin = sealed_gate_inputs(tmp_path, monkeypatch, True)
    monkeypatch.setattr("eval.runner.exposure_journal.verify_committed_exposure", lambda *a, **k: committed("b" * 64))
    monkeypatch.setattr("eval.runner.benchmark_access.read_metadata", lambda *a: pytest.fail("custody read"))
    with pytest.raises(ValueError, match="committed_input_exposure_permission_mismatch"):
        _gate(tmp_path, manifest, pins, permission, pin, exposure)


def test_committed_intent_mismatch_never_activates_accessor(tmp_path, monkeypatch):
    """what_bug_this_catches: frozen run opens inputs although committed intents differ from the permission."""
    config, path, price = fixture(tmp_path)
    config = replace(config, input_scope="heldout", fake_only=False, synthetic_input_attested=False)
    manifest, pins_, permission, exposure = metadata_with_exposure(tmp_path)
    values = {name: "a" * 64 for name in FrozenRunPins.model_fields}
    # Match the exposure-authorization pin so the INTENT comparison is what refuses.
    values["exposure_authorization_sha256"] = metadata_digest(exposure)
    pins = FrozenRunPins(**values)
    monkeypatch.setattr("eval.runner.frozen_run._selection", lambda *a: None)
    monkeypatch.setattr("eval.runner.frozen_run.verify_committed_exposure", lambda *a, **k: committed("b" * 64))
    monkeypatch.setattr("eval.runner.frozen_run.authorize_heldout_access", lambda *a, **k: pytest.fail("accessor"))
    with AttemptJournal(path, config.budget, price) as journal:
        runtime = FrozenRuntime(tmp_path, config, manifest, pins_, permission, exposure, None,
                                journal, FakeTransport(), {}, tmp_path / "events.jsonl")
        result = run_frozen(runtime, pins, expected_pins_sha256="a" * 64)
    outcome = json.loads(result.private_outcome_json)
    assert all(row["status"] == "not_run" for row in outcome["statuses"])
    assert outcome["oracle_opened"] is False and result.status == "INCOMPLETE"
