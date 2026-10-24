"""Access-controller regression SOURCE. No hidden payload/corpus is present here."""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from iac_review.contracts.manifest import ArtifactRef, ComponentVersion, RunManifest
from eval.model.experiment import digest
from eval.runner.benchmark_access import (HeldoutAccess, HeldoutAuthorization, PayloadPermission,
    _gate, arm_inventory_digest, authorize_heldout_access)
from eval.runner.bundle import root_digest
from eval.runner.custody import metadata_digest
from eval.runner.exposure_journal import (ExposureCommitAuthorization, InputExposureCommit,
                                          InputExposureReceipt)
from eval.runner.preflight import PreflightPins

ARMS = ("D", "L", "P", "M", "C", "C-custom", "T")


def metadata_with_exposure(tmp_path):
    """Artificial incomplete metadata plus an S1 exposure authorization: refusal-order only."""
    pin = "a" * 64
    manifest = RunManifest(run_id="fixture_run", edition_id="fixture_edition", split="heldout",
        edition_state="consumed_holdout", build_sha256=pin, policy_sha256=pin,
        authority_sha256=pin, semantic_suite_sha256=pin, eligibility_sha256=pin,
        components=(ComponentVersion(component_id="fixture_source", kind="source", name="fixture", version="not_executed", sha256=pin),),
        cases=(), invocations=(), attempts=(), artifacts=(), eligibility=())
    pins = PreflightPins(run_manifest_sha256=metadata_digest(manifest), authority_sha256=pin,
                          semantic_suite_sha256=pin, eligibility_sha256=pin)
    exposure = ExposureCommitAuthorization(run_id=manifest.run_id, edition_id=manifest.edition_id,
        run_manifest_sha256=pin, source_root_sha256=root_digest(tmp_path), authority_sha256=pin,
        seal_sha256=pin, policy_sha256=pin, semantic_suite_sha256=pin, eligibility_sha256=pin,
        build_sha256=pin, oracle_sha256=pin, inventory_sha256=pin, prompt_sha256=pin, rubric_sha256=pin,
        arm_inventory_sha256=pin, custodian="fixture_custodian",
        measurement_intents_sha256={arm: pin for arm in ARMS}, approved_before_access=True)
    now = datetime.now(timezone.utc)
    permission = HeldoutAuthorization(schema_version="m4-heldout-input-access-v2",
        purpose="consumed_heldout_evaluation", run_id=manifest.run_id,
        edition_id=manifest.edition_id, run_manifest_sha256=pins.run_manifest_sha256,
        source_root_sha256=root_digest(tmp_path), authority_sha256=pin, seal_sha256=pin,
        semantic_suite_sha256=pin, build_sha256=pin, inventory_sha256=pin, prompt_sha256=pin,
        rubric_sha256=pin, arm_inventory_sha256=pin,
        input_exposure_authorization_sha256=metadata_digest(exposure),
        input_exposure_commit_sha256=pin, input_exposure_receipt_file_sha256=pin,
        measurement_intents_sha256={arm: pin for arm in ARMS},
        custodian="fixture_custodian", authorized_by="fixture_custodian",
        consumption_committed_before_access=True, tuning_forbidden=True,
        valid_from=now-timedelta(minutes=1), valid_until=now+timedelta(minutes=1),
        payloads=(PayloadPermission(artifact_id="fixture_input", role="case_input", sha256=pin, case_id="fixture_case"),))
    return manifest, pins, permission, exposure


def metadata(tmp_path):
    manifest, pins, permission, _ = metadata_with_exposure(tmp_path)
    return manifest, pins, permission


def committed(intent: str, *, file_pin="a" * 64, commit_pin="a" * 64):
    """Unvalidated stand-in for D6's as-built InputExposureCommit (type identity preserved)."""
    rows = tuple(InputExposureReceipt.model_construct(run_id="fixture_run", edition_id="fixture_edition",
        arm=arm, measurement_intents_sha256=intent, seal_sha256="a" * 64, custodian="fixture_custodian")
        for arm in ARMS)
    authorization = SimpleNamespace(measurement_intents_sha256={arm: intent for arm in ARMS})
    return InputExposureCommit.model_construct(state="CONSUMED_HOLDOUT_INPUT", commit_sha256=commit_pin,
        receipt_file_sha256=file_pin, authorization=authorization, receipts=rows)


def test_wrong_external_permission_pin_precedes_even_preflight(tmp_path, monkeypatch):
    """what_bug_this_catches: metadata consistency silently substitutes for explicit access permission."""
    manifest, pins, permission, exposure = metadata_with_exposure(tmp_path)
    monkeypatch.setattr("eval.runner.benchmark_access.preflight", lambda *a: pytest.fail("metadata accessed"))
    with pytest.raises(ValueError, match="externally_pinned"):
        _gate(tmp_path, manifest, pins, permission, "b" * 64, exposure)


def test_missing_or_substituted_exposure_authorization_precedes_preflight(tmp_path, monkeypatch):
    """what_bug_this_catches: input access proceeds without the exact D6 pre-access exposure authorization."""
    manifest, pins, permission, exposure = metadata_with_exposure(tmp_path)
    monkeypatch.setattr("eval.runner.benchmark_access.preflight", lambda *a: pytest.fail("metadata accessed"))
    for substitute in (None, exposure.model_copy(update={"custodian": "other_custodian"})):
        with pytest.raises(ValueError, match="externally_pinned"):
            _gate(tmp_path, manifest, pins, permission, metadata_digest(permission), substitute)


def test_consistent_preflight_without_consumption_never_opens_payload(tmp_path, monkeypatch):
    """what_bug_this_catches: a successful sealed metadata preflight is mistaken for unblinding permission."""
    manifest, pins, permission, exposure = metadata_with_exposure(tmp_path)
    monkeypatch.setattr("eval.runner.benchmark_access.preflight", lambda *a: {"edition_state": "sealed", "payloads_opened": 0})
    monkeypatch.setattr("eval.runner.benchmark_access.read_metadata", lambda *a: pytest.fail("later access"))
    with pytest.raises(ValueError, match="durable_consumption"):
        _gate(tmp_path, manifest, pins, permission, metadata_digest(permission), exposure)


def test_committed_intents_differing_from_permission_refuse_before_custody_reads(tmp_path, monkeypatch):
    """what_bug_this_catches: permission bound to one intent set opens inputs under a different committed intent (S1)."""
    manifest, pins, permission, exposure = metadata_with_exposure(tmp_path)
    monkeypatch.setattr("eval.runner.benchmark_access.preflight",
                        lambda *a: {"edition_state": "consumed_holdout", "payloads_opened": 0})
    monkeypatch.setattr("eval.runner.exposure_journal.verify_committed_exposure", lambda *a, **k: committed("b" * 64))
    monkeypatch.setattr("eval.runner.benchmark_access.read_metadata", lambda *a: pytest.fail("custody read"))
    with pytest.raises(ValueError, match="committed_input_exposure_permission_mismatch"):
        _gate(tmp_path, manifest, pins, permission, metadata_digest(permission), exposure)


def test_committed_receipt_file_pin_must_match_permission(tmp_path, monkeypatch):
    """what_bug_this_catches: a different (e.g. replaced) input-exposure receipt file still unlocks inputs."""
    manifest, pins, permission, exposure = metadata_with_exposure(tmp_path)
    monkeypatch.setattr("eval.runner.benchmark_access.preflight",
                        lambda *a: {"edition_state": "consumed_holdout", "payloads_opened": 0})
    monkeypatch.setattr("eval.runner.exposure_journal.verify_committed_exposure",
                        lambda *a, **k: committed("a" * 64, file_pin="c" * 64))
    monkeypatch.setattr("eval.runner.benchmark_access.read_metadata", lambda *a: pytest.fail("custody read"))
    with pytest.raises(ValueError, match="committed_input_exposure_permission_mismatch"):
        _gate(tmp_path, manifest, pins, permission, metadata_digest(permission), exposure)


def test_no_fresh_access_log_cannot_overwrite_existing_evidence(tmp_path):
    """what_bug_this_catches: failure reporting replaces an existing journal or approval artifact."""
    manifest, pins, permission, exposure = metadata_with_exposure(tmp_path)
    log = tmp_path / "existing.jsonl"
    log.write_bytes(b"preserve")
    with pytest.raises(ValueError, match="fresh_separate"):
        authorize_heldout_access(tmp_path, manifest, pins, permission,
                                 expected_permission_sha256=metadata_digest(permission), event_path=log,
                                 exposure_authorization=exposure)
    assert log.read_bytes() == b"preserve"


def lease(tmp_path, monkeypatch, *, expected=b"public synthetic plumbing", actual=None):
    manifest, pins, permission = metadata(tmp_path)
    path = tmp_path / "private" / "synthetic" / "inputs" / "fixture.json"
    path.parent.mkdir(parents=True)
    path.write_bytes(expected if actual is None else actual)
    ref = ArtifactRef(artifact_id="fixture_input", role="case_input", path="private/synthetic/inputs/fixture.json",
                      sha256=digest(expected), bytes_upper=1024)
    monkeypatch.setattr("eval.runner.benchmark_access._gate", lambda *a: {ref.artifact_id: ref})
    events = []
    monkeypatch.setattr("eval.runner.benchmark_access._event", lambda *a, **k: events.append(a[2:]))
    return HeldoutAccess(tmp_path, manifest, pins, permission, metadata_digest(permission), tmp_path / "own.jsonl",
                         None), events


def test_payload_hash_failure_returns_no_bytes_and_halts_retry(tmp_path, monkeypatch):
    """what_bug_this_catches: changed input is returned or retried under a consumed capability."""
    access, events = lease(tmp_path, monkeypatch, actual=b"changed")
    with pytest.raises(ValueError, match="incomplete"):
        access.read_case_input("fixture_case")
    with pytest.raises(ValueError, match="halted_no_retry"):
        access.read_case_input("fixture_case")
    assert any(event[0] == "not_run" for event in events)


def test_access_log_failure_stops_before_payload_open(tmp_path, monkeypatch):
    """what_bug_this_catches: logging failure leaves unrecorded hidden access enabled."""
    access, _ = lease(tmp_path, monkeypatch)
    def broken(*a, **k):
        raise OSError("fixture durable log failure")
    monkeypatch.setattr("eval.runner.benchmark_access._event", broken)
    monkeypatch.setattr("eval.runner.benchmark_access.checked_path", lambda *a: pytest.fail("payload open"))
    with pytest.raises(OSError):
        access.read_case_input("fixture_case")


def test_successful_capability_is_single_use(tmp_path, monkeypatch):
    """what_bug_this_catches: a consumed permission becomes an unrestricted repeated hidden-data accessor."""
    access, events = lease(tmp_path, monkeypatch)
    assert access.read_case_input("fixture_case") == b"public synthetic plumbing"
    with pytest.raises(ValueError, match="incomplete"):
        access.read_case_input("fixture_case")
    assert sum(event[0] == "read" for event in events) == 1


def test_missing_arm_inventory_never_becomes_frozen_all_arm_proof(tmp_path):
    """what_bug_this_catches: pinned build alone replaces seven frozen version/config/case bindings."""
    manifest, _, _ = metadata(tmp_path)
    with pytest.raises(ValueError, match="all_arm_case_inventory_missing"):
        arm_inventory_digest(manifest)


def test_input_permission_never_delivers_oracle(tmp_path, monkeypatch):
    """what_bug_this_catches: an input-access permission doubles as oracle/scoring permission (S1 item 4)."""
    manifest, pins, permission = metadata(tmp_path)
    access = HeldoutAccess(tmp_path, manifest, pins, permission, metadata_digest(permission), tmp_path / "own.jsonl", None)
    monkeypatch.setattr(access, "_read", lambda *a: pytest.fail("oracle read"))
    scored = []
    with pytest.raises(ValueError, match="input_access_is_not_oracle_permission"):
        access.deliver_oracle_to_scoring(scored.append)
    assert scored == []


def test_oracle_payload_rows_are_refused_by_closed_wire(tmp_path):
    """what_bug_this_catches: an oracle allowlist row slips into the input-only permission."""
    _, _, permission = metadata(tmp_path)
    value = permission.model_dump(mode="json")
    value["payloads"].append({"artifact_id": "fixture_oracle", "role": "oracle", "sha256": "a" * 64,
                              "case_id": "fixture_oracle_case"})
    with pytest.raises(ValidationError):
        HeldoutAuthorization.model_validate(value)


def test_legacy_v1_permission_document_is_refused_not_reinterpreted(tmp_path):
    """what_bug_this_catches: a v1 document's results-hash field is silently read as pre-access intents."""
    _, _, permission = metadata(tmp_path)
    value = permission.model_dump(mode="json")
    legacy = dict(value, schema_version=1, measurements_sha256=value.pop("measurement_intents_sha256"),
                  exposure_artifact_sha256="a" * 64)
    for key in ("input_exposure_authorization_sha256", "input_exposure_commit_sha256",
                "input_exposure_receipt_file_sha256"):
        legacy.pop(key)
    with pytest.raises(ValidationError):
        HeldoutAuthorization.model_validate(legacy)
    missing = permission.model_dump(mode="json")
    missing.pop("schema_version")
    with pytest.raises(ValidationError):
        HeldoutAuthorization.model_validate(missing)


def test_consumption_attestation_is_required_closed_wire(tmp_path):
    """what_bug_this_catches: false consumption or missing arm becomes optional metadata."""
    _, _, permission = metadata(tmp_path)
    value = permission.model_dump(mode="json")
    value["consumption_committed_before_access"] = False
    with pytest.raises(ValidationError):
        HeldoutAuthorization.model_validate(value)
    value = permission.model_dump(mode="json")
    value["measurement_intents_sha256"].pop("T")
    with pytest.raises(ValidationError):
        HeldoutAuthorization.model_validate(value)
