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
from eval.runner.preflight import PreflightPins


def metadata(tmp_path):
    """Artificial incomplete metadata: useful only for refusal-order assertions."""
    pin = "a" * 64
    manifest = RunManifest(run_id="fixture_run", edition_id="fixture_edition", split="heldout",
        edition_state="consumed_holdout", build_sha256=pin, policy_sha256=pin,
        authority_sha256=pin, semantic_suite_sha256=pin, eligibility_sha256=pin,
        components=(ComponentVersion(component_id="fixture_source", kind="source", name="fixture", version="not_executed", sha256=pin),),
        cases=(), invocations=(), attempts=(), artifacts=(), eligibility=())
    pins = PreflightPins(run_manifest_sha256=metadata_digest(manifest), authority_sha256=pin,
                          semantic_suite_sha256=pin, eligibility_sha256=pin)
    now = datetime.now(timezone.utc)
    permission = HeldoutAuthorization(purpose="consumed_heldout_evaluation", run_id=manifest.run_id,
        edition_id=manifest.edition_id, run_manifest_sha256=pins.run_manifest_sha256,
        source_root_sha256=root_digest(tmp_path), authority_sha256=pin, seal_sha256=pin,
        semantic_suite_sha256=pin, build_sha256=pin, inventory_sha256=pin, prompt_sha256=pin,
        rubric_sha256=pin, arm_inventory_sha256=pin, exposure_artifact_sha256=pin,
        measurements_sha256={arm: pin for arm in ("D", "L", "P", "M", "C", "C-custom", "T")},
        custodian="fixture_custodian", authorized_by="fixture_custodian",
        consumption_committed_before_access=True, tuning_forbidden=True,
        valid_from=now-timedelta(minutes=1), valid_until=now+timedelta(minutes=1),
        payloads=(PayloadPermission(artifact_id="fixture_input", role="case_input", sha256=pin, case_id="fixture_case"),
                  PayloadPermission(artifact_id="fixture_oracle", role="oracle", sha256=pin)))
    return manifest, pins, permission


def test_wrong_external_permission_pin_precedes_even_preflight(tmp_path, monkeypatch):
    """what_bug_this_catches: metadata consistency silently substitutes for explicit access permission."""
    manifest, pins, permission = metadata(tmp_path)
    monkeypatch.setattr("eval.runner.benchmark_access.preflight", lambda *a: pytest.fail("metadata accessed"))
    with pytest.raises(ValueError, match="externally_pinned"):
        _gate(tmp_path, manifest, pins, permission, "b" * 64)


def test_consistent_preflight_without_consumption_never_opens_payload(tmp_path, monkeypatch):
    """what_bug_this_catches: a successful sealed metadata preflight is mistaken for unblinding permission."""
    manifest, pins, permission = metadata(tmp_path)
    monkeypatch.setattr("eval.runner.benchmark_access.preflight", lambda *a: {"edition_state": "sealed", "payloads_opened": 0})
    monkeypatch.setattr("eval.runner.benchmark_access.read_metadata", lambda *a: pytest.fail("later access"))
    with pytest.raises(ValueError, match="durable_consumption"):
        _gate(tmp_path, manifest, pins, permission, metadata_digest(permission))


def test_no_fresh_access_log_cannot_overwrite_existing_evidence(tmp_path):
    """what_bug_this_catches: failure reporting replaces an existing journal or approval artifact."""
    manifest, pins, permission = metadata(tmp_path)
    log = tmp_path / "existing.jsonl"
    log.write_bytes(b"preserve")
    with pytest.raises(ValueError, match="fresh_separate"):
        authorize_heldout_access(tmp_path, manifest, pins, permission,
                                 expected_permission_sha256=metadata_digest(permission), event_path=log)
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
    return HeldoutAccess(tmp_path, manifest, pins, permission, metadata_digest(permission), tmp_path / "own.jsonl"), events


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


def test_oracle_delivery_is_explicit_scoring_sink_and_withholds_return(tmp_path, monkeypatch):
    """what_bug_this_catches: accessor returns hidden oracle bytes as an inference-friendly result."""
    manifest, pins, permission = metadata(tmp_path)
    access = HeldoutAccess(tmp_path, manifest, pins, permission, metadata_digest(permission), tmp_path / "own.jsonl")
    roles, scored = [], []
    monkeypatch.setattr(access, "_read", lambda identity, role: roles.append(role) or b"public fixture oracle envelope")
    assert access.deliver_oracle_to_scoring(lambda raw: scored.append(raw) or "discard this return") is None
    assert roles == ["oracle"] and len(scored) == 1


def test_consumption_attestation_is_required_closed_wire(tmp_path):
    """what_bug_this_catches: false consumption or missing arm becomes optional metadata."""
    _, _, permission = metadata(tmp_path)
    value = permission.model_dump(mode="json")
    value["consumption_committed_before_access"] = False
    with pytest.raises(ValidationError):
        HeldoutAuthorization.model_validate(value)
    value = permission.model_dump(mode="json")
    value["measurements_sha256"].pop("T")
    with pytest.raises(ValidationError):
        HeldoutAuthorization.model_validate(value)
