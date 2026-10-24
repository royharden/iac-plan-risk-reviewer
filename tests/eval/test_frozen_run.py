"""Frozen journey regression SOURCE; artificial public bytes, no heldout corpus."""
from dataclasses import replace
import json

import pytest

from iac_review.attempts import AttemptJournal
from iac_review.contracts.manifest import ArtifactRef, CaseBinding
from iac_review.ingest import InputError, SourceChangedError, load_plan_bytes
from eval.model.experiment import digest
from eval.model.transport import FakeTransport
from eval.runner.benchmark import coordinate
from eval.runner.benchmark_access import GuardedCaseReader, HeldoutAccess
from eval.runner.frozen_run import FrozenRunPins, FrozenRuntime, run_frozen
from test_benchmark_access import metadata
from test_benchmark_coordination import fixture


def test_guarded_byte_ingestion_never_reopens_private_source_path(tmp_path, monkeypatch):
    """what_bug_this_catches: already authorized bytes trigger a second uncontrolled loader read."""
    raw = b'{"format_version":"1.2","complete":true,"errored":false,"resource_changes":[]}'
    path = tmp_path / "metadata-only-does-not-exist.json"
    monkeypatch.setattr("iac_review.ingest.read_source_bytes", lambda *a: pytest.fail("private path reopened"))
    plan = load_plan_bytes(raw, source_path=path, expected_sha256=digest(raw))
    assert plan.identity.sha256 == digest(raw) and plan.source_path == str(path.absolute())
    assert not path.exists()


def test_guarded_byte_pin_and_existing_decoder_limits_are_not_relaxed(tmp_path):
    """what_bug_this_catches: byte entrypoint bypasses identity or duplicate-key admission."""
    raw = b'{"format_version":"1.2","format_version":"1.2"}'
    with pytest.raises(SourceChangedError, match="identity_mismatch"):
        load_plan_bytes(raw, source_path=tmp_path / "private.json", expected_sha256="0" * 64)
    with pytest.raises(InputError, match="duplicate_json_key"):
        load_plan_bytes(raw, source_path=tmp_path / "private.json", expected_sha256=digest(raw))


def test_reader_checks_permission_repeatedly_but_opens_snapshot_once(tmp_path, monkeypatch):
    """what_bug_this_catches: each arm silently rereads/stages private raw input outside the capability."""
    manifest, pins, permission = metadata(tmp_path)
    access = HeldoutAccess(tmp_path, manifest, pins, permission, "a" * 64, tmp_path / "events.jsonl", None)
    checks, reads = [], []
    monkeypatch.setattr(access, "check_authorized", lambda: checks.append(1) or {})
    monkeypatch.setattr(access, "read_case_input", lambda cid: reads.append(cid) or b"public fixture bytes")
    reader = GuardedCaseReader(access)
    config, _, _ = fixture(tmp_path)
    case = replace(config.cases[0], case_id="fixture_case", plan_sha256=digest(b"public fixture bytes"))
    reader.verify(case)
    assert reader.read(case) == b"public fixture bytes"
    reader.verify(case)
    assert reads == ["fixture_case"] and len(checks) == 3


def test_frozen_mode_without_typed_reader_refuses_before_payload(tmp_path, monkeypatch):
    """what_bug_this_catches: an execution mode string or split flag replaces actual access authority."""
    config, path, price = fixture(tmp_path)
    monkeypatch.setattr("eval.runner.benchmark.verify_case", lambda *a: pytest.fail("payload access"))
    with AttemptJournal(path, config.budget, price) as journal:
        with pytest.raises(ValueError, match="required_together"):
            coordinate(replace(config, input_scope="heldout", fake_only=False), journal=journal,
                       transport=FakeTransport(), execution_mode="frozen_heldout")


def test_commit_failure_precedes_accessor_and_preserves_seven_arm_statuses(tmp_path, monkeypatch):
    """what_bug_this_catches: preflight/permission reads occur after an incomplete durable consumption commit."""
    config, path, price = fixture(tmp_path)
    config = replace(config, input_scope="heldout", fake_only=False)
    pin = "a" * 64
    pins = FrozenRunPins(**{name: pin for name in FrozenRunPins.model_fields})
    monkeypatch.setattr("eval.runner.frozen_run._selection", lambda *a: None)
    def denied(*a, **k):
        raise ValueError("fixture incomplete commit")
    monkeypatch.setattr("eval.runner.frozen_run.verify_committed_exposure", denied)
    monkeypatch.setattr("eval.runner.frozen_run.authorize_heldout_access", lambda *a, **k: pytest.fail("accessor activated"))
    with AttemptJournal(path, config.budget, price) as journal:
        runtime = FrozenRuntime(tmp_path, config, None, None, None, None, None,
                                journal, FakeTransport(), {}, tmp_path / "events.jsonl")
        result = run_frozen(runtime, pins, expected_pins_sha256=pin)
        assert journal.summary()["requests"] == 0
    outcome = json.loads(result.private_outcome_json)
    assert len(outcome["statuses"]) == 14 and all(row["status"] == "not_run" for row in outcome["statuses"])
    assert outcome["split"] == "heldout" and outcome["oracle_opened"] is False
    assert outcome["journal_snapshot"]["summary"]["requests"] == 0
    assert result.outcome_sha256 == digest(result.private_outcome_json)


def test_guarded_inventory_checks_raw_lineage_without_opening_payload(tmp_path, monkeypatch):
    """what_bug_this_catches: caller substitutes a different raw input under an authorized case ID."""
    manifest, pins, permission = metadata(tmp_path)
    binding = CaseBinding(case_id="fixture_case", split="heldout", configuration_id="config",
                          family_id="family", mutation_lineage="mutation", raw_source_sha256="a" * 64)
    manifest = manifest.model_copy(update={"cases": (binding,)})
    ref = ArtifactRef(artifact_id="fixture_input", role="case_input", path="private/synthetic/inputs/fixture.json",
                      sha256="a" * 64, bytes_upper=1024)
    access = HeldoutAccess(tmp_path, manifest, pins, permission, "a" * 64, tmp_path / "events.jsonl", None)
    monkeypatch.setattr(access, "check_authorized", lambda: {ref.artifact_id: ref})
    monkeypatch.setattr(access, "read_case_input", lambda *a: pytest.fail("payload opened"))
    config, _, _ = fixture(tmp_path)
    case = replace(config.cases[0], case_id="fixture_case", plan_path=tmp_path/ref.path,
                   configuration_id="config", family_id="family", mutation_lineage="mutation")
    with pytest.raises(ValueError, match="raw_lineage_path_mismatch"):
        GuardedCaseReader(access).check_inventory((case,), manifest.build_sha256)
