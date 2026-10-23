"""Unexecuted public empty-plan regression SOURCE, never hidden oracle data."""
from hashlib import sha256
import json
from pathlib import Path
from time import monotonic

import pytest

from iac_review.contracts.manifest import RunManifest
from iac_review.ingest import InputError, load_plan
from iac_review.provenance import ReportProvenance, descriptor_bytes, verify_descriptor
from iac_review.report import build_report, write_report
from iac_review.rules import evaluate


def empty_review(tmp_path):
    source = tmp_path / "public-empty-plan.json"
    source.write_text(json.dumps({"format_version": "1.2", "complete": True,
                                  "errored": False, "resource_changes": []}), encoding="utf-8")
    plan = load_plan(source)
    return source, build_report(plan, evaluate(plan))


def test_local_manifest_is_real_d_only_without_fabricated_benchmark_pins(tmp_path):
    source, report = empty_review(tmp_path)
    descriptor = ReportProvenance.model_validate_json(json.dumps(report.private["provenance"]["descriptor"]))
    run = descriptor.run_manifest
    assert run.stage == "deterministic"
    assert run.authority_sha256 is run.semantic_suite_sha256 is run.eligibility_sha256 is None
    assert {row.kind for row in run.components} == {"source", "parser", "rules", "config"}
    assert len(run.invocations) == 1 and run.invocations[0].arm == "D"
    assert not run.attempts and not run.eligibility and not run.artifacts
    assert run.cases[0].raw_source_sha256 == sha256(source.read_bytes()).hexdigest()
    assert report.shareable["measurements"]["D"] == "NOT MEASURED"
    shared = json.dumps(report.shareable)
    assert run.cases[0].raw_source_sha256 not in shared
    assert "provenance" not in report.shareable and "source_files" not in report.shareable


def test_outer_receipt_is_acyclic_and_binds_exact_private_artifacts(tmp_path):
    _, report = empty_review(tmp_path)
    out = tmp_path / "bound-report"
    write_report(report, out)
    manifest_raw = (out / "manifest.json").read_bytes()
    manifest = json.loads(manifest_raw)
    assert manifest["schema_version"] == "1.1.0"
    assert "manifest.json" not in manifest["artifacts"] and "manifest.sha256" not in manifest["artifacts"]
    assert set(manifest["artifacts"]) == {"private.json", "private.html", "shareable.json", "shareable.html", "run-manifest.json"}
    for name, expected in manifest["artifacts"].items():
        assert sha256((out / name).read_bytes()).hexdigest() == expected
    assert (out / "manifest.sha256").read_text().strip() == sha256(manifest_raw).hexdigest()
    assert len(list(out.iterdir())) == 8
    private = json.loads((out / "private.json").read_bytes())
    assert private["provenance"]["descriptor_sha256"] == manifest["artifacts"]["run-manifest.json"]
    assert json.loads((out / "export-state.json").read_bytes())["state"] == "COMPLETE"


def test_cross_stage_fields_and_missing_evaluation_pins_reject(tmp_path):
    _, report = empty_review(tmp_path)
    run = report.private["provenance"]["descriptor"]["run_manifest"]
    for change in ({"authority_sha256": "a" * 64}, {"stage": "evaluation"},
                   {"stage": "evaluation", "authority_sha256": "a" * 64},
                   {"attempts": [{"invented": "usage"}]}):
        with pytest.raises(ValueError):
            RunManifest.model_validate_json(json.dumps(run | change))


def test_private_config_or_raw_pin_mismatch_refuses_export_and_stays_aborted(tmp_path):
    _, report = empty_review(tmp_path)
    report.private["summary"]["fail_on"] = 1
    out = tmp_path / "refused-report"
    with pytest.raises(ValueError):
        write_report(report, out)
    assert json.loads((out / "export-state.json").read_bytes())["state"] == "ABORTED"
    assert not (out / "manifest.json").exists()


def test_expired_export_keeps_aborted_marker_and_no_complete_bundle(tmp_path):
    _, report = empty_review(tmp_path)
    out = tmp_path / "expired-report"
    with pytest.raises(InputError, match="time_limit"):
        write_report(report, out, deadline=monotonic() - 1)
    assert json.loads((out / "export-state.json").read_bytes())["state"] == "ABORTED"
    assert not (out / "private.json").exists()


def test_deterministic_stage_is_rejected_before_benchmark_file_access(tmp_path, monkeypatch):
    from eval.runner.custody import metadata_digest
    from eval.runner.preflight import PreflightPins, preflight
    _, report = empty_review(tmp_path)
    descriptor = ReportProvenance.model_validate_json(json.dumps(report.private["provenance"]["descriptor"]))
    pins = PreflightPins(run_manifest_sha256=metadata_digest(descriptor.run_manifest),
                         authority_sha256="a" * 64, semantic_suite_sha256="a" * 64,
                         eligibility_sha256="a" * 64)
    def refuse(*args, **kwargs):
        raise AssertionError("benchmark preflight opened a file for local deterministic stage")
    monkeypatch.setattr(Path, "open", refuse)
    with pytest.raises(ValueError, match="not benchmark"):
        preflight(tmp_path, descriptor.run_manifest, pins)


def test_descriptor_does_not_depend_on_its_artifact_receipts(tmp_path):
    _, report = empty_review(tmp_path)
    descriptor = ReportProvenance.model_validate_json(json.dumps(report.private["provenance"]["descriptor"]))
    raw = descriptor_bytes(descriptor)
    assert verify_descriptor(report.private, report.shareable, raw,
                             report.private["plan"]["sha256"], report.private["run_id"]) == descriptor
    assert not descriptor.run_manifest.artifacts
