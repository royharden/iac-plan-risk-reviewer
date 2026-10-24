"""Writer/viewer consumers of the canonical report bundle inventory.

Regression SOURCE only; not imported or executed during Dirty Mode. Public
synthetic plans only, never hidden oracle data.
"""
from hashlib import sha256
import json
from pathlib import Path

import pytest

from iac_review import report as reporting
from iac_review import source_view
from iac_review.contracts.report_inventory import (
    BOUND_FILES, LEGACY_FILES, AbortedMarker, BoundManifest, CompleteMarker, classify_bundle,
    validate_export_state, validate_manifest,
)
from iac_review.ingest import InputError, load_plan
from iac_review.rules import evaluate


def _bundle(tmp_path: Path) -> Path:
    source = tmp_path / "public-empty-plan.json"
    source.write_text(json.dumps({"format_version": "1.2", "complete": True,
                                  "errored": False, "resource_changes": []}), encoding="utf-8")
    plan = load_plan(source)
    out = tmp_path / "bundle"
    reporting.write_report(reporting.build_report(plan, evaluate(plan)), out)
    return out


def _reseal(out: Path, manifest: dict) -> None:
    payload = json.dumps(manifest).encode("utf-8")
    (out / "manifest.json").write_bytes(payload)
    # Binary write: the canonical receipt is exactly LF-terminated on every platform.
    (out / "manifest.sha256").write_bytes((sha256(payload).hexdigest() + "\n").encode("ascii"))


def test_writer_output_classifies_as_bound_complete(tmp_path):
    out = _bundle(tmp_path)
    names = {path.name for path in out.iterdir()}
    assert names == BOUND_FILES
    manifest = (out / "manifest.json").read_bytes()
    assert type(validate_manifest(manifest)) is BoundManifest
    marker = validate_export_state((out / "export-state.json").read_bytes())
    assert type(marker) is CompleteMarker
    inventory = classify_bundle(
        names, state=(out / "export-state.json").read_bytes(), manifest=manifest,
        receipt=(out / "manifest.sha256").read_bytes(),
        artifact_hashes={name: sha256((out / name).read_bytes()).hexdigest()
                         for name in json.loads(manifest)["artifacts"]})
    assert inventory.kind == "bound" and inventory.exit_code == marker.exit_code
    assert source_view.verify_report(out)["run_manifest_bound"] is True


def test_failed_export_leaves_only_the_canonical_aborted_marker(tmp_path, monkeypatch):
    source = tmp_path / "public-empty-plan.json"
    source.write_text(json.dumps({"format_version": "1.2", "complete": True,
                                  "errored": False, "resource_changes": []}), encoding="utf-8")
    plan = load_plan(source)
    report = reporting.build_report(plan, evaluate(plan))

    def fail_replace(*_args):
        raise OSError("synthetic finalization failure")

    monkeypatch.setattr(reporting.os, "replace", fail_replace)
    out = tmp_path / "aborted"
    with pytest.raises(OSError):
        reporting.write_report(report, out)
    assert type(validate_export_state((out / "export-state.json").read_bytes())) is AbortedMarker
    with pytest.raises(InputError):
        source_view.verify_report(out)


def test_legacy_layout_never_classifies_bound(tmp_path):
    out = _bundle(tmp_path)
    manifest = json.loads((out / "manifest.json").read_bytes())
    # Downgrading a bound bundle to legacy 1.0.0 must not keep its descriptor or
    # pass as bound; the descriptor file makes the legacy layout invalid.
    manifest["schema_version"] = "1.0.0"
    del manifest["artifacts"]["run-manifest.json"]
    _reseal(out, manifest)
    assert {path.name for path in out.iterdir()} != LEGACY_FILES
    with pytest.raises(InputError):
        source_view.verify_report(out)


@pytest.mark.parametrize("state", [
    b'{"state":"ABORTED","reason":"export_not_finalized"}',
    b'{"state":"COMPLETE","exit_code":1,"extra":true}',
    b'{"state":"PENDING","exit_code":0}',
])
def test_noncomplete_or_noncanonical_state_is_refused(tmp_path, state):
    out = _bundle(tmp_path)
    (out / "export-state.json").write_bytes(state)
    with pytest.raises(InputError):
        source_view.verify_report(out)


def test_manifest_extra_field_is_refused_even_when_resealed(tmp_path):
    out = _bundle(tmp_path)
    manifest = json.loads((out / "manifest.json").read_bytes())
    manifest["note"] = "unexpected"
    _reseal(out, manifest)
    with pytest.raises(InputError, match="bundle_manifest_schema_invalid"):
        source_view.verify_report(out)


def test_manifest_privacy_text_drift_is_refused_by_canonical_inventory(tmp_path):
    out = _bundle(tmp_path)
    manifest = json.loads((out / "manifest.json").read_bytes())
    manifest["privacy"] = "Share freely."
    _reseal(out, manifest)
    with pytest.raises(InputError, match="bundle_inventory_invalid"):
        source_view.verify_report(out)


def test_extra_pending_entry_is_refused(tmp_path):
    out = _bundle(tmp_path)
    (out / ".pending").mkdir()
    with pytest.raises(InputError, match="bundle_layout_invalid"):
        source_view.verify_report(out)
