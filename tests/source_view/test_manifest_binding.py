"""Unexecuted integrity regressions with public empty plans; no hidden labels."""
from hashlib import sha256
import json

import pytest

from iac_review.ingest import InputError, load_plan
from iac_review.report import build_report, write_report
from iac_review.rules import evaluate
from iac_review.source_view import verify_report


def bundle(tmp_path):
    source = tmp_path / "public-empty.json"
    source.write_text(json.dumps({"format_version": "1.2", "complete": True,
                                  "errored": False, "resource_changes": []}), encoding="utf-8")
    plan = load_plan(source)
    report = build_report(plan, evaluate(plan))
    out = tmp_path / "reports"
    write_report(report, out)
    return source, out


def test_viewer_verifies_bound_manifest_without_authentication_claim(tmp_path):
    source, out = bundle(tmp_path)
    result = verify_report(out, source)
    assert result["run_manifest_bound"] is True
    assert result["run_manifest_sha256"] == sha256((out / "run-manifest.json").read_bytes()).hexdigest()
    assert result["artifacts_verified"] == 4  # Existing report-file API remains stable.
    assert result["producer_authenticated"] is False and result["product_acceptance"] is False


def test_matching_outer_hash_cannot_substitute_another_descriptor(tmp_path):
    _, out = bundle(tmp_path)
    path = out / "run-manifest.json"
    descriptor = json.loads(path.read_bytes())
    descriptor["run_manifest"]["run_id"] = "f" * 32
    raw = (json.dumps(descriptor, sort_keys=True, ensure_ascii=True, indent=2) + "\n").encode()
    path.write_bytes(raw)
    manifest_path = out / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest["artifacts"]["run-manifest.json"] = sha256(raw).hexdigest()
    manifest_raw = (json.dumps(manifest, sort_keys=True, ensure_ascii=True, indent=2) + "\n").encode()
    manifest_path.write_bytes(manifest_raw)
    (out / "manifest.sha256").write_text(sha256(manifest_raw).hexdigest() + "\n")
    with pytest.raises(InputError, match="run_manifest_binding"):
        verify_report(out)


def test_viewer_rejects_extra_files_and_aborted_state(tmp_path):
    _, out = bundle(tmp_path)
    (out / "untracked.json").write_text("{}")
    with pytest.raises(InputError, match="layout"):
        verify_report(out)
    # Remove only this test's own extra file; production viewer never repairs a bundle.
    (out / "untracked.json").unlink()
    (out / "export-state.json").write_text('{"state":"ABORTED","reason":"test"}')
    with pytest.raises(InputError, match="not_complete"):
        verify_report(out)
