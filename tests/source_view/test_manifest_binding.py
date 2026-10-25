"""Unexecuted integrity regressions with public empty plans; no hidden labels."""
import json
from hashlib import sha256

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
    assert result["artifacts_verified"] == 5  # Bound inventory includes run-manifest.json.
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
    (out / "manifest.sha256").write_bytes((sha256(manifest_raw).hexdigest() + "\n").encode("ascii"))
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


@pytest.mark.parametrize("layout,expected_count", [("bound", 5), ("legacy", 4)])
def test_verified_count_matches_each_closed_payload_inventory(tmp_path, layout, expected_count):
    """Count actual verified files, not one constant shared between two layouts."""
    source, bound = bundle(tmp_path)
    target = bound
    if layout == "legacy":
        target = tmp_path / "legacy"
        target.mkdir()
        manifest = json.loads((bound / "manifest.json").read_bytes())
        manifest["schema_version"] = "1.0.0"
        del manifest["artifacts"]["run-manifest.json"]
        for name in manifest["artifacts"]:
            raw = (bound / name).read_bytes()
            if name == "private.json":
                private = json.loads(raw)
                private.pop("provenance", None)
                raw = json.dumps(private).encode("utf-8")
            (target / name).write_bytes(raw)
            manifest["artifacts"][name] = sha256(raw).hexdigest()
        manifest_raw = json.dumps(manifest).encode("utf-8")
        (target / "manifest.json").write_bytes(manifest_raw)
        (target / "manifest.sha256").write_bytes(
            (sha256(manifest_raw).hexdigest() + "\n").encode("ascii"))
        (target / "export-state.json").write_bytes((bound / "export-state.json").read_bytes())
    result = verify_report(target, source)
    manifest = json.loads((target / "manifest.json").read_bytes())
    assert len(manifest["artifacts"]) == expected_count
    assert result["artifacts_verified"] == expected_count
    assert result["run_manifest_bound"] is (layout == "bound")
    assert result["source_digest_verified"] is True



def test_receipt_crlf_is_rejected_instead_of_weakening_exact_bytes(tmp_path):
    """Windows text translation must not silently change a canonical LF receipt."""
    source, out = bundle(tmp_path)
    manifest_raw = (out / "manifest.json").read_bytes()
    (out / "manifest.sha256").write_bytes(
        (sha256(manifest_raw).hexdigest() + "\r\n").encode("ascii"))
    with pytest.raises(InputError, match="manifest_hash_invalid"):
        verify_report(out, source)
