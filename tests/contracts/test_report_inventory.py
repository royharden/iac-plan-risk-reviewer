"""Report bundle inventory/control types: bound 1.1.0 eight-file, legacy 1.0.0 seven-file,
COMPLETE/ABORTED markers.

Regression SOURCE only; authored in Dirty Mode, not imported or executed yet.
Synthetic control bytes only; no real archive is read.
"""
from hashlib import sha256
import json

import pytest

from iac_review.contracts import report_inventory as inv
from iac_review.contracts.report_inventory import (
    BOUND_FILES, LEGACY_FILES, AbortedMarker, BoundManifest, CompleteMarker, LegacyManifest,
    classify_bundle, expected_files, validate_export_state, validate_manifest, validate_manifest_receipt,
)

INVALID = "report_inventory_invalid"
RUN = "a" * 32
PLAN = "b" * 64


def _json(value) -> bytes:
    # Same serialization as the writer's _json_bytes.
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("utf-8")


def _bundle(version="1.1.0", *, exit_code=1, payloads=None):
    names = sorted(inv.BOUND_PAYLOADS if version == "1.1.0" else inv.LEGACY_PAYLOADS) if payloads is None else payloads
    hashes = {name: sha256(name.encode()).hexdigest() for name in names}
    manifest = _json({
        "schema_version": version, "run_id": RUN, "created_at": "2026-10-23T22:00:00+00:00",
        "plan_sha256": PLAN, "parser_version": "1.0.0", "policy_version": "1.0.0",
        "artifacts": hashes, "privacy": inv.PRIVACY_TEXT,
    })
    receipt = (sha256(manifest).hexdigest() + "\n").encode("ascii")
    state = _json({"state": "COMPLETE", "exit_code": exit_code})
    files = set(hashes) | {"manifest.json", "manifest.sha256", "export-state.json"}
    return dict(names=sorted(files), state=state, manifest=manifest, receipt=receipt, artifact_hashes=hashes)


def _rejected(call, *args, **kwargs):
    with pytest.raises(ValueError) as caught:
        call(*args, **kwargs)
    assert str(caught.value) == INVALID


def test_file_sets_are_exactly_eight_bound_and_seven_legacy():
    assert len(BOUND_FILES) == 8 and len(LEGACY_FILES) == 7
    assert BOUND_FILES - LEGACY_FILES == {"run-manifest.json"}
    assert expected_files("1.1.0") == BOUND_FILES and expected_files("1.0.0") == LEGACY_FILES
    _rejected(expected_files, "1.2.0")


def test_bound_bundle_classifies_as_bound_complete():
    result = classify_bundle(**_bundle())
    assert result.kind == "bound" and result.manifest_version == "1.1.0" and result.exit_code == 1
    assert set(result.artifacts) == inv.BOUND_PAYLOADS


def test_legacy_bundle_classifies_as_legacy_never_bound():
    result = classify_bundle(**_bundle("1.0.0"))
    assert result.kind == "legacy" and "run-manifest.json" not in result.artifacts


def test_aborted_or_unknown_state_never_classifies_complete():
    bundle = _bundle()
    bundle["state"] = _json({"state": "ABORTED", "reason": "export_not_finalized"})
    _rejected(classify_bundle, **bundle)
    for state in ({"state": "COMPLETE"}, {"state": "COMPLETE", "exit_code": 3},
                  {"state": "COMPLETE", "exit_code": True}, {"state": "DONE", "exit_code": 0},
                  {"state": "ABORTED", "reason": "other"}, {"state": "COMPLETE", "exit_code": 0, "extra": 1}):
        bundle["state"] = _json(state)
        _rejected(classify_bundle, **bundle)


def test_markers_parse_to_their_types():
    assert type(validate_export_state(_json({"state": "COMPLETE", "exit_code": 0}))) is CompleteMarker
    assert type(validate_export_state(_json({"state": "ABORTED", "reason": "export_not_finalized"}))) is AbortedMarker
    _rejected(validate_export_state, b'{"state":"COMPLETE","exit_code":0,"state":"ABORTED"}')


@pytest.mark.parametrize("mutate", [
    lambda b: b.__setitem__("names", b["names"][:-1]),                                   # partial
    lambda b: b.__setitem__("names", [*b["names"], ".pending"]),                         # staging left
    lambda b: b.__setitem__("names", [*b["names"], ".export-state.pending"]),
    lambda b: b.__setitem__("names", [n for n in b["names"] if n != "run-manifest.json"]),  # bound missing descriptor
    lambda b: b.__setitem__("names", [*b["names"], b["names"][0]]),                      # duplicate entry
    lambda b: b["artifact_hashes"].__setitem__("private.json", "c" * 64),                # hash drift
    lambda b: b.__setitem__("receipt", b["receipt"].rstrip(b"\n")),                      # receipt not LF-terminated
    lambda b: b.__setitem__("receipt", b"0" * 64 + b"\n"),                               # receipt mismatch
])
def test_partial_or_mismatched_bundles_rejected(mutate):
    bundle = _bundle()
    mutate(bundle)
    _rejected(classify_bundle, **bundle)


def test_legacy_manifest_cannot_list_the_bound_descriptor_and_vice_versa():
    _rejected(validate_manifest, _bundle("1.0.0", payloads=sorted(inv.BOUND_PAYLOADS))["manifest"])
    _rejected(validate_manifest, _bundle("1.1.0", payloads=sorted(inv.LEGACY_PAYLOADS))["manifest"])
    assert type(validate_manifest(_bundle("1.1.0")["manifest"])) is BoundManifest
    assert type(validate_manifest(_bundle("1.0.0")["manifest"])) is LegacyManifest


def test_legacy_layout_with_bound_files_rejected():
    bundle = _bundle("1.0.0")
    bundle["names"] = sorted(BOUND_FILES)
    _rejected(classify_bundle, **bundle)


@pytest.mark.parametrize("field, value", [
    ("created_at", "2026-10-23T22:00:00"),  # naive timestamp
    ("schema_version", "1.2.0"), ("run_id", "A" * 32), ("plan_sha256", "short"),
    ("privacy", "share everything"), ("parser_version", "2.0.0"),
])
def test_manifest_fields_strict(field, value):
    manifest = json.loads(_bundle()["manifest"])
    manifest[field] = value
    _rejected(validate_manifest, _json(manifest))


def test_receipt_helper_returns_manifest_digest():
    bundle = _bundle()
    assert validate_manifest_receipt(bundle["receipt"], bundle["manifest"]) == sha256(bundle["manifest"]).hexdigest()
    _rejected(validate_manifest_receipt, bundle["receipt"].decode(), bundle["manifest"])


def test_control_files_are_bounded_and_strict_json():
    _rejected(validate_export_state, b" " * (inv.MAX_CONTROL_BYTES + 1))
    # Otherwise-valid documents, so only strict ingress can reject them.
    _rejected(validate_export_state, b'{"state":"COMPLETE","exit_code":0,"x":NaN}')
    assert type(validate_manifest(_bundle()["manifest"])) is BoundManifest
    _rejected(validate_manifest, b"\xef\xbb\xbf" + _bundle()["manifest"])
