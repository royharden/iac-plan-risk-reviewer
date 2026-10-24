"""Canonical report wire at producer/writer/reader boundaries and source profile v2.

Regression SOURCE only; not imported or executed during Dirty Mode. Public
synthetic plans only, never hidden oracle data.
"""
from hashlib import sha256
import json
from pathlib import Path

import pytest

from iac_review import source_view
from iac_review.contracts import ReviewReport
from iac_review.contracts.report_wire import PrivateProjection, ShareableProjection, validate_report_pair
from iac_review.ingest import InputError, load_plan
from iac_review.provenance import (
    CORE_FILES_V1, CORE_FILES_V2, CURRENT_PROFILE, ReportProvenance, content_digest,
)
from iac_review.report import build_report, write_report
from iac_review.rules import evaluate

ADDRESS = "aws_db_instance.wire_address_canary"


def _review(tmp_path: Path) -> tuple[Path, ReviewReport]:
    source = tmp_path / "public-wire-plan.json"
    source.write_text(json.dumps({
        "format_version": "1.2", "terraform_version": "1.9.0", "complete": True, "errored": False,
        "resource_changes": [{"address": ADDRESS, "name": "demo", "mode": "managed",
                              "provider_name": "registry.terraform.io/hashicorp/aws",
                              "type": "aws_db_instance", "change": {
                                  "actions": ["update"],
                                  "before": {"publicly_accessible": False, "storage_encrypted": True},
                                  "after": {"publicly_accessible": True, "storage_encrypted": True},
                                  "after_sensitive": {}, "after_unknown": {}}}],
    }), encoding="utf-8")
    plan = load_plan(source)
    return source, build_report(plan, evaluate(plan))


def _descriptor(report: ReviewReport) -> ReportProvenance:
    return ReportProvenance.model_validate_json(json.dumps(report.private["provenance"]["descriptor"]))


def test_producer_output_is_the_canonical_validated_pair(tmp_path):
    _, report = _review(tmp_path)
    private, shareable = validate_report_pair(report.private, report.shareable, exit_code=report.exit_code)
    assert isinstance(private, PrivateProjection) and isinstance(shareable, ShareableProjection)
    # The dictionary facade is preserved and already equals the canonical dump.
    assert report.validate_wire() == (report.private, report.shareable)
    assert ADDRESS not in json.dumps(report.shareable)


@pytest.mark.parametrize("mutate", [
    lambda r: r.shareable["evaluations"][0].__setitem__("address", ADDRESS),   # private leak
    lambda r: r.shareable.__setitem__("provenance", {}),                        # extra field
    lambda r: r.private["summary"].pop("clear"),                                # missing truth
    lambda r: r.private["summary"].__setitem__("exit_code", (r.exit_code + 1) % 3),  # exit drift
    lambda r: r.private["evaluations"][0].__setitem__("severity", 9),           # malformed
    lambda r: r.private["provenance"]["descriptor"].pop("kind"),                # default must not refill
    lambda r: r.private["provenance"]["descriptor"].pop("producer_authenticated"),
])
def test_writer_revalidates_mutated_dictionaries_and_stays_aborted(tmp_path, mutate):
    _, report = _review(tmp_path)
    mutate(report)
    out = tmp_path / "refused"
    with pytest.raises(ValueError):
        write_report(report, out)
    assert json.loads((out / "export-state.json").read_bytes())["state"] == "ABORTED"
    assert sorted(p.name for p in out.iterdir()) == ["export-state.json"]


def test_validated_constructor_rejects_instead_of_filling(tmp_path):
    _, report = _review(tmp_path)
    private = dict(report.private)
    del private["limitations"]
    with pytest.raises(ValueError):
        ReviewReport.validated(private, report.shareable, report.exit_code)


def test_reader_rejects_bound_bundle_that_fails_canonical_wire(tmp_path):
    _, report = _review(tmp_path)
    out = tmp_path / "bundle"
    write_report(report, out)
    shared = json.loads((out / "shareable.json").read_bytes())
    shared["unexpected"] = True
    (out / "shareable.json").write_bytes(json.dumps(shared).encode("utf-8"))
    manifest = json.loads((out / "manifest.json").read_bytes())
    manifest["artifacts"]["shareable.json"] = sha256((out / "shareable.json").read_bytes()).hexdigest()
    payload = json.dumps(manifest).encode("utf-8")
    (out / "manifest.json").write_bytes(payload)
    (out / "manifest.sha256").write_bytes((sha256(payload).hexdigest() + "\n").encode("ascii"))
    with pytest.raises(InputError, match="bundle_report_wire_invalid"):
        source_view.verify_report(out)


@pytest.mark.parametrize("control", ["receipt-without-lf", "error-exit-3"])
def test_reader_control_files_follow_report_inventory(tmp_path, control):
    _, report = _review(tmp_path)
    out = tmp_path / "bundle"
    write_report(report, out)
    if control == "receipt-without-lf":
        (out / "manifest.sha256").write_bytes((out / "manifest.sha256").read_bytes().rstrip(b"\n"))
        code = "bundle_manifest_hash_invalid"
    else:
        (out / "export-state.json").write_bytes(b'{"state":"COMPLETE","exit_code":3}')
        code = "bundle_exit_invalid"
    with pytest.raises(InputError, match=code):
        source_view.verify_report(out)


def test_reader_accepts_escaped_address_beyond_plan_string_cap(tmp_path):
    # ensure_ascii turns each non-ASCII character into a 6-byte escape; the
    # writer's own bundle must not trip the plan decoder's 256 KiB string cap.
    source = tmp_path / "wide-address-plan.json"
    address = "aws_db_instance." + "é" * 60000
    source.write_text(json.dumps({
        "format_version": "1.2", "complete": True, "errored": False,
        "resource_changes": [{"address": address, "name": "demo", "mode": "managed",
                              "provider_name": "registry.terraform.io/hashicorp/aws",
                              "type": "aws_db_instance", "change": {
                                  "actions": ["update"],
                                  "before": {"publicly_accessible": False, "storage_encrypted": True},
                                  "after": {"publicly_accessible": True, "storage_encrypted": True},
                                  "after_sensitive": {}, "after_unknown": {}}}],
    }, ensure_ascii=False), encoding="utf-8")
    plan = load_plan(source)
    out = tmp_path / "bundle"
    write_report(build_report(plan, evaluate(plan)), out)
    assert source_view.verify_report(out)["run_manifest_bound"] is True


def test_new_reports_pin_profile_two_with_report_wire(tmp_path):
    _, report = _review(tmp_path)
    descriptor = _descriptor(report)
    assert CURRENT_PROFILE == 2 and descriptor.schema_version == 2
    assert {row.path for row in descriptor.source_files} == set(CORE_FILES_V2)
    assert len(CORE_FILES_V1) == 9 and len(CORE_FILES_V2) == 11
    for added in ("contracts/report_wire.py", "contracts/report_inventory.py"):
        assert added in CORE_FILES_V2 and added not in CORE_FILES_V1
    source = next(c for c in descriptor.run_manifest.components if c.kind == "source")
    assert source.version == "content-v2"


def _as_profile(descriptor: ReportProvenance, schema_version: int, paths, source_version: str) -> dict:
    data = descriptor.model_dump(mode="json")
    pins = [row for row in data["source_files"] if row["path"] in paths]
    build = content_digest({row["path"]: row["sha256"] for row in pins})
    data["schema_version"], data["source_files"] = schema_version, pins
    data["run_manifest"]["build_sha256"] = build
    for component in data["run_manifest"]["components"]:
        if component["kind"] == "source":
            component["sha256"], component["version"] = build, source_version
    return data


def test_profile_one_descriptor_still_verifies_without_repin(tmp_path):
    _, report = _review(tmp_path)
    v1 = _as_profile(_descriptor(report), 1, CORE_FILES_V1, "content-v1")
    assert ReportProvenance.model_validate_json(json.dumps(v1)).schema_version == 1


@pytest.mark.parametrize("schema_version,paths,source_version", [
    (1, CORE_FILES_V2, "content-v1"),   # v1 claiming eleven files
    (2, CORE_FILES_V1, "content-v2"),   # v2 missing report_wire and inventory
    (2, CORE_FILES_V1 + ("contracts/report_wire.py",), "content-v2"),  # pre-amendment ten-file v2
    (1, CORE_FILES_V1, "content-v2"),   # profile/source version mismatch
    (2, CORE_FILES_V2, "content-v1"),
])
def test_mixed_profile_inventories_refuse(tmp_path, schema_version, paths, source_version):
    _, report = _review(tmp_path)
    forged = _as_profile(_descriptor(report), schema_version, paths, source_version)
    with pytest.raises(ValueError):
        ReportProvenance.model_validate_json(json.dumps(forged))


def test_unversioned_constructor_does_not_claim_profile_two(tmp_path):
    _, report = _review(tmp_path)
    descriptor = _descriptor(report)
    with pytest.raises(ValueError):
        ReportProvenance(run_manifest=descriptor.run_manifest, source_files=descriptor.source_files,
                         config=descriptor.config)
