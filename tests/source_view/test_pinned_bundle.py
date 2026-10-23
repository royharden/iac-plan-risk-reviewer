"""Focused viewer regression SOURCE; not imported or executed in Dirty Mode."""
from hashlib import sha256
import json
from pathlib import Path

import pytest

from iac_review.evidence import make_ref, resolve
from iac_review.ingest import InputError, load_plan
from iac_review.report import build_report, write_report
from iac_review.rules import evaluate
from iac_review import source_view

ADDRESS = "aws_db_instance.private_address_canary"
SECRET = "marked_and_arbitrary_tag_canary_do_not_export"


def _bundle(tmp_path: Path, mask: str = "known") -> tuple[Path, Path, str, str]:
    source = tmp_path / "original.json"
    change = {
        "actions": ["update"],
        "before": {"publicly_accessible": False, "storage_encrypted": True},
        "after": {"publicly_accessible": True, "storage_encrypted": True,
                  "tags": {"private": SECRET}},
        "after_sensitive": {"tags": True}, "after_unknown": {},
    }
    if mask == "sensitive":
        change["after_sensitive"]["publicly_accessible"] = True
    elif mask == "unknown":
        change["after_unknown"]["publicly_accessible"] = True
    source.write_text(json.dumps({
        "format_version": "1.2", "terraform_version": "1.9.0",
        "complete": True, "errored": False,
        "resource_changes": [{"address": ADDRESS, "name": "demo", "mode": "managed",
                              "provider_name": "registry.terraform.io/hashicorp/aws",
                              "type": "aws_db_instance", "change": change}],
    }), encoding="utf-8")
    plan = load_plan(source)
    report = build_report(plan, evaluate(plan))
    out = tmp_path / "report"
    write_report(report, out)
    row = next(r for r in report.private["evaluations"] if r["rule_id"] == "R2")
    fact = next(f for f in row["facts"] if f["side"] == "after" and f["field"] == "publicly_accessible")
    return out, source, row["finding_id"], fact["fact_id"]


def _reseal(out: Path) -> None:
    """Tamper fixtures recalculate hashes; source checks still must reject false facts."""
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    for name in manifest["artifacts"]:
        manifest["artifacts"][name] = sha256((out / name).read_bytes()).hexdigest()
    payload = json.dumps(manifest).encode("utf-8")
    (out / "manifest.json").write_bytes(payload)
    (out / "manifest.sha256").write_bytes((sha256(payload).hexdigest() + "\n").encode("ascii"))


def _edit_fact(out: Path, finding: str, fact_id: str, **updates) -> None:
    for filename in ("private.json", "shareable.json"):
        report = json.loads((out / filename).read_text(encoding="utf-8"))
        row = next(r for r in report["evaluations"] if r["finding_id"] == finding)
        fact = next(f for f in row["facts"] if f["fact_id"] == fact_id)
        fact.update({k: v for k, v in updates.items() if filename == "private.json" or k in fact})
        (out / filename).write_text(json.dumps(report), encoding="utf-8")
    _reseal(out)


def test_view_calls_actual_helpers_and_outputs_only_private_safe_fact(tmp_path: Path, monkeypatch) -> None:
    """Catches bypassed evidence helpers, whole-plan dumps and arbitrary tag disclosure."""
    out, source, finding, fact = _bundle(tmp_path)
    calls = []

    def checked_make(*args, **kwargs):
        calls.append("make")
        return make_ref(*args, **kwargs)

    def checked_resolve(*args, **kwargs):
        calls.append("resolve")
        return resolve(*args, **kwargs)

    monkeypatch.setattr(source_view, "make_ref", checked_make)
    monkeypatch.setattr(source_view, "resolve", checked_resolve)
    result = source_view.view_evidence(out, source, finding, fact)
    text = json.dumps(result)
    assert calls == ["make", "resolve"]
    assert result["fact"]["value"] is True and result["sensitive"] is True
    assert result["location"]["address"] == ADDRESS and result["location"]["resource_index"] == 0
    assert SECRET not in text and str(source) not in text
    assert result["decision_changed"] is False and result["producer_authenticated"] is False


@pytest.mark.parametrize("mask", ["sensitive", "unknown"])
def test_source_masks_dominate_report_value(tmp_path: Path, mask: str) -> None:
    """Catches a masked source value being returned despite a valid pointer/hash."""
    out, source, finding, fact = _bundle(tmp_path, mask)
    result = source_view.view_evidence(out, source, finding, fact)
    assert result["fact"]["state"] == mask and result["fact"]["value"] is None
    _edit_fact(out, finding, fact, value=True, state="known")
    with pytest.raises(InputError, match="evidence_value_or_mask_mismatch"):
        source_view.view_evidence(out, source, finding, fact)


@pytest.mark.parametrize("problem", ["aborted", "missing-state", "pending", "partial", "artifact"])
def test_incomplete_or_changed_bundle_is_never_trusted(tmp_path: Path, problem: str) -> None:
    """Catches using a bundle without the last COMPLETE boundary or verified bytes."""
    out, source, finding, fact = _bundle(tmp_path)
    if problem == "aborted":
        (out / "export-state.json").write_text('{"state":"ABORTED","reason":"interrupted"}', encoding="utf-8")
    elif problem == "missing-state":
        (out / "export-state.json").unlink()
    elif problem == "pending":
        (out / ".pending").mkdir()
    elif problem == "partial":
        (out / "private.html").unlink()
    else:
        with (out / "private.html").open("ab") as handle:
            handle.write(b"changed")
    with pytest.raises(InputError):
        source_view.view_evidence(out, source, finding, fact)


def test_mutated_original_and_self_rehashed_false_fact_are_rejected(tmp_path: Path) -> None:
    """Catches trusting a rehashed report's asserted value or resolving a different source."""
    out, source, finding, fact = _bundle(tmp_path)
    _edit_fact(out, finding, fact, value=False)
    with pytest.raises(InputError, match="evidence_value_or_mask_mismatch"):
        source_view.view_evidence(out, source, finding, fact)
    source.write_text(source.read_text(encoding="utf-8") + " ", encoding="utf-8")
    with pytest.raises(InputError, match="evidence_source_digest_mismatch"):
        source_view.view_evidence(out, source, finding, fact)


@pytest.mark.parametrize("pointer", [
    "/resource_changes/0/change/after/tags/private",
    "/resource_changes/0/change/after/bad~2escape",
    "/resource_changes/01/change/after/publicly_accessible",
    "/resource_changes/1/change/after/publicly_accessible",
])
def test_rehashed_locator_cannot_broaden_access(tmp_path: Path, pointer: str) -> None:
    """Catches arbitrary tag traversal, noncanonical escaping/index and cross-resource locators."""
    out, source, finding, fact = _bundle(tmp_path)
    _edit_fact(out, finding, fact, pointer=pointer)
    with pytest.raises(InputError):
        source_view.view_evidence(out, source, finding, fact)


def test_catalog_cannot_escape_bundle_and_shared_only_cannot_resolve(tmp_path: Path) -> None:
    """Catches manifest-driven file access and treating shareable IDs as a raw-source map."""
    out, source, finding, fact = _bundle(tmp_path)
    public = tmp_path / "shared-only"
    public.mkdir()
    (public / "shareable.json").write_bytes((out / "shareable.json").read_bytes())
    with pytest.raises(InputError, match="bundle_layout_invalid"):
        source_view.view_evidence(public, source, finding, fact)
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    manifest["artifacts"]["../outside.json"] = "0" * 64
    payload = json.dumps(manifest).encode("utf-8")
    (out / "manifest.json").write_bytes(payload)
    (out / "manifest.sha256").write_bytes((sha256(payload).hexdigest() + "\n").encode("ascii"))
    with pytest.raises(InputError, match="bundle_artifact_catalog_invalid"):
        source_view.verify_report(out)


def test_bundle_verification_does_not_guess_original_path(tmp_path: Path, monkeypatch) -> None:
    """Catches verify-only unexpectedly reopening a plan or making a security verdict."""
    out, _, _, _ = _bundle(tmp_path)

    def forbidden(*args, **kwargs):
        raise AssertionError("verify-only must not load any plan")

    monkeypatch.setattr(source_view, "load_plan", forbidden)
    result = source_view.verify_report(out)
    assert result["source_digest_verified"] is False
    assert result["raw_source_access_enabled"] is False and result["product_acceptance"] is False


def test_bundle_symlink_is_refused_before_source_resolution(tmp_path: Path) -> None:
    """Catches following a leaf link even when its contents match the artifact hash."""
    out, source, finding, fact = _bundle(tmp_path)
    target = tmp_path / "copied-private.json"
    target.write_bytes((out / "private.json").read_bytes())
    (out / "private.json").unlink()
    try:
        (out / "private.json").symlink_to(target)
    except OSError:
        pytest.skip("platform does not permit this synthetic symlink fixture")
    with pytest.raises(InputError, match="source_link_rejected"):
        source_view.view_evidence(out, source, finding, fact)


@pytest.mark.parametrize("state", [
    b'{"state":"COMPLETE","state":"COMPLETE","exit_code":1}', b"x" * 4097,
])
def test_bundle_decoder_and_small_state_limit_remain_closed(tmp_path: Path, state: bytes) -> None:
    """Catches permissive duplicate-key parsing or unbounded export-state ingestion."""
    out, _, _, _ = _bundle(tmp_path)
    (out / "export-state.json").write_bytes(state)
    with pytest.raises(InputError):
        source_view.verify_report(out)


def test_bundle_mutation_during_resolve_aborts_return(tmp_path: Path, monkeypatch) -> None:
    """Catches trusting only the initial artifact digest during a source lookup."""
    out, source, finding, fact = _bundle(tmp_path)

    def mutate_after_resolve(*args, **kwargs):
        resolved = resolve(*args, **kwargs)
        with (out / "private.html").open("ab") as handle:
            handle.write(b"mutation")
        return resolved

    monkeypatch.setattr(source_view, "resolve", mutate_after_resolve)
    with pytest.raises(InputError, match="bundle_changed_during_view"):
        source_view.view_evidence(out, source, finding, fact)


def test_integrated_cli_keeps_verification_separate_from_private_location(tmp_path: Path, capsys) -> None:
    """Catches private location disclosure in verify-only or loss of explicit source selection."""
    from iac_review.cli import main

    out, source, finding, fact = _bundle(tmp_path)
    assert main(["evidence", str(out), "--plan", str(source), "--finding", finding, "--fact", fact]) == 0
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert not captured.err and result["location"]["address"] == ADDRESS
    assert result["sensitive"] is True and SECRET not in captured.out
    assert main(["verify-report", str(out)]) == 0
    captured = capsys.readouterr()
    verified = json.loads(captured.out)
    assert ADDRESS not in captured.out and SECRET not in captured.out
    assert verified["source_digest_verified"] is False and verified["raw_source_access_enabled"] is False


def test_integrated_cli_missing_plan_or_failed_manifest_returns_error_without_data(tmp_path: Path, capsys) -> None:
    """Catches argparse/verification errors impersonating coverage success or echoing source data."""
    from iac_review.cli import main

    out, _, finding, fact = _bundle(tmp_path)
    assert main(["evidence", str(out), "--finding", finding, "--fact", fact]) == 3
    capsys.readouterr()
    (out / "manifest.sha256").write_bytes(b"0" * 64 + b"\n")
    assert main(["verify-report", str(out)]) == 3
    captured = capsys.readouterr()
    assert not captured.out and "bundle_manifest_hash_mismatch" in captured.err
    assert ADDRESS not in captured.err and SECRET not in captured.err


def test_integrated_cli_shares_whole_invocation_budget(tmp_path: Path, monkeypatch, capsys) -> None:
    """Catches viewer routing resetting the existing CLI budget or emitting after deadline."""
    from iac_review import cli
    from types import SimpleNamespace

    observed = []

    def fake_verify(bundle, original, *, deadline):
        observed.append(deadline)
        return {"status": "fixture_only"}

    clock = iter((100.0, 100.0 + cli.MAX_SECONDS + 1))
    monkeypatch.setattr(source_view, "verify_report", fake_verify)
    monkeypatch.setattr(cli, "time", SimpleNamespace(monotonic=lambda: next(clock)))
    assert cli.main(["verify-report", str(tmp_path)]) == 3
    captured = capsys.readouterr()
    assert observed == [100.0 + cli.MAX_SECONDS]
    assert not captured.out and "review_time_limit" in captured.err
