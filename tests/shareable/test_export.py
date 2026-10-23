"""Safe sharing regression SOURCE only; not executed during Dirty Mode."""
from hashlib import sha256
import json
from pathlib import Path

import pytest

from iac_review import cli, shareable_export
from iac_review.ingest import InputError, load_plan
from iac_review.report import build_report, write_report
from iac_review.rules import evaluate


@pytest.fixture
def bound_bundle(core_change, core_plan_file, tmp_path):
    def build(fail_on=3):
        entry = core_change(
            actions=("create",), address='aws_db_instance.synthetic["PRIVATE-ADDRESS-CANARY"]',
            after={"publicly_accessible": True, "storage_encrypted": True,
                   "tags": {"x": "PRIVATE-TAG-CANARY", "secret": "MARKED-VALUE-CANARY"}},
            change_fields={"after_sensitive": {"tags": {"secret": True}}},
        )
        initial = core_plan_file([entry])
        source = tmp_path / "PRIVATE-SOURCE-FILENAME-CANARY.json"
        source.write_bytes(initial.read_bytes())
        plan = load_plan(source)
        report = build_report(plan, evaluate(plan), fail_on=fail_on)
        bundle = tmp_path / "private-bundle"
        write_report(report, bundle)
        return bundle, source, plan, report
    return build


def rehash_artifact(bundle, name):
    manifest = json.loads((bundle / "manifest.json").read_text())
    manifest["artifacts"][name] = sha256((bundle / name).read_bytes()).hexdigest()
    raw = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    (bundle / "manifest.json").write_bytes(raw)
    (bundle / "manifest.sha256").write_text(sha256(raw).hexdigest() + "\n")


@pytest.mark.parametrize("fail_on", [3, 4])
def test_detached_export_contains_only_fresh_safe_projection_and_same_threshold(bound_bundle, tmp_path, fail_on):
    bundle, source, plan, original = bound_bundle(fail_on)
    out = tmp_path / "shared"
    result = shareable_export.export_shareable(bundle, source, out)
    assert result["review_exit_code"] == original.exit_code
    assert result["private_mapping_retained"] is False
    assert {file.name for file in out.iterdir()} == {
        "shareable.json", "shareable.html", "manifest.json", "manifest.sha256", "export-state.json",
    }
    shared = json.loads((out / "shareable.json").read_text())
    assert shared["summary"] == original.shareable["summary"]
    assert shared["run_id"] != original.shareable["run_id"]
    assert shared["case_id"] != original.shareable["case_id"]
    assert set(shared["measurements"].values()) == {"NOT MEASURED"}
    contents = "".join(file.read_text(encoding="utf-8") for file in out.iterdir())
    for private in ("PRIVATE-ADDRESS-CANARY", "PRIVATE-TAG-CANARY", "MARKED-VALUE-CANARY",
                    source.name, plan.identity.sha256, "run-manifest.json", "private_map"):
        assert private not in contents
    assert json.loads((out / "export-state.json").read_text())["state"] == "COMPLETE"
    manifest = json.loads((out / "manifest.json").read_text())
    assert manifest["source_resolvable"] is False
    for name, pin in manifest["artifacts"].items():
        assert sha256((out / name).read_bytes()).hexdigest() == pin


@pytest.mark.parametrize("fault", ["source", "html_hash", "semantic_json", "html_consistent_hash", "code", "unbound"])
def test_changed_or_unbound_inputs_refuse_before_safe_output(bound_bundle, tmp_path, monkeypatch, fault):
    bundle, source, *_ = bound_bundle()
    out = tmp_path / "shared"
    if fault == "source":
        source.write_bytes(source.read_bytes() + b" ")
    elif fault in ("html_hash", "html_consistent_hash"):
        (bundle / "shareable.html").write_text("<script>UNTRUSTED-STORED-HTML</script>")
        if fault == "html_consistent_hash":
            rehash_artifact(bundle, "shareable.html")
    elif fault == "semantic_json":
        shared = json.loads((bundle / "shareable.json").read_text())
        shared["summary"]["risk_present"] = False
        (bundle / "shareable.json").write_text(json.dumps(shared))
        rehash_artifact(bundle, "shareable.json")
    elif fault == "code":
        monkeypatch.setattr(shareable_export, "_current_pins", lambda _check: {})
    else:
        monkeypatch.setattr(shareable_export, "verify_report", lambda *_args, **_kwargs: {"run_manifest_bound": False})
    with pytest.raises((InputError, ValueError)):
        shareable_export.export_shareable(bundle, source, out)
    assert not out.exists()


def test_existing_private_or_unsafe_output_namespace_is_never_overwritten(bound_bundle, tmp_path):
    bundle, source, *_ = bound_bundle()
    with pytest.raises(InputError):
        shareable_export.export_shareable(bundle, source, bundle / "shared")
    out = tmp_path / "occupied"
    out.mkdir()
    sentinel = out / "private.json"
    sentinel.write_text("preserve")
    with pytest.raises(InputError):
        shareable_export.export_shareable(bundle, source, out)
    assert sentinel.read_text() == "preserve" and list(out.iterdir()) == [sentinel]
    with pytest.raises(InputError, match="plain_local"):
        shareable_export.export_shareable(bundle, source, bundle / ".." / "shared")


def test_partial_write_rolls_back_only_safe_files_and_keeps_aborted(bound_bundle, tmp_path, monkeypatch):
    bundle, source, *_ = bound_bundle()
    out = tmp_path / "shared"
    real_open = Path.open
    def fail_public_write(path, *args, **kwargs):
        if path == out / "shareable.html":
            raise OSError("synthetic publication failure")
        return real_open(path, *args, **kwargs)
    monkeypatch.setattr(Path, "open", fail_public_write)
    with pytest.raises(OSError):
        shareable_export.export_shareable(bundle, source, out)
    assert {path.name for path in out.iterdir()} == {"export-state.json"}
    assert json.loads((out / "export-state.json").read_text())["state"] == "ABORTED"


def test_share_cli_preserves_review_exit_and_requires_explicit_original_plan(bound_bundle, tmp_path, capsys):
    bundle, source, _, original = bound_bundle()
    out = tmp_path / "shared"
    assert cli.main(["share", str(bundle), "--plan", str(source), "--out", str(out)]) == original.exit_code
    assert "shareable_exported" in capsys.readouterr().out
    assert cli.main(["share", str(bundle), "--out", str(tmp_path / "missing-plan")]) == 3
    assert not (tmp_path / "missing-plan").exists()
