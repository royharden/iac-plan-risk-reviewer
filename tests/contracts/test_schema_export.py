"""Unexecuted schema-export regression SOURCE; no generated schema claim."""
import ast
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
EXPORTER = ROOT / "scripts" / "export_schemas.py"


def exporter():
    spec = importlib.util.spec_from_file_location("public_schema_export_source", EXPORTER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_import_does_not_load_application_or_write_files(monkeypatch):
    tree = ast.parse(EXPORTER.read_text(encoding="utf-8"))
    def refuse(*args, **kwargs):
        raise AssertionError("schema exporter wrote during import")
    monkeypatch.setattr(Path, "mkdir", refuse)
    monkeypatch.setattr(Path, "write_text", refuse)
    monkeypatch.setattr(Path, "open", refuse)
    module = exporter()
    assert callable(module.export_schemas)
    # App imports live inside the explicit registry function, never at module scope.
    imports = [node for node in tree.body if isinstance(node, ast.ImportFrom)]
    assert not any((node.module or "").startswith(("iac_review", "eval.")) for node in imports)


def test_explicit_boundary_schemas_are_closed_and_manifest_matches(tmp_path):
    module = exporter()
    out = tmp_path / "fresh-schemas"
    manifest = module.export_schemas(out)
    assert manifest["schema_version"] == 2
    assert manifest["schema_only"] is True
    catalogue = json.loads((out / "catalogue.json").read_text())
    entries = {entry["filename"]: entry for entry in catalogue["entries"]}
    assert {"eval-ArmRow.schema.json", "custody-Seal.schema.json",
            "bridge-UtilityRequest.schema.json", "utility-Attempt.schema.json"} <= set(manifest["files"])
    for name, expected in manifest["files"].items():
        raw = (out / name).read_bytes()
        schema = json.loads(raw)
        if entries[name]["representation"] == "pydantic_closed":
            assert schema["additionalProperties"] is False
        else:
            assert entries[name]["canonical_root_unknown_fields_rejected"] is False
        assert hashlib.sha256(raw).hexdigest() == expected
    assert hashlib.sha256((out / "catalogue.json").read_bytes()).hexdigest() == manifest["catalogue"]["sha256"]
    assert json.loads((out / "schema-export-state.json").read_text())["state"] == "COMPLETE"
    for field in ("payload_admission", "execution_verified", "actor_authenticated",
                  "provider_activated", "release_authorized", "product_acceptance"):
        assert manifest[field] is False
    assert json.loads((out / "manifest.json").read_text()) == manifest
    with pytest.raises(ValueError, match="fresh"):
        module.export_schemas(out)


def test_schema_generation_failure_leaves_destination_absent(tmp_path, monkeypatch):
    module = exporter()
    class InvalidBoundary:
        model_config = {"strict": False, "frozen": True, "extra": "forbid"}
    monkeypatch.setattr(module, "boundary_models", lambda: {"invalid": InvalidBoundary})
    out = tmp_path / "should-not-exist"
    with pytest.raises(ValueError, match="required completed wire"):
        module.export_schemas(out)
    assert not out.exists()


def test_cli_retains_out_and_refuses_module_or_object_selection(tmp_path, monkeypatch):
    module = exporter()
    seen = []
    monkeypatch.setattr(module, "export_schemas", lambda out: seen.append(out))
    out = tmp_path / "schemas"
    assert module.main(["--out", str(out)]) == 0
    assert seen == [out]
    for extra in (("--module", "eval.model.provider_http"), ("--type", "ProviderTransport")):
        with pytest.raises(SystemExit) as caught:
            module.main(["--out", str(out), *extra])
        assert caught.value.code == 2
    assert seen == [out]


def test_partial_schema_write_retains_aborted_marker(tmp_path, monkeypatch):
    module = exporter()
    real_open = Path.open
    def fail_catalogue(path, *args, **kwargs):
        if path.name == "catalogue.json" and args and args[0] == "xb":
            raise OSError("synthetic write failure")
        return real_open(path, *args, **kwargs)
    monkeypatch.setattr(Path, "open", fail_catalogue)
    out = tmp_path / "partial"
    with pytest.raises(OSError):
        module.export_schemas(out)
    assert json.loads((out / "schema-export-state.json").read_text())["state"] == "ABORTED"
    assert {path.name for path in out.iterdir()} == {"schema-export-state.json"}
