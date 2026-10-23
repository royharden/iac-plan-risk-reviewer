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
    assert {"eval-ArmRow.schema.json", "custody-Seal.schema.json",
            "bridge-UtilityRequest.schema.json", "utility-Attempt.schema.json"} <= set(manifest["files"])
    for name, expected in manifest["files"].items():
        raw = (out / name).read_bytes()
        schema = json.loads(raw)
        assert schema["additionalProperties"] is False
        assert hashlib.sha256(raw).hexdigest() == expected
    assert json.loads((out / "manifest.json").read_text()) == manifest
    with pytest.raises(ValueError, match="fresh"):
        module.export_schemas(out)


def test_schema_generation_failure_leaves_destination_absent(tmp_path, monkeypatch):
    module = exporter()
    class InvalidBoundary:
        model_config = {"strict": False, "frozen": True, "extra": "forbid"}
    monkeypatch.setattr(module, "boundary_models", lambda: {"invalid": InvalidBoundary})
    out = tmp_path / "should-not-exist"
    with pytest.raises(ValueError, match="strict"):
        module.export_schemas(out)
    assert not out.exists()
