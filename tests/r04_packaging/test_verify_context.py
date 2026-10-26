"""Public negative controls for the reviewer validator, no candidate code import."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile

import pytest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("rv4_packaging_checker", HERE / "verify_context.py")
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)
COMMIT = "7d9e6efe682a55146d51b0675c0611a1381576f7"


@pytest.fixture
def directory():
    # Keep every adversarial output; no pytest deletion or linked current path.
    root = Path(tempfile.mkdtemp(prefix="m4-r04-rv4-packaging-",
                              dir=os.environ["RV4_PACKAGING_OUTPUT"]))
    context = root / "context"
    (context / "pins").mkdir(parents=True)
    return context


def materialize(context, pins=None, source_delta=None):
    source = {"source_commit": checker.BASE, "packaging_commit": COMMIT,
              "primary_scans": 0, "files": {}}
    source.update(source_delta or {})
    raw_source = json.dumps(source).encode()
    raw_pins = json.dumps(pins or {}).encode()
    (context / "pins/source.json").write_bytes(raw_source)
    (context.parent / "context-pins.json").write_bytes(raw_pins)
    return hashlib.sha256(raw_pins).hexdigest(), hashlib.sha256(raw_source).hexdigest()


@pytest.mark.parametrize("commit", ["HEAD", COMMIT[:8], COMMIT.upper(), "x" * 40])
def test_exact_packaging_commit_required(directory, commit):
    pins, source = materialize(directory)
    with pytest.raises(ValueError, match="exact packaging commit"):
        checker.inspect(directory, commit, pins, source)


@pytest.mark.parametrize("which", ["pins", "source"])
def test_external_manifest_tamper_is_rejected(directory, which):
    pins, source = materialize(directory)
    path = directory.parent / "context-pins.json" if which == "pins" else directory / "pins/source.json"
    with path.open("ab") as stream: stream.write(b" ")
    with pytest.raises(ValueError, match="external .* pin mismatch"):
        checker.inspect(directory, COMMIT, pins, source)


@pytest.mark.parametrize("delta", [{"source_commit": "0" * 40}, {"packaging_commit": "0" * 40},
                                   {"primary_scans": 1}])
def test_wrong_source_tuple_or_scan_claim_refuses(directory, delta):
    pins, source = materialize(directory, source_delta=delta)
    with pytest.raises(ValueError): checker.inspect(directory, COMMIT, pins, source)


@pytest.mark.parametrize("path", ["../escape.py", "/absolute.py", "product/../escape.py",
    "product\\eval\\oops.py", "C:/escape.py", "product/eval/auth.json", "product/eval/.env",
    "unapproved/file.py"])
def test_unsafe_manifest_paths_refused_before_target_read(directory, path):
    pins, source = materialize(directory, {path: {"bytes": 1, "sha256": "0" * 64}})
    with pytest.raises(ValueError): checker.inspect(directory, COMMIT, pins, source)


def test_corrupt_staged_byte_refuses(directory):
    data = b"mutated"
    (directory / "product").mkdir()
    (directory / "product/pyproject.toml").write_bytes(data)
    pins, source = materialize(directory, {"product/pyproject.toml": {"bytes": len(data), "sha256": "0" * 64}})
    with pytest.raises(ValueError, match="staged byte pin mismatch"):
        checker.inspect(directory, COMMIT, pins, source)


def test_missing_policy_declaration_refuses(directory):
    pins, source = materialize(directory)
    with pytest.raises(ValueError, match="approved policy differs"):
        checker.inspect(directory, COMMIT, pins, source)
