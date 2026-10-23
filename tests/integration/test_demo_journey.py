"""Offline fake walkthrough regression SOURCE, not executed in Dirty Mode."""
import importlib.util
import json
from pathlib import Path
import socket
import subprocess

import pytest


@pytest.fixture
def demo_module():
    path = Path(__file__).resolve().parents[2] / "scripts" / "demo.py"
    spec = importlib.util.spec_from_file_location("offline_demo_source", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_explicit_fake_synthetic_flags_required_before_output(demo_module, tmp_path, capsys):
    out = tmp_path / "demo"
    assert demo_module.main(["--out", str(out)]) == 3
    assert not out.exists()
    assert "offline_demo_aborted" in capsys.readouterr().err


def test_offline_journey_same_finding_fallback_private_boundary_and_no_measurements(demo_module, tmp_path, monkeypatch):
    def denied(*_args, **_kwargs):
        raise AssertionError("demo attempted a real network/process effect")
    monkeypatch.setattr(socket, "create_connection", denied)
    monkeypatch.setattr(subprocess, "run", denied)
    monkeypatch.setattr(subprocess, "Popen", denied)
    out = tmp_path / "demo"
    result = demo_module.run_demo(out, fake=True, synthetic=True)
    assert json.loads((out / "demo-state.json").read_text())["state"] == "COMPLETE"
    assert len(result["cases"]) == 4
    assert set(result["measurements"].values()) == {"NOT MEASURED"}
    assert result["finite_selection"]["valid"]["accepted"] is True
    assert result["finite_selection"]["invalid_fallback"]["accepted"] is False
    assert result["finite_selection"]["invalid_fallback"]["source"] == "deterministic_fallback"
    assert result["finite_selection"]["valid"]["finding_id"] == result["finite_selection"]["invalid_fallback"]["finding_id"]
    assert result["finite_selection"]["rule_results_unchanged"] is True
    assert result["fake_accounting"]["requests"] == 2
    assert result["product_acceptance"] is False
    private = json.loads((out / "private-evidence.json").read_text())
    assert private["sensitive"] is True and private["source_digest_verified"] is True
    shared = (out / "public-ssh" / "shareable.json").read_text()
    assert "CANARY-ADDRESS-DO-NOT-SHARE" not in shared
    assert "PRIVATE demo directory" in (out / "index.html").read_text()


def test_existing_output_is_preserved(demo_module, tmp_path):
    out = tmp_path / "occupied"
    out.mkdir()
    sentinel = out / "existing.txt"
    sentinel.write_text("preserve", encoding="utf-8")
    with pytest.raises(ValueError):
        demo_module.run_demo(out, fake=True, synthetic=True)
    assert sentinel.read_text() == "preserve"
    assert list(out.iterdir()) == [sentinel]


def test_unbound_viewer_result_aborts_whole_demo(demo_module, tmp_path, monkeypatch):
    from iac_review import source_view
    monkeypatch.setattr(source_view, "verify_report", lambda *_args, **_kwargs: {"run_manifest_bound": False})
    out = tmp_path / "demo"
    with pytest.raises(ValueError, match="bound"):
        demo_module.run_demo(out, fake=True, synthetic=True)
    assert json.loads((out / "demo-state.json").read_text())["state"] == "ABORTED"
