"""Public fixture integrity and policy journey; no acceptance-oracle access."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from evals import run_public


def test_public_policy_matrix_has_four_rules_and_no_failures():
    """what_bug_this_catches: public rule boundaries or privacy regress while aggregate status still looks green."""
    result = run_public.run()
    assert result["total"] == 24
    assert {r["rule_id"] for r in result["cases"]} == {"R1", "R2", "R3", "R4"}
    assert result["failed"] == 0, result["cases"]
    assert result["passed"] == 24
    assert result["product_acceptance"] is False
    assert result["hidden_evaluation"] == "NOT RUN"
    assert result["model_scanner_comparison"] == "NOT MEASURED"


def copied(tmp_path, monkeypatch):
    root = Path(run_public.ROOT)
    for name in ("fixtures/scenarios/dev", "fixtures/expected/dev"):
        shutil.copytree(root / name, tmp_path / name)
    monkeypatch.setattr(run_public, "ROOT", tmp_path)
    path = tmp_path / "fixtures/expected/dev/rv2-policy-v1.json"
    return path, json.loads(path.read_bytes())


def test_changed_public_input_is_refused(tmp_path, monkeypatch):
    """what_bug_this_catches: mutated case bytes are evaluated under stale input provenance."""
    _, inventory = copied(tmp_path, monkeypatch)
    path = tmp_path / inventory["cases"][0]["path"]
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(ValueError, match="digest"):
        run_public.run()


@pytest.mark.parametrize("change", [{"split": "heldout"}, {"path": "../private.json"}])
def test_dev_runner_refuses_split_or_path_escape(tmp_path, monkeypatch, change):
    """what_bug_this_catches: dev CI is redirected into private data by a changed inventory row."""
    path, inventory = copied(tmp_path, monkeypatch)
    inventory["cases"][0].update(change)
    path.write_text(json.dumps(inventory), encoding="utf-8")
    with pytest.raises(ValueError, match="fixed public"):
        run_public.run()
