"""Bounded default-path effect guards to execute only after authorized activation.

Synthetic local data only; these deny common Python network/process paths, not
every native effect. Source construction is not evidence that the guards pass.
"""
import hashlib
import json
import os
import socket
import subprocess
import urllib.request

from iac_review import cli, explain, rules


def test_default_inspect_never_calls_model_network_or_process_and_writes_only_bundle(
    core_change, core_plan_file, tmp_path, monkeypatch,
):
    entry = core_change(actions=("create",), after={"publicly_accessible": True, "storage_encrypted": True})
    source = core_plan_file([entry])
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    out = tmp_path / "bundle"
    before = {path.relative_to(tmp_path) for path in tmp_path.rglob("*")}

    def denied(*_args, **_kwargs):
        raise AssertionError("default inspect attempted a forbidden external effect")

    monkeypatch.setattr(socket, "socket", denied)
    monkeypatch.setattr(socket, "create_connection", denied)
    monkeypatch.setattr(urllib.request, "urlopen", denied)
    monkeypatch.setattr(subprocess, "Popen", denied)
    monkeypatch.setattr(subprocess, "run", denied)
    monkeypatch.setattr(os, "system", denied)
    monkeypatch.setattr(explain.FakeSelector, "select", denied)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "SYNTHETIC_UNUSED_CANARY")
    assert cli.main(["inspect", str(source), "--out", str(out)]) == 1
    assert hashlib.sha256(source.read_bytes()).hexdigest() == digest
    created = {path.relative_to(tmp_path) for path in tmp_path.rglob("*")} - before
    assert created == {out.relative_to(tmp_path)} | {
        (out / name).relative_to(tmp_path) for name in (
            "private.json", "private.html", "shareable.json", "shareable.html",
            "manifest.json", "manifest.sha256", "export-state.json",
        )
    }
    assert all("SYNTHETIC_UNUSED_CANARY" not in path.read_text(encoding="utf-8")
               for path in out.iterdir() if path.is_file())


def test_mutation_between_evaluation_and_reporting_aborts_without_export(
    core_change, core_plan_file, tmp_path, monkeypatch, capsys,
):
    path = core_plan_file([core_change(actions=("create",),
                                      after={"publicly_accessible": True, "storage_encrypted": True})])
    original_evaluate = rules.evaluate

    def mutate_after_evaluation(plan):
        rows = original_evaluate(plan)
        path.write_bytes(path.read_bytes() + b" ")
        return rows

    monkeypatch.setattr(rules, "evaluate", mutate_after_evaluation)
    out = tmp_path / "bundle"
    assert cli.main(["inspect", str(path), "--out", str(out)]) == 3
    assert "source_digest_changed" in capsys.readouterr().err
    assert not out.exists()


def test_offline_explain_accepts_only_shareable_projection_without_model_call(
    core_change, core_plan_file, tmp_path, monkeypatch, capsys,
):
    entry = core_change(actions=("create",), after={"publicly_accessible": True, "storage_encrypted": True})
    source = core_plan_file([entry])
    out = tmp_path / "bundle"
    assert cli.main(["inspect", str(source), "--out", str(out)]) == 1
    capsys.readouterr()
    shared = json.loads((out / "shareable.json").read_text())
    finding = next(row for row in shared["evaluations"] if row["rule_id"] == "R2")
    capsule = explain.build_capsule(shared, finding["finding_id"])
    selection = tmp_path / "selection.json"
    selection.write_text(explain.FakeSelector().select(capsule).model_dump_json(), encoding="utf-8")

    def no_implicit_selector(*_args, **_kwargs):
        raise AssertionError("offline explain attempted an implicit selector call")

    monkeypatch.setattr(explain.FakeSelector, "select", no_implicit_selector)
    arguments = ["--finding", finding["finding_id"], "--selection", str(selection)]
    assert cli.main(["explain", str(out / "shareable.json"), *arguments]) == 0
    assert json.loads(capsys.readouterr().out)["accepted"] is True
    assert cli.main(["explain", str(out / "private.json"), *arguments]) == 3
    assert "explanation_input_invalid" in capsys.readouterr().err
