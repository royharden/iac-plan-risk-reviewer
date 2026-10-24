"""Regression source for the durable all-arm PRE-ACCESS input-exposure commit (S1).

Authored, not run (Dirty Mode). Never executes a real commit or opens payloads.
"""
from __future__ import annotations

import ast
import inspect
import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from eval.runner.custody import ExposureReceipt
from eval.runner.scoring import ARMS
from eval.runner.exposure_journal import (
    INPUT_EXPOSURE_SCHEMA, InputExposureCommit, InputExposureReceipt,
    LEDGER_RELATIVE, LEGACY_WIP_RELATIVE, LOCK_RELATIVE, RECEIPTS_RELATIVE,
    _ledger_events, _parse_receipts, _receipt_bytes, _receipt_set_matches,
    exposure_status, verify_input_exposure_commit,
)

SOURCE = Path(__file__).parents[2] / "eval" / "runner" / "exposure_journal.py"
NOW = datetime(2026, 10, 23, tzinfo=timezone.utc)


def _intents():
    return {arm: f"{index:x}" * 64 for index, arm in enumerate(ARMS, start=1)}


def _receipts(intents=None):
    intents = intents or _intents()
    return tuple(InputExposureReceipt(
        run_id="run-1", edition_id="edition-1", authority_sha256="a" * 64,
        seal_sha256="b" * 64, build_sha256="c" * 64, oracle_sha256="d" * 64,
        arm=arm, measurement_intents_sha256=intents[arm], custodian="custodian-1",
        committed_at=NOW, durable_receipt_id=f"receipt-{index}",
        committed_before_access_attested=True)
        for index, arm in enumerate(ARMS))


def _envelope(receipts):
    auth = SimpleNamespace(measurement_intents_sha256=_intents(), custodian="custodian-1")
    return SimpleNamespace(receipts=receipts, authorization=auth, run_id="run-1",
        edition_id="edition-1", authority_sha256="a" * 64, seal_sha256="b" * 64,
        build_sha256="c" * 64, oracle_sha256="d" * 64)


def test_all_seven_receipts_roundtrip_and_partial_sets_reject():
    values = _receipts()
    parsed = _parse_receipts(_receipt_bytes(values))
    assert tuple(row.arm for row in parsed) == ARMS
    assert parsed == values
    assert all(row.schema_version == INPUT_EXPOSURE_SCHEMA for row in parsed)
    with pytest.raises(ValueError, match="all seven"):
        _parse_receipts(_receipt_bytes(values[:-1]))


def test_legacy_or_unversioned_receipt_rows_are_refused_not_reinterpreted():
    legacy = ExposureReceipt(
        edition_id="edition-1", authority_sha256="a" * 64, seal_sha256="b" * 64,
        build_sha256="c" * 64, oracle_sha256="d" * 64, measurements_sha256="e" * 64,
        arm="D", custodian="custodian-1", exposed_at=NOW,
        durable_receipt_id="legacy-0", durable_before_access_attested=True)
    rows = [row.model_dump(mode="json") for row in _receipts()]
    rows[0] = legacy.model_dump(mode="json")
    with pytest.raises(ValueError, match="legacy"):
        _parse_receipts((json.dumps(rows) + "\n").encode())
    rows = [row.model_dump(mode="json") for row in _receipts()]
    del rows[3]["schema_version"]
    with pytest.raises(ValueError, match="legacy"):
        _parse_receipts((json.dumps(rows) + "\n").encode())


def test_input_receipt_has_intents_not_result_field_and_strict_shape():
    fields = set(InputExposureReceipt.model_fields)
    assert "measurement_intents_sha256" in fields
    assert "measurements_sha256" not in fields
    row = _receipts()[0].model_dump(mode="json")
    with pytest.raises(ValidationError):
        InputExposureReceipt.model_validate_json(json.dumps({**row, "measurements_sha256": "e" * 64}))
    with pytest.raises(ValidationError):
        InputExposureReceipt.model_validate_json(json.dumps(
            {**row, "committed_before_access_attested": False}))
    with pytest.raises(ValidationError):
        InputExposureReceipt.model_validate_json(json.dumps({**row, "schema_version": 1}))
    with pytest.raises(ValidationError):
        InputExposureReceipt.model_validate_json(json.dumps(
            {**row, "committed_at": "2026-10-23T00:00:00"}))


def test_commit_result_never_grants_permission():
    for name in ("payload_permission_granted", "oracle_permission_granted",
                 "scoring_permission_granted", "authorship_authenticated",
                 "product_acceptance"):
        assert InputExposureCommit.model_fields[name].default is False


def test_torn_or_ambiguous_journal_is_never_reusable():
    with pytest.raises(ValueError, match="torn"):
        _ledger_events(b'{"event":"prepared"}')
    with pytest.raises(ValueError, match="event count"):
        _ledger_events(b'{"event":"prepared"}\n{"event":"committed"}\n{"event":"again"}\n')
    with pytest.raises(ValueError, match="duplicate"):
        _ledger_events(b'{"event":"prepared","event":"committed"}\n')


def test_duplicate_identity_cross_binding_and_intent_mismatch_reject():
    rows = list(_receipts())
    rows[1] = rows[1].model_copy(update={"durable_receipt_id": rows[0].durable_receipt_id})
    with pytest.raises(ValueError, match="incomplete or duplicated"):
        _parse_receipts(_receipt_bytes(tuple(rows)))
    good = _receipts()
    envelope = _envelope(good)
    assert _receipt_set_matches(envelope)
    for update in ({"edition_id": "other-edition"}, {"run_id": "other-run"},
                   {"custodian": "other-custodian"},
                   {"measurement_intents_sha256": "f" * 64},
                   {"committed_at": datetime(2026, 10, 24, tzinfo=timezone.utc)}):
        envelope.receipts = (good[0].model_copy(update=update), *good[1:])
        assert not _receipt_set_matches(envelope), update


def test_status_lock_alone_is_unconsumed_and_torn_commit_is_blocked(tmp_path):
    (tmp_path / "metadata").mkdir()
    assert exposure_status(tmp_path).state == "UNCONSUMED"
    (tmp_path / LOCK_RELATIVE).write_bytes(b"\0")
    assert exposure_status(tmp_path).state == "UNCONSUMED"
    (tmp_path / LEDGER_RELATIVE).write_bytes(b'{"event":"prepared"}')
    assert exposure_status(tmp_path).state == "BLOCKED"
    (tmp_path / LEDGER_RELATIVE).unlink()
    (tmp_path / RECEIPTS_RELATIVE).write_bytes(_receipt_bytes(_receipts()))
    assert exposure_status(tmp_path).state == "BLOCKED"


@pytest.mark.parametrize("legacy", LEGACY_WIP_RELATIVE)
def test_legacy_wip_journal_paths_block_status_never_ignored(tmp_path, legacy):
    (tmp_path / "metadata").mkdir()
    (tmp_path / legacy).write_bytes(b"\0")
    status = exposure_status(tmp_path)
    assert status.state == "BLOCKED"
    assert status.reason_code == "legacy_wip_exposure_journal_present"


def test_commit_refuses_legacy_wip_and_preexisting_post_measurement_exposure():
    module = ast.parse(SOURCE.read_text(encoding="utf-8"))
    commit = next(node for node in module.body
                  if isinstance(node, ast.FunctionDef) and node.name == "commit_exposure")
    names = {node.id for node in ast.walk(commit) if isinstance(node, ast.Name)}
    assert {"LEGACY_WIP_RELATIVE", "POST_MEASUREMENT_RELATIVE"} <= names


def test_public_journal_seam_signature_is_keyword_only_and_returns_commit():
    signature = inspect.signature(verify_input_exposure_commit)
    params = signature.parameters
    assert list(params) == ["root", "expected_authorization_sha256", "expected_commit_sha256"]
    assert params["expected_authorization_sha256"].kind is inspect.Parameter.KEYWORD_ONLY
    assert params["expected_commit_sha256"].kind is inspect.Parameter.KEYWORD_ONLY
    assert params["expected_commit_sha256"].default is None


def test_public_journal_seam_fails_closed_with_value_error(tmp_path):
    (tmp_path / "metadata").mkdir()
    with pytest.raises(ValueError):  # absent journal
        verify_input_exposure_commit(tmp_path, expected_authorization_sha256="a" * 64)
    (tmp_path / LEDGER_RELATIVE).write_bytes(b'{"event":"prepared"}')
    with pytest.raises(ValueError, match="torn"):
        verify_input_exposure_commit(tmp_path, expected_authorization_sha256="a" * 64)
    (tmp_path / LEGACY_WIP_RELATIVE[0]).write_bytes(b"\0")
    with pytest.raises(ValueError, match="legacy WIP"):
        verify_input_exposure_commit(tmp_path, expected_authorization_sha256="a" * 64)
    # Deep nesting within the byte cap surfaces as ValueError, never RecursionError.
    (tmp_path / LEGACY_WIP_RELATIVE[0]).unlink()
    (tmp_path / LEDGER_RELATIVE).write_bytes(b"[" * 100000 + b"]" * 100000 + b"\n")
    with pytest.raises(ValueError):
        verify_input_exposure_commit(tmp_path, expected_authorization_sha256="a" * 64)


def test_journal_files_are_distinct_from_legacy_exposure_artifact():
    assert RECEIPTS_RELATIVE.name == "input-exposure.json"
    assert LEDGER_RELATIVE.name == "input-exposure-commit.jsonl"
    assert RECEIPTS_RELATIVE.name != "exposure.json"


def test_source_orders_durable_commit_before_return_and_status_is_read_only():
    module = ast.parse(SOURCE.read_text(encoding="utf-8"))
    functions = {node.name: node for node in module.body
                 if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
    commit = functions["commit_exposure"]
    calls = sorted((node.lineno, node.func.id) for node in ast.walk(commit)
                   if isinstance(node, ast.Call) and isinstance(node.func, ast.Name))
    lines = {name: [line for line, called in calls if called == name]
             for name in ("_authorize", "_append_durable", "_write_exclusive_durable",
                          "_verify_committed")}
    assert lines["_authorize"][0] < lines["_append_durable"][0]
    assert lines["_append_durable"][0] < lines["_write_exclusive_durable"][0]
    assert lines["_write_exclusive_durable"][0] < lines["_append_durable"][1]
    assert lines["_append_durable"][1] < lines["_verify_committed"][-1]
    status = functions["exposure_status"]
    status_calls = {node.func.id for node in ast.walk(status)
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
    assert not ({"_append_durable", "_write_exclusive_durable", "_exclusive_lock"} & status_calls)
    text = SOURCE.read_text(encoding="utf-8")
    assert "LK_NBLCK" in text and "LOCK_NB" in text and "fsync" in text


def test_journal_never_constructs_legacy_exposure_receipt():
    module = ast.parse(SOURCE.read_text(encoding="utf-8"))
    constructed = {node.func.id for node in ast.walk(module)
                   if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
    imported = {alias.name for node in ast.walk(module) if isinstance(node, ast.ImportFrom)
                for alias in node.names}
    assert "ExposureReceipt" not in constructed
    assert "ExposureReceipt" not in imported
    assert "measurements_sha256=" not in SOURCE.read_text(encoding="utf-8")
