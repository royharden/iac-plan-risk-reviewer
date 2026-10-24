"""Regression source for durable all-arm metadata commit; never executes a commit."""
from __future__ import annotations

import ast
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from eval.runner.custody import ExposureReceipt
from eval.runner.scoring import ARMS
from eval.runner.exposure_journal import (
    _ledger_events, _parse_receipts, _receipt_bytes, _receipt_set_matches,
    exposure_status,
)


def _receipts():
    now = datetime(2026, 10, 23, tzinfo=timezone.utc)
    return tuple(ExposureReceipt(
        edition_id="edition-1", authority_sha256="a" * 64, seal_sha256="b" * 64,
        build_sha256="c" * 64, oracle_sha256="d" * 64, measurements_sha256="e" * 64,
        arm=arm, custodian="custodian-1", exposed_at=now,
        durable_receipt_id=f"receipt-{index}", durable_before_access_attested=True)
        for index, arm in enumerate(ARMS))


def test_all_seven_receipts_roundtrip_and_partial_sets_reject():
    values = _receipts()
    assert tuple(row.arm for row in _parse_receipts(_receipt_bytes(values))) == ARMS
    with pytest.raises(ValueError, match="all seven"):
        _parse_receipts(_receipt_bytes(values[:-1]))


def test_torn_or_ambiguous_journal_is_never_reusable():
    with pytest.raises(ValueError, match="torn"):
        _ledger_events(b'{"event":"prepared"}')
    with pytest.raises(ValueError, match="event count"):
        _ledger_events(b'{"event":"prepared"}\n{"event":"committed"}\n{"event":"again"}\n')


def test_duplicate_receipt_identity_and_cross_edition_binding_reject():
    rows = list(_receipts())
    rows[1] = rows[1].model_copy(update={"durable_receipt_id": rows[0].durable_receipt_id})
    with pytest.raises(ValueError, match="incomplete or duplicated"):
        _parse_receipts(_receipt_bytes(tuple(rows)))
    good = _receipts()
    auth = SimpleNamespace(measurement_intents_sha256={row.arm: row.measurements_sha256 for row in good})
    envelope = SimpleNamespace(receipts=good, authorization=auth, edition_id="edition-1",
        authority_sha256="a" * 64, seal_sha256="b" * 64, build_sha256="c" * 64,
        oracle_sha256="d" * 64)
    assert _receipt_set_matches(envelope)
    envelope.receipts = (good[0].model_copy(update={"edition_id": "other-edition"}), *good[1:])
    assert not _receipt_set_matches(envelope)


def test_status_reports_stale_lock_and_torn_commit_as_blocked(tmp_path):
    metadata = tmp_path / "metadata"
    metadata.mkdir()
    assert exposure_status(tmp_path).state == "UNCONSUMED"
    (metadata / ".exposure-commit.lock").write_bytes(b"\0")
    assert exposure_status(tmp_path).state == "BLOCKED"
    (metadata / ".exposure-commit.lock").unlink()
    (metadata / "exposure-commit.jsonl").write_bytes(b'{"event":"prepared"}')
    assert exposure_status(tmp_path).state == "BLOCKED"


def test_source_orders_durable_commit_before_return_and_status_is_read_only():
    path = Path(__file__).parents[2] / "eval" / "runner" / "exposure_journal.py"
    module = ast.parse(path.read_text(encoding="utf-8"))
    functions = {node.name: node for node in module.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
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
    assert not ({"_append_durable", "_write_exclusive_durable"} & status_calls)
    assert "LK_NBLCK" in path.read_text(encoding="utf-8")
    assert "LOCK_NB" in path.read_text(encoding="utf-8")
    assert "fsync" in path.read_text(encoding="utf-8")


def test_source_does_not_claim_payload_permission_or_executed_arms():
    result = Path(__file__).parents[2] / "eval" / "runner" / "exposure_journal.py"
    source = result.read_text(encoding="utf-8")
    assert 'payload_permission_granted: Literal[False]' in source
    assert '"state": "CONSUMED_HOLDOUT"' in source
    assert "measurement_intents_sha256" in source
