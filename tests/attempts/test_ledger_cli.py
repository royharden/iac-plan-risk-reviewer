"""Operator ledger regression SOURCE; no execution/import during Dirty Mode."""
from decimal import Decimal
from hashlib import sha256
import json
from pathlib import Path

import pytest

from iac_review.attempts import AttemptJournal, Budget, JournalError, PriceIdentity, Reservation
from iac_review.ledger_cli import main, reconcile_file

CANARY = "synthetic-private-marker"


def _seed(tmp_path: Path, *, timeout: bool = False) -> tuple[Path, str]:
    path = tmp_path / "attempts.jsonl"
    budget = Budget(max_requests=10, max_input_tokens=1000, max_output_tokens=1000, max_usd=Decimal(1))
    price = PriceIdentity(provider=CANARY, model="fake", price_id="mock-price", price_date="2026-10-23",
                          input_usd_per_million=Decimal(0), output_usd_per_million=Decimal(0))
    hashes = {name: "a" * 64 for name in ("build", "corpus", "projection", "prompt", "input", "model", "config")}
    with AttemptJournal(path, budget, price) as journal:
        attempt = journal.start(Reservation(input_tokens_upper=100, output_tokens_upper=100,
                                             request_usd_upper=Decimal("0.01"), hashes=hashes))
        if timeout:
            journal.terminal(attempt, "timeout", 12, input_tokens=2, output_tokens=1,
                             known_usd=Decimal("0.004"))
        else:
            journal.terminal(attempt, "error", 12, known_usd=Decimal("0.004"))
    return path, attempt


def _receipt(tmp_path: Path) -> tuple[Path, str]:
    receipt = tmp_path / "receipt.bin"
    receipt.write_bytes(("synthetic billing evidence " + CANARY).encode("utf-8"))
    return receipt, sha256(receipt.read_bytes()).hexdigest()


def test_missing_status_creates_no_journal_lock_or_directory(tmp_path: Path, capsys) -> None:
    """Catches status accidentally constructing a worker or creating missing state."""
    path = tmp_path / "missing-parent" / "missing.jsonl"
    before = set(tmp_path.iterdir())
    assert main(["status", str(path)]) == 3
    captured = capsys.readouterr()
    assert "journal_missing" in captured.err and not captured.out
    assert set(tmp_path.iterdir()) == before and not path.exists()


def test_status_preserves_bytes_and_hides_labels_receipts_payloads(tmp_path: Path, capsys) -> None:
    """Catches read-only status mutating history or exposing raw identity/receipt text."""
    path, attempt = _seed(tmp_path)
    before = path.read_bytes()
    names = set(tmp_path.iterdir())
    assert main(["status", str(path)]) == 0
    captured = capsys.readouterr()
    status = json.loads(captured.out)
    assert path.read_bytes() == before and set(tmp_path.iterdir()) == names
    assert CANARY not in captured.out and str(path) not in captured.out
    assert status["start_authorized"] is False and status["read_only"] is True
    assert status["summary"]["pending_attempt_ids"] == [attempt]
    assert Decimal(status["summary"]["known_usd"]) == Decimal("0.004")
    assert Decimal(status["summary"]["unresolved_usd_upper"]) == Decimal("0.006")


@pytest.mark.parametrize("timeout", [False, True])
def test_explicit_receipt_reconciliation_is_append_only_and_keeps_original_status(tmp_path: Path, timeout: bool) -> None:
    """Catches automatic receipt inference, history replacement or timeout relabeling as ok."""
    path, attempt = _seed(tmp_path, timeout=timeout)
    receipt, receipt_hash = _receipt(tmp_path)
    before = path.read_bytes()
    result = reconcile_file(
        path, expected_journal_sha256=sha256(before).hexdigest(), attempt_id=attempt,
        receipt=receipt, expected_receipt_sha256=receipt_hash,
        input_tokens=2, output_tokens=1, known_usd=Decimal("0.004"))
    assert path.read_bytes().startswith(before)
    assert len(path.read_bytes().splitlines()) == len(before.splitlines()) + 1
    assert result["operation"] == "reconciliation_recorded"
    assert result["snapshot"]["summary"]["pending_attempt_ids"] == []
    assert result["snapshot"]["attempts"][0]["status"] == ("timeout" if timeout else "error")
    assert result["snapshot"]["attempts"][0]["reconciled"] is True
    assert result["provider_billing_authenticated"] is False and result["start_authorized"] is False
    assert not path.with_suffix(".jsonl.lock").exists()
    assert CANARY not in json.dumps(result) and CANARY not in path.read_text(encoding="utf-8").splitlines()[-1]


@pytest.mark.parametrize("wrong", ["journal", "receipt"])
def test_stale_journal_or_wrong_receipt_pin_refuses_append(tmp_path: Path, wrong: str) -> None:
    """Catches reconciliation against a changed journal or an uninspected receipt."""
    path, attempt = _seed(tmp_path)
    receipt, receipt_hash = _receipt(tmp_path)
    before = path.read_bytes()
    with pytest.raises(JournalError, match="digest_mismatch"):
        reconcile_file(
            path, expected_journal_sha256="0" * 64 if wrong == "journal" else sha256(before).hexdigest(),
            attempt_id=attempt, receipt=receipt,
            expected_receipt_sha256="0" * 64 if wrong == "receipt" else receipt_hash,
            input_tokens=2, output_tokens=1, known_usd=Decimal("0.004"))
    assert path.read_bytes() == before and not path.with_suffix(".jsonl.lock").exists()


def test_status_never_steals_residual_lock_and_reconciliation_refuses_it(tmp_path: Path) -> None:
    """Catches implicit stale-lock recovery, even with a valid receipt and journal pin."""
    path, attempt = _seed(tmp_path)
    receipt, receipt_hash = _receipt(tmp_path)
    lock = path.with_suffix(".jsonl.lock")
    lock.write_bytes(b"operator-must-investigate-owner")
    before = path.read_bytes()
    status = AttemptJournal.snapshot(path)
    assert status["worker_lock_present"] is True
    with pytest.raises(JournalError, match="another worker"):
        reconcile_file(path, expected_journal_sha256=sha256(before).hexdigest(), attempt_id=attempt,
                       receipt=receipt, expected_receipt_sha256=receipt_hash,
                       input_tokens=2, output_tokens=1, known_usd=Decimal("0.004"))
    assert path.read_bytes() == before and lock.read_bytes() == b"operator-must-investigate-owner"


@pytest.mark.parametrize("damage", ["truncated", "duplicate-key", "extra-payload"])
def test_bounded_strict_replay_refuses_partial_or_secret_payload_records(tmp_path: Path, damage: str) -> None:
    """Catches forgiving a torn JSONL tail, duplicate keys or unsupported prompt payload fields."""
    path, _ = _seed(tmp_path)
    data = path.read_bytes()
    if damage == "truncated":
        data = data[:-1]
    elif damage == "duplicate-key":
        data = data.replace(b'"schema":1', b'"schema":1,"schema":1', 1)
    else:
        records = [json.loads(line) for line in data.splitlines()]
        records[0]["prompt"] = CANARY
        data = b"".join(json.dumps(row).encode("utf-8") + b"\n" for row in records)
    path.write_bytes(data)
    with pytest.raises(JournalError):
        AttemptJournal.snapshot(path)
    assert path.read_bytes() == data


def test_reconciliation_cannot_use_journal_as_receipt_or_infer_missing_fields(tmp_path: Path, capsys) -> None:
    """Catches self-receipting a ledger or defaulting missing accounting/receipt arguments."""
    path, attempt = _seed(tmp_path)
    before = path.read_bytes()
    with pytest.raises(JournalError, match="receipt_must_be_separate"):
        reconcile_file(path, expected_journal_sha256=sha256(before).hexdigest(), attempt_id=attempt,
                       receipt=path, expected_receipt_sha256=sha256(before).hexdigest(),
                       input_tokens=2, output_tokens=1, known_usd=Decimal("0.004"))
    assert main(["reconcile", str(path), "--attempt", attempt]) == 3
    captured = capsys.readouterr()
    assert not captured.out and "invalid_arguments" in captured.err
    assert path.read_bytes() == before and not path.with_suffix(".jsonl.lock").exists()
