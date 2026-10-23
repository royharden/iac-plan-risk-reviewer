"""Public synthetic accounting contract SOURCE; not executed during Dirty Mode."""
from decimal import Decimal
import json
from pathlib import Path

import pytest

from iac_review.attempts import AttemptJournal, Budget, JournalError, PriceIdentity, Reservation


def _budget(**changes) -> Budget:
    values = dict(max_requests=10, max_input_tokens=10_000, max_output_tokens=10_000,
                  max_usd=Decimal("0.10"))
    values.update(changes)
    return Budget(**values)


def _price() -> PriceIdentity:
    return PriceIdentity(provider="synthetic", model="contract-fake", price_id="synthetic-price-v1",
                         price_date="2026-10-23", input_usd_per_million=Decimal(1),
                         output_usd_per_million=Decimal(2))


def _reservation(**changes) -> Reservation:
    values = dict(input_tokens_upper=1000, output_tokens_upper=500,
                  request_usd_upper=Decimal("0.01"),
                  hashes={name: "a" * 64 for name in (
                      "build", "corpus", "projection", "prompt", "input", "model", "config")})
    values.update(changes)
    return Reservation(**values)


def _bytes(path: Path) -> bytes:
    return path.read_bytes() if path.exists() else b""


@pytest.mark.parametrize("caps", [
    {"max_requests": 0}, {"max_input_tokens": 999}, {"max_output_tokens": 499},
    {"max_usd": Decimal("0.009")},
])
def test_caps_reject_before_durable_start(tmp_path: Path, caps: dict) -> None:
    """Catches spending/reservation before request, token or USD cap admission."""
    path = tmp_path / "attempts.jsonl"
    with AttemptJournal(path, _budget(**caps), _price()) as journal:
        before = _bytes(path)
        with pytest.raises(JournalError):
            journal.start(_reservation())
        assert _bytes(path) == before and journal.summary()["requests"] == 0


def test_price_floor_rejects_underreserved_request(tmp_path: Path) -> None:
    """Catches accepting a reservation below the pinned worst-case token prices."""
    with AttemptJournal(tmp_path / "attempts.jsonl", _budget(), _price()) as journal:
        with pytest.raises(JournalError, match="below"):
            journal.start(_reservation(request_usd_upper=Decimal("0.001")))
        assert journal.summary()["requests"] == 0


@pytest.mark.parametrize("status", ["invalid", "error", "cancelled", "timeout"])
def test_all_failed_terminals_keep_usage_cost_and_timeout_liability(tmp_path: Path, status: str) -> None:
    """Catches failure charges disappearing or known-accounting timeout unblocking calls."""
    path = tmp_path / "attempts.jsonl"
    with AttemptJournal(path, _budget(), _price()) as journal:
        attempt = journal.start(_reservation())
        journal.terminal(attempt, status, 17, input_tokens=100, output_tokens=50,
                         known_usd=Decimal("0.003"), response_sha256="b" * 64)
        summary = journal.summary()
        assert summary["requests"] == 1 and summary["successful_attempts"] == 0
        assert Decimal(summary["known_usd"]) == Decimal("0.003")
        assert summary["billing_known"] is (status != "timeout")
        assert summary["new_requests_blocked"] is (status == "timeout")
        assert summary["cost_per_success_usd"] is None
        terminal = json.loads(path.read_text(encoding="utf-8").splitlines()[-1])
        assert terminal["status"] == status and terminal["input_tokens"] == 100


def test_partial_known_charge_retains_remaining_upper_and_blocks(tmp_path: Path) -> None:
    """Catches treating missing usage as zero or forgetting the rest of reserved exposure."""
    path = tmp_path / "attempts.jsonl"
    with AttemptJournal(path, _budget(), _price()) as journal:
        attempt = journal.start(_reservation())
        journal.terminal(attempt, "error", 10, input_tokens=200, known_usd=Decimal("0.004"))
        summary = journal.summary()
        assert Decimal(summary["known_usd"]) == Decimal("0.004")
        assert Decimal(summary["unresolved_usd_upper"]) == Decimal("0.006")
        assert summary["input_tokens_with_unresolved_bounds"] == 1000
        assert summary["output_tokens_with_unresolved_bounds"] == 500
        before = path.read_bytes()
        with pytest.raises(JournalError, match="unresolved"):
            journal.start(_reservation())
        assert path.read_bytes() == before


def test_unmatched_start_replays_pending_and_requires_explicit_receipt(tmp_path: Path) -> None:
    """Catches restart replay forgiving an interrupted call or automatic zero reconciliation."""
    path = tmp_path / "attempts.jsonl"
    with AttemptJournal(path, _budget(), _price()) as journal:
        attempt = journal.start(_reservation())
    with AttemptJournal(path, _budget(), _price()) as replay:
        assert replay.summary()["pending_attempt_ids"] == [attempt]
        with pytest.raises(JournalError):
            replay.start(_reservation())
        before = path.read_bytes()
        with pytest.raises(JournalError):
            replay.reconcile(attempt, input_tokens=100, output_tokens=20,
                             known_usd=Decimal("0.003"), evidence_sha256="not-a-receipt")
        assert path.read_bytes() == before
        replay.reconcile(attempt, input_tokens=100, output_tokens=20,
                         known_usd=Decimal("0.003"), evidence_sha256="c" * 64)
        assert replay.summary()["pending_attempt_ids"] == []
        assert Decimal(replay.summary()["known_usd"]) == Decimal("0.003")
        assert replay.start(_reservation()) != attempt


@pytest.mark.parametrize("usage", [
    {"input_tokens": 1001}, {"output_tokens": 501}, {"known_usd": Decimal("0.011")},
])
def test_known_overrun_is_not_clamped_or_allowed_to_start_again(tmp_path: Path, usage: dict) -> None:
    """Catches complete accounting above any reservation being treated as ordinary success."""
    path = tmp_path / "attempts.jsonl"
    with AttemptJournal(path, _budget(), _price()) as journal:
        attempt = journal.start(_reservation())
        values = dict(input_tokens=100, output_tokens=50, known_usd=Decimal("0.003"))
        values.update(usage)
        journal.terminal(attempt, "ok", 1, **values)
        assert journal.summary()["new_requests_blocked"] is True
        before = path.read_bytes()
        with pytest.raises(JournalError, match="overrun"):
            journal.start(_reservation())
        assert path.read_bytes() == before


def test_worker_ownership_and_residual_crash_lock_are_never_stolen(tmp_path: Path) -> None:
    """Catches concurrent ownership, implicit stale-lock deletion and lock replacement."""
    path = tmp_path / "attempts.jsonl"
    lock = path.with_suffix(".jsonl.lock")
    with AttemptJournal(path, _budget(), _price()):
        owner = lock.read_bytes()
        with pytest.raises(JournalError, match="another worker"):
            AttemptJournal(path, _budget(), _price())
        assert lock.read_bytes() == owner
    assert not lock.exists()
    lock.write_bytes(b"synthetic-unreconciled-crash")
    with pytest.raises(JournalError, match="another worker"):
        AttemptJournal(path, _budget(), _price())
    assert lock.read_bytes() == b"synthetic-unreconciled-crash"


def test_duplicate_terminals_and_orphan_replay_do_not_erase_history(tmp_path: Path) -> None:
    """Catches terminal duplication or accepting a terminal without its request start."""
    path = tmp_path / "attempts.jsonl"
    with AttemptJournal(path, _budget(), _price()) as journal:
        attempt = journal.start(_reservation())
        journal.terminal(attempt, "invalid", 1, input_tokens=1, output_tokens=1, known_usd=Decimal(0))
        before = path.read_bytes()
        with pytest.raises(JournalError):
            journal.terminal(attempt, "error", 2)
        assert path.read_bytes() == before
    orphan = tmp_path / "orphan.jsonl"
    orphan.write_bytes(path.read_bytes().splitlines(keepends=True)[-1])
    with pytest.raises(JournalError, match="without request start"):
        AttemptJournal(orphan, _budget(), _price())
