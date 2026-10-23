"""F2: complete timeout usage must not silently clear operator reconciliation.

Regression source only; not executed during Dirty Mode.
"""
from decimal import Decimal

import pytest

from iac_review.attempts import AttemptJournal, Budget, JournalError, PriceIdentity, Reservation


def test_complete_timeout_stays_pending_across_replay_until_reconciled(tmp_path):
    budget = Budget(max_requests=3, max_input_tokens=100, max_output_tokens=100, max_usd=Decimal("5"))
    price = PriceIdentity(
        provider="synthetic", model="fake", price_id="synthetic-v1", price_date="2026-10-23",
        input_usd_per_million=Decimal("1"), output_usd_per_million=Decimal("1"),
    )
    reservation = Reservation(
        input_tokens_upper=10, output_tokens_upper=10, request_usd_upper=Decimal("1"),
        hashes={field: "a" * 64 for field in
                ("build", "corpus", "projection", "prompt", "input", "model", "config")},
    )
    path = tmp_path / "attempts.jsonl"
    with AttemptJournal(path, budget, price) as journal:
        attempt = journal.start(reservation)
        journal.terminal(attempt, "timeout", 50, input_tokens=2, output_tokens=3, known_usd=Decimal("0.25"))
        state = journal.summary()
        assert state["pending_attempt_ids"] == [attempt]
        assert state["known_usd"] == "0.25"
        assert state["unresolved_usd_upper"] == "0.75"
        assert state["input_tokens_with_unresolved_bounds"] == 10
        assert state["output_tokens_with_unresolved_bounds"] == 10
        assert state["billing_known"] is False
        with pytest.raises(JournalError, match="unresolved"):
            journal.start(reservation)
    with AttemptJournal(path, budget, price) as journal:
        assert journal.summary()["new_requests_blocked"] is True
        journal.reconcile(attempt, input_tokens=2, output_tokens=3,
                          known_usd=Decimal("0.25"), evidence_sha256="b" * 64)
        assert journal.summary()["pending_attempt_ids"] == []
        assert journal.summary()["billing_known"] is True
        assert journal.summary()["known_usd"] == "0.25"
        assert journal.start(reservation) != attempt
