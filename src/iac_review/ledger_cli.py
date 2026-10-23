"""Bounded local ledger status/operator reconciliation. No provider, retry or unlock."""
from __future__ import annotations

import argparse
from decimal import Decimal
from hashlib import sha256
import json
from pathlib import Path
import re
import sys
from typing import Sequence

from iac_review.attempts import AttemptJournal, JournalError
from iac_review.ingest import read_source_bytes

_CODES = {
    "journal_missing", "journal_truncated_line", "journal_event_limit", "journal_read_invalid",
    "journal_link_rejected", "journal_digest_invalid", "journal_digest_mismatch",
    "attempt_id_invalid", "receipt_digest_invalid", "receipt_digest_mismatch",
    "receipt_must_be_separate", "only unresolved liabilities may be reconciled",
}


def reconcile_file(
    journal: Path, *, expected_journal_sha256: str, attempt_id: str,
    receipt: Path, expected_receipt_sha256: str, input_tokens: int,
    output_tokens: int, known_usd: Decimal,
) -> dict:
    """Explicit receipt bytes are only hashed, never parsed, copied or output."""
    if not isinstance(expected_receipt_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_receipt_sha256):
        raise JournalError("receipt_digest_invalid")
    journal, receipt = Path(journal).absolute(), Path(receipt).absolute()
    if receipt in (journal, journal.with_suffix(journal.suffix + ".lock")):
        raise JournalError("receipt_must_be_separate")
    data = read_source_bytes(receipt)
    receipt_hash = sha256(data).hexdigest()
    if receipt_hash != expected_receipt_sha256:
        raise JournalError("receipt_digest_mismatch")
    return AttemptJournal.operator_reconcile(
        journal, expected_journal_sha256=expected_journal_sha256, attempt_id=attempt_id,
        input_tokens=input_tokens, output_tokens=output_tokens, known_usd=known_usd,
        evidence_sha256=receipt_hash)


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.exit(3, "ledger_aborted code=invalid_arguments\n")


def main(argv: Sequence[str] | None = None) -> int:
    parser = _Parser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    status = sub.add_parser("status", help="Read an existing bounded journal without acquiring a lock")
    status.add_argument("journal", type=Path)
    reconcile = sub.add_parser("reconcile", help="Append explicit operator receipt/accounting to one pending attempt")
    reconcile.add_argument("journal", type=Path)
    reconcile.add_argument("--expect-journal-sha256", required=True)
    reconcile.add_argument("--attempt", required=True)
    reconcile.add_argument("--receipt", type=Path, required=True)
    reconcile.add_argument("--expect-receipt-sha256", required=True)
    reconcile.add_argument("--input-tokens", type=int, required=True)
    reconcile.add_argument("--output-tokens", type=int, required=True)
    reconcile.add_argument("--known-usd", required=True)
    try:
        args = parser.parse_args(argv)
    except SystemExit as error:
        return 0 if error.code == 0 else 3
    try:
        if args.command == "status":
            result = AttemptJournal.snapshot(args.journal)
        else:
            result = reconcile_file(
                args.journal, expected_journal_sha256=args.expect_journal_sha256,
                attempt_id=args.attempt, receipt=args.receipt,
                expected_receipt_sha256=args.expect_receipt_sha256,
                input_tokens=args.input_tokens, output_tokens=args.output_tokens,
                known_usd=Decimal(args.known_usd))
        sys.stdout.write(json.dumps(result, sort_keys=True, allow_nan=False) + "\n")
        return 0
    except JournalError as error:
        value = str(error)
        code = value if value in _CODES and " " not in value else "journal_operation_refused"
        if value == "another worker or an unreconciled crash owns this journal":
            code = "journal_worker_or_crash_lock"
        sys.stderr.write(f"ledger_aborted code={code}\n")
    except KeyboardInterrupt:
        sys.stderr.write("ledger_aborted code=cancelled\n")
    except Exception:
        # Decoder, decimal and filesystem error strings may contain local data.
        sys.stderr.write("ledger_aborted code=invalid_journal_receipt_or_accounting\n")
    return 3
