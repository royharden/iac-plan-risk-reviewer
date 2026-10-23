# Attempt budget and operator journal

Dirty Mode source construction: **runtime unverified**. No ledger command, app
import or regression test was executed. Synthetic fixture prices are arithmetic
examples, not current provider prices or authority to spend.

`AttemptJournal` is the accounting authority. One local worker exclusively owns
its `.lock`. `start` checks total requests/input/output/USD and pinned token-price
exposure before appending and flushing a request reservation. `terminal` preserves
ok/invalid/error/cancelled/timeout attempts, measured duration, reported usage/cost
and a response hash without text. Failed attempts are not free or removed.

Missing usage or price/cost leaves a pending liability; known partial USD plus its
remaining reserved upper bound stays visible. Pending tokens conservatively retain
at least the reservation (or any higher reported usage). **Every timeout remains
pending even with complete usage/cost** until explicit receipt reconciliation.
Known reservation overruns also block new starts; a receipt does not silently raise
the original cap or clear a genuine overrun. Cost per success is undefined when
there are no successes or billing is unresolved.

Replaying an unmatched start retains its liability. A residual lock is never
assumed stale from its age/PID or automatically removed. This implementation offers
no force unlock, lock stealing, retry, provider operation or cloud access.
`reconcile` requires an explicit attempt, complete measured usage/known USD and a
SHA256 receipt identity. It appends a new event; original history is retained. A
receipt hash binds supplied evidence but does not authenticate provider billing.
Operators remain responsible for obtaining genuine receipts and confirming worker
ownership before recovery. A blocked residual lock requires a separate authorized
manual ownership recovery outside this interface, not a bypass flag.

The source contract regressions in `tests/attempts/test_budget_journal_contract.py`
cover each cap before append, worst-case price floor, failed/cancelled/timeout
accounting, partial liabilities, unmatched-start replay and explicit reconciliation,
known overruns, single-worker/residual-lock ownership, duplicate terminals and orphan
history. They are public synthetic examples; they are not hidden gold, observed
crashes, measured billing or executed durability/concurrency evidence.

## Explicit operator source interfaces

`AttemptJournal.snapshot(path)` reads an **existing** regular JSONL file through the
shared replay/summary logic without constructing a worker, creating a directory,
acquiring a lock or writing any file. It returns a digest-bound snapshot, numeric
accounting, pending/overrun flags and opaque per-attempt status. Price/provider/model
labels, prompts, responses and receipt text are not exported. Lock presence is as
observed, not a declaration that a worker is dead. `start_authorized` is always false;
status has no caller budget and cannot admit another request.

`AttemptJournal.operator_reconcile` requires the exact expected journal digest,
attempt, complete input/output token counts, known USD and receipt digest. It checks
the journal before and after acquiring normal exclusive ownership, and appends through
the existing `reconcile` method. Its temporary worker has zero request/token/USD caps
and cannot start requests; its placeholder price is never written into reservations
or substituted for historical prices. No cap or original event is overwritten.
The returned snapshot is taken while the operator lock is held; observed lock presence
describes that instant, and the owned lock is released on exit.

`ledger_cli.reconcile_file` additionally hashes an explicitly supplied separate
bounded regular receipt file and requires its expected digest before passing the
operation to the journal. It never parses, outputs or copies receipt contents.
This proves which bytes the operator supplied, not whether a provider actually
billed them or the asserted usage matches the receipt. No model/provider inference
fills missing accounting; operator assertions remain explicit and unauthenticated.

Standalone interfaces for **later authorized activation**, not commands run here:

```text
python scripts/ledger.py status EXISTING_JOURNAL.jsonl
python scripts/ledger.py reconcile EXISTING_JOURNAL.jsonl --expect-journal-sha256 JOURNAL_SHA256 --attempt ATTEMPT_ID --receipt RECEIPT_FILE --expect-receipt-sha256 RECEIPT_SHA256 --input-tokens 12 --output-tokens 7 --known-usd 0.001
```

There is no default mutation or force/unlock/retry flag. A missing status journal
fails without creating state. Stale journal/receipt pins, malformed accounting,
already reconciled attempts and any live/residual lock refuse reconciliation.
Success returns 0 for reading/recording only, not permission to spend or a statement
that all liabilities/overruns are clear. Error returns 3 with a fixed invariant code;
paths, receipt text and exception payloads are not logged. An overrun remains blocked
even after pending billing is reconciled. CLI `inspect`/`explain`/viewer behavior is
untouched; this is a separate script, not another product subcommand.

Replay is bounded to 16 MiB, 100,000 events and a cooperative 30-second JSON parse
budget, with shared strict JSON depth/string limits. Every generated event ends in
LF; a nonempty journal with no final LF is treated as torn/incomplete. Duplicate
keys, nonfinite values, extra payload fields and invalid event pairs are refused.
This strengthens generated-format parsing without changing normal worker method
signatures or timeout reconciliation semantics. Existing journals outside the
generated closed format need investigation; the operator tool does not repair them.

`tests/attempts/test_ledger_cli.py` adds regression **source** for read-only missing
status, hidden labels/receipt text, append-only explicit receipts, fully accounted
timeout reconciliation, stale pins, residual locks, strict/torn replay and required
arguments. No tests were imported or executed. Real execution, hostile filesystem
race isolation, crash/Windows durability and concurrency checks remain deferred.
