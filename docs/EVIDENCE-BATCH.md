# Report evidence transaction

Report construction resolves its eligible evidence references through one
invocation-local `resolve_many` transaction. It passes the original report start
time plus `MAX_SECONDS` as an absolute monotonic deadline. The report's existing
entry and final source checks and its time budget remain in effect.

The evidence producer safely reopens, checks the pinned digest, and strictly
decodes the source at transaction entry. It checks all references against that
same freshly read snapshot using the standalone resolver's internal checker.
It then independently reopens and verifies the source digest at transaction exit.
No result tuple is returned before this closure. Persistent source mutation,
unreadable or link-replaced input, read-identity races, and expired deadlines
abort the transaction before evidence can be published.

This is an entry/exit observation boundary. A transient modification restored
entirely between those boundaries may go unobserved. It does not provide
continuous mutation monitoring or identical observation to per-fact reopening.
Every emitted fact still verifies against a freshly read snapshot with the exact
pinned input digest. Standalone `resolve(plan, ref)` retains its per-call reopen,
digest, and decode behavior. Neither path trusts `plan.raw` as verification data.

The consumer gathers references in evaluation order, decision references before
supporting references, preserving every eligible occurrence and duplicate ID.
References whose resource key or index contradict their evaluation keep the
existing mismatch/withholding behavior and are excluded from the transaction.
Batch results are consumed by position; count or reference-order mismatches abort
report construction. Fact IDs are never deduplication or association keys.

Existing rules for required decision facts, optional supporting facts,
unknown/sensitive markers, exact JSON types, masks, checked absence, and
object-summary privacy remain in force. Failed decision evidence withholds the
finding and its partial fact list. No process-wide, global, or path cache is
introduced, and no deadline, schema, source-profile inventory, or old report
bundle is migrated by this change.

Producer and consumer are separate delivery candidates. Runtime validation must
use their exact combined source and independent mutation, privacy, effect, and
performance regressions. A consumer-only import or mock is not proof of the
joined transaction behavior.
