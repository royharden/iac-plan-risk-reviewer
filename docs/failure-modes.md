# Core failure boundaries

Source repairs and focused regression-test source exist for the cases below.
Dirty Mode has not executed these tests or established runtime correctness.

| Failure | Intended behavior | Regression source |
|---|---|---|
| A finding cites another resource's key or index | Reject before resolving; foreign decision evidence withholds the outcome and forces exit 2; foreign optional evidence is omitted | `tests/report/test_resource_binding.py` |
| Timeout supplies apparently complete usage and cost | Preserve pending liability and known costs/reservation bounds; block new attempts until explicit receipt-backed reconciliation, including after replay | `tests/attempts/test_timeout_reconciliation.py` |
| Deadline expires during rendering or publication fails | Keep `export-state.json` ABORTED and roll back this invocation's report files | `tests/report/test_export_finalization.py` |
| Finalization fails | Keep ABORTED, remove created report artifacts where filesystem cleanup succeeds | `tests/report/test_export_finalization.py` |
| CLI checks time after successful publication | Writer owns the last deadline check; CLI returns the finalized report code rather than relabeling it as aborted | `tests/integration/test_cli_export_boundary.py` |

The writer retains `write_report(report, out)` compatibility. CLI adds the optional
absolute monotonic `deadline` keyword to cover the entire review. A caller without
that keyword gets an export-only budget. Output remains at the original directory
paths; `export-state.json` is additional local lifecycle metadata, not a benchmark
measurement. Verify COMPLETE before using or sharing exported reports. Share only
the shareable JSON/HTML, after verifying that local marker; private files and
manifest stay sensitive.

Publication is staged, with COMPLETE written atomically to the marker after all
artifacts and the final cooperative deadline check. ABORTED is installed before
rendering. Exceptions remove only this invocation's created artifact paths.
Process termination or filesystem refusal can leave residual artifacts, but the
ABORTED marker remains authoritative. No code can promise cleanup when the
filesystem rejects it; do not treat those remnants as a completed invocation.
Crash durability, races and platform-specific I/O behavior remain deferred.

Journal start/terminal/reconcile signatures are unchanged. A timeout's known
amount is retained without being counted twice; unresolved USD exposure is at
least the reservation remainder and token accounting retains conservative bounds.
Reconciliation supplies actual usage/cost and a receipt hash; it does not make a
timed-out model response successful or erase the attempt's terminal history.
