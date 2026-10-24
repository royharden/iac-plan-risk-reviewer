# Post-run scoring handoff (SOURCE ONLY)

Dirty Mode OPEN. Nothing here was imported or run. No oracle, gold label, heldout
input, measured result or receipt exists or was read. All arms remain NOT_MEASURED.

## Purpose (contract S1 item 4)

Two exposure events are kept separate:

1. **Pre-access input exposure** (D6 `InputExposureReceipt`, per-arm measurement
   *intents*) gates reading heldout inputs for the frozen run (`FROZEN-RUN.md`). It is
   never oracle or scoring permission.
2. **Post-measurement, pre-oracle exposure** (legacy `custody.ExposureReceipt`, meaning
   unchanged): `measurements_sha256` is the SHA256 of the ACTUAL measured-results file.
   `scripts/eval.py` checks it before decoding the oracle.

`eval/runner/scoring_handoff.py` bridges the two without reading the oracle.

## Steps

1. `prepare_handoff(outcome_json, expected_outcome_sha256=..., edition_id=...,
   input_commit=<InputExposureCommit>)`. It needs the exact frozen-run private outcome
   (`m4-frozen-run-outcome-v1`, `oracle_opened=false`), bound to the same committed
   input exposure. It refuses unless every case has all seven arms exactly once, so
   dropped arms can't shrink the denominator. It returns:
   - `ScoringHandoff` (`m4-scoring-handoff-v1`): immutable run-result pins, the full
     case x arm status inventory (including not_run/error/timeout/mock/unknown), the
     incomplete arms, missing items, the cumulative journal summary (not re-summed per
     invocation), `journal_sha256`, `reservation_overrun`, the count of interrupted or
     unreconciled attempts and `all_attempts_retained`. The per-attempt list itself
     stays in the pinned frozen outcome (`frozen_outcome_sha256`). Any lost snapshot,
     overrun or unresolved attempt marks every arm incomplete.
   - The measured-results bytes: every ArmRow from the outcome, strictly
     re-validated, as LF-terminated canonical JSONL with nothing filtered or added.
   Arms with any status other than `ok` are listed incomplete. A lost or unpinned
   journal snapshot, a reservation overrun, or any interrupted-unreconciled attempt
   marks all arms incomplete. v2 execution eligibility is external
   (`EXTERNAL_V2_ELIGIBILITY_REQUIRED`); without it, scoring stays incomplete.
2. `post_measurement_receipts(handoff, authority=..., seal=..., expected_authority_sha256=...,
   exposed_at=..., receipt_ids={arm: id})`: seven legacy receipts carrying the actual
   results hash. Receipt IDs come from the external custodian. They are validated by
   the existing `validate_exposure`.
3. `write_handoff(fresh_dir, handoff, measurements, receipts)`: writes
   `measurements.jsonl`, `scoring-handoff.json` and `exposure-receipts.json` once each
   (exclusive create, fsync, readback) into a directory that must not exist yet.
   Nothing is overwritten, repinned or removed. It returns the pins for step 4.
4. Separately authorized scoring: `scripts/eval.py --split heldout --measurements
   <measurements.jsonl> --exposure-receipts <exposure-receipts.json> --scoring-handoff
   <scoring-handoff.json> --scoring-handoff-sha256 <pin> ...` plus all existing custody,
   semantic, eligibility and utility pins. Heldout now refuses without the pinned
   handoff, and its build must equal the edition's frozen build. Before the oracle is
   decoded, `check_handoff_for_scoring` requires that the measurement hash, all seven
   receipts, the row count and the build all match. It also recomputes the arms that
   must stay incomplete and refuses a handoff whose list omits any of them. Every
   incomplete arm is forced to `INCOMPLETE`, and if D is incomplete then
   `deterministic_exact_gate` is false. `exposure.json` records `scoring_handoff_sha256`. There is
   no favorable-score gate, and no detector-derived gold is ever introduced. The
   existing order (exposure record durably written before any hidden read) is unchanged.

## Release cross-check (D6 `CompletionReference`)

When a release completion reference exists, pass `--completion-reference <file>
--completion-reference-sha256 <pin>` together (one without the other refuses). These
flags are only accepted with a heldout scoring handoff. Before the exposure record is
written or anything hidden is read, `check_completion_reference` verifies the pin
(`metadata_digest`). It then requires
`CompletionReference.input_exposure_commit_sha256 == ScoringHandoff.input_exposure_commit_sha256`,
so scoring and release must describe the same pre-access input exposure. The
completion type is D6-owned (`eval/runner/edition_release.py`) and is only read here.
The result records `completion_reference_check`.

## Not done / deferred

Nothing ran (imports, schemas, `tests/eval/test_scoring_handoff.py`, exclusive-create
or fsync on Windows/OneDrive, real outcome sizes). Legacy receipts are not written into
the bundle's `metadata/exposure.json`. Doing that is a custody/edition-release
decision (D6 NEXT reconciles release records). Independent oracle custody, external
v2 eligibility, real scoring and nonauthoring product acceptance remain required.
