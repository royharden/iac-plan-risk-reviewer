# Frozen heldout seven-arm journey (SOURCE ONLY)

Dirty Mode OPEN. Nothing here has been imported, run or activated. No heldout corpus,
oracle, grant, exposure record, scanner binary, provider key or output exists or was
read. All seven arms (D, L, P, M, C, C-custom, T) remain **NOT_MEASURED**; every
result of this journey is `INCOMPLETE` until a separate scoring handoff.

## Entry point

`eval.runner.frozen_run.run_frozen(runtime, pins, *, expected_pins_sha256)` with an
owner-injected `FrozenRuntime` (actual root, BenchmarkConfig, RunManifest,
PreflightPins, v2 `HeldoutAuthorization`, D6 `ExposureCommitAuthorization`, frozen
execution authority, the one shared `AttemptJournal`, ProviderTransport, per-case
`ApprovedScanner` bindings and a fresh access-event log path) and external
`FrozenRunPins`. `scripts/run_frozen_benchmark.py` refuses bare flags: there is no
plugin loader, controller construction or key loader.

## Order of gates (each fails closed to a complete seven-arm NOT_RUN outcome)

1. **Selection pins** (`_selection`): exact metadata digests of pins, manifest,
   configuration, access permission, exposure authorization, execution authority,
   build (recomputed from source), prompt/rubric, arm inventory and external case
   records. Config must be `input_scope="heldout"`, `fake_only=false`,
   `synthetic_input_attested=false`; manifest heldout and `consumed_holdout` or
   `sealed` (S1.6, see below).
2. **Pre-access input exposure (contract S1, seam owner D6)**:
   `exposure_journal.verify_committed_exposure(...)` must return an
   `InputExposureCommit` (all permission flags false) whose commit pin, receipt-file
   pin and all seven `InputExposureReceipt.measurement_intents_sha256` rows equal the
   v2 permission. Intents are declared pre-access config/intent pins, never result
   hashes. This record is not payload, oracle or scoring permission.
3. **Independent input-access permission** (`authorize_heldout_access`, see
   `BENCHMARK-ACCESS.md`): re-verifies step 2 and custody/seal metadata, allowlists
   exactly one private input per case, opens a fresh access-event log. No oracle.
4. **Coordinator** `coordinate(..., execution_mode="frozen_heldout",
   _frozen_reader=GuardedCaseReader(...))`: the same single engine and journal as the
   synthetic route. Each case's raw bytes are opened once through the accessor and
   cached in memory; every later use rechecks permission and the byte pin. D uses
   `load_plan_bytes` (no source reopen). L/P/M keep the safe projection boundaries.
   The frozen route requires the distinct closed authority
   `m4-approved-frozen-heldout-benchmark-v1` (`heldout_frozen_only=true`,
   `access_authorization_sha256` = the v2 permission pin); the synthetic authority is
   refused for heldout and vice versa.
5. **Guarded heldout scanners (C, C-custom, T)**: per case, the approved scanner
   manifest must be heldout-scoped (`input_scope="heldout"`, `guarded_input=true`,
   no `plan_path`) and its runner must carry a `m4-local-scanner-heldout-grant-v1`
   grant bound to the same access permission. The driver receives
   `GuardedScannerInput` (bytes from `GuardedCaseReader.read`), stages them
   explicitly per arm into `<arm workspace>/guarded-input/<plan_sha256>.json` with
   exclusive create, scans with the unchanged single `BoundedSubprocessRunner`
   (fixed argv, timeouts, output caps) and removes the staged file; failed cleanup
   aborts. A missing/unscoped scanner is NOT_RUN/incomplete, never measured. See
   `scanner-activation.md`.
6. **Outcome**: private canonical outcome `m4-frozen-run-outcome-v1` (all statuses,
   journal snapshot, provenance, manifest candidate, rows, `oracle_opened=false`)
   and its SHA256; public summary `m4-frozen-run-summary-v1`, status-only.

## Amendment A2 / contract S1.6: input-access ordering

Preflight derives `consumed_holdout` only from the legacy post-measurement receipts,
so before measurement a legitimate run is `sealed`. Input access is therefore
admitted when EITHER (a) the manifest/preflight state is `consumed_holdout` (legacy),
OR (b) it is `sealed` AND preflight reports `input_exposure_committed=true`. In both
cases the access gate still requires the fully pinned `verify_committed_exposure`
`InputExposureCommit` (step 2). `eval/runner/preflight.py` reads the journal
read-only via D6's public `exposure_status` and reports `input_exposure_committed`;
it creates no new manifest state, never changes `edition_state`, and never satisfies
the legacy heldout eligibility/receipt checks. Path (b) is input permission only:
never oracle, scoring or tuning permission.

## Amendment A1 (M4-INT, 2026-10-23)

`eval/scanners/scoring_bridge.bridge_report` now accepts source `input_scope` in
{`development_synthetic`, `heldout`} only. A heldout source additionally requires the
externally pinned `eligibility` and `expected_eligibility_sha256`; otherwise it
raises. Development-synthetic behavior is unchanged.

## Heldout scanner admission (D4 assignment 2)

`eval/scanners/run_manifest.adapt_scanner_report` is now scope-aware. A
`development_synthetic` report keeps the dev split and refuses any heldout context.
A `heldout` report requires a `ScannerRunContext` carrying all of:
`edition_state` in {`sealed`, `consumed_holdout`}, the exact
`heldout_access_authorization_sha256` (v2 permission pin) and the exact
`heldout_scanner_manifest_json`. That manifest must satisfy the heldout-manifest
predicate for that pin and match the report's `manifest_sha256` and build. The context
also needs the externally pinned eligibility (A1), and heldout-split case bindings
only. Anything missing raises, and the coordinator records that as
`scanner_admission_incomplete` (NOT_RUN, original captures retained). The typed
metadata uses the heldout split and the given edition state.

The frozen coordinator passes this context automatically and takes the eligibility
only through the optional `coordinate(..., heldout_scanner_eligibility=(EligibilityManifest, pin))`,
which is refused outside frozen mode. `run_frozen` passes it through from the optional
`FrozenRuntime.heldout_scanner_eligibility = (EligibilityManifest, pin)` (D4 assignment 3).
The pair must be the exact typed record, `record_digest(manifest) == pin`, and the
config's edition. It is supplied externally and never derived from the run. It is not
part of `FrozenRunPins`, so existing selection digests stay valid. The outcome records
`heldout_scanner_eligibility_sha256`. When it's absent, the outcome lists
`heldout_scanner_eligibility_absent` and the scanner arms stay
`scanner_admission_incomplete`. Even when admitted,
the coordinator keeps scanner arm status `scanner_unadmitted_not_measured` with
alias placeholders. The scanner-local to public alias join still needs its own later
admission. Nothing here is a measurement.

## Heldout input layout (decision)

Heldout case inputs stay at `private/synthetic/inputs/<file>` inside the run bundle,
the case_input role prefix of the shared `eval/runner/bundle.PAYLOAD_PREFIXES`
(oracle `private/synthetic/oracle/`, measurements `private/synthetic/measurements/`).
The gate reads that constant instead of a second copy. "synthetic" in the path is a
legacy bundle namespace name, not a scope claim. Heldout identity comes only from the
manifest (`split="heldout"`, edition state) plus the v2 input-access permission and
D6's committed input exposure, never from a path. Renaming the namespace would change
`bundle.py`, edition release and existing archives. That would be a deliberate
versioned migration owned elsewhere, not a silent change.

## Scoring is separate

The legacy `custody.ExposureReceipt` (post-measurement, pre-oracle; its
`measurements_sha256` is the actual measured-results file hash) is produced only
after this run, by the scoring handoff, and is checked by `scripts/eval.py` before
the oracle is decoded. Nothing in this journey reads the oracle or writes that receipt.

## Deferred validation

Nothing ran: imports, pydantic schemas, the regression files
`tests/eval/test_frozen_run.py`, `test_frozen_run_boundaries.py` and
`test_benchmark_access.py`, file locking/fsync/exclusive-create on Windows/OneDrive,
scanner staging paths against real Checkov/Trivy argv, deadlines, crash behavior,
provider/scanner effects and cost accounting. Independent oracle custody, real
grants/eligibility and nonauthoring product acceptance remain required.
