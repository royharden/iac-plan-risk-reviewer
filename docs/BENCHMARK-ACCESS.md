# Future consumed-heldout access controller

Source construction only, Dirty Mode OPEN. Nothing here has been imported or run;
no hidden input, oracle, grant, receipt, output, key or service has been accessed or
created. All seven arms remain NOT_MEASURED. The coordinator rejects heldout except
through the explicit frozen journey (`docs/FROZEN-RUN.md`). There is no automatic
unblinding or experiment launch.

`eval.runner.benchmark_access.authorize_heldout_access` requires an actual shared
RunManifest and PreflightPins, a separate externally pinned HeldoutAuthorization,
an exact local bundle root and a fresh private/access-events log path. The caller
must create that log's parent directory later under separate explicit activation.
Flags or successful preflight alone cannot create permission.

The authorization (`schema_version="m4-heldout-input-access-v2"`, contract S1) has
purpose consumed_heldout_evaluation. It pins exact run, edition, manifest, root,
authority, seal, executed semantic suite, build, independent inventory, prompt,
rubric, all-seven-arm component/case bindings, and D6's committed pre-access input
exposure: `input_exposure_authorization_sha256`, `input_exposure_commit_sha256`,
`input_exposure_receipt_file_sha256` and per-arm `measurement_intents_sha256`
(declared intent/config pins, never result hashes). It names exact private case-INPUT
artifacts only (one per case), case/raw identities, time interval and
custodian/authorizer. It never names the oracle. Consumption committed before access
and no tuning are mandatory true fields. Version 1 documents (integer schema,
legacy `measurements_sha256`/`exposure_artifact_sha256`, oracle rows) are refused by
the closed schema, never reinterpreted. The external custodian must supply the
independent expected canonical authorization digest, not a submitted self-hash.
Hash agreement cannot authenticate identity, independence or permission origin.

Before any payload open, the controller checks the permission and the exact
`ExposureCommitAuthorization` pin, calls actual D6 preflight (metadata-only), then
D6's `exposure_journal.verify_committed_exposure(...)`, requiring an
`InputExposureCommit` whose commit/receipt-file pins and all seven
`InputExposureReceipt.measurement_intents_sha256` rows equal the permission, with
every permission flag false. It then loads only allowlisted authority/seal metadata
and calls actual validate_seal. Preflight delegates to actual validate_seal,
validate_independence and validate_semantics. These enforce independent qualified
author/checker/custodian lineage, sealed disjoint family/configuration/mutation/raw
input partitions, raw-identity scenario cardinality/balance, frozen build/policy/
prompt/inventory and executed mandatory semantics. No detector/scanner-generated
labels, weakened inventory, derived raw hashes or producer repinning is introduced.
The additional controller gate requires consumed_holdout state, or (contract S1.6)
sealed state with preflight `input_exposure_committed=true`, and exactly seven
distinct committed pre-access input-exposure receipts, not merely receipts for whichever
arms happened to succeed. Frozen arm inventory binds actual invocation case sets
and actual version/config components. D invocations use kind rules, with a separate
primary source component, matching current actual D6 preflight.

The controller accepts ONLY an already committed input-exposure record. The writer
is now D6's `eval/runner/exposure_journal.commit_exposure` (see
`docs/EXPOSURE-LEDGER.md`; files `metadata/input-exposure.json` and
`metadata/input-exposure-commit.jsonl`). This controller never calls the writer,
infers consumption from preflight, or flips sealed state itself; the external
custodian commits and separately pins the record before this API can open anything.
Two distinct events are kept apart (S1): the pre-access input exposure (intents,
D6 `InputExposureReceipt`) gates inputs here; the legacy post-measurement
`custody.ExposureReceipt.measurements_sha256` keeps its exact meaning (actual
measured-results file hash) and is used only by the separate scoring handoff.
Unknown/unavailable values remain a source/admission gap, never invented
input/request digests or fake future measurement pins. D6 edition_release.prepare_consumed_edition is a post-completion
release tool, and ReleaseAuthorization has private_reproducibility_only purpose;
neither is repurposed as fresh inference authorization here.

The authorized accessor is local and single-use per artifact. Every access repeats
all metadata/permission gates, checks time, writes and fsyncs a payload-free pending
event, validates exact path/bound/hash and repeats metadata gates before returning
bytes. Any mismatch or permission failure halts further access with explicit
not_run/access_incomplete; a log-write failure stops access and is surfaced rather
than claiming a durable denial. The fresh access log cannot overwrite an existing
journal/evidence path. Existing model/scanner attempts, partial failures, costs and
unknown liabilities are never modified, reset, hidden or reconciled. Local event
logging is not an external consumption receipt or a proof of truthful access.

`read_case_input(case_id)` returns only exact authorized raw input for a local
parser. It is not a provider Request and must never be passed directly to inference.
Any future separately approved heldout orchestrator must retain the existing safe
L/P capsule and M raw-safe projection boundaries and one global budget journal.
The only heldout route through coordinate is the fixed frozen journey in
`docs/FROZEN-RUN.md`, via `GuardedCaseReader`. `deliver_oracle_to_scoring` now
always refuses (`input_access_is_not_oracle_permission`): input permission is never
oracle or scoring permission (S1 item 4). Scoring-only oracle access is a separate,
separately authorized post-measurement path.

Still deferred: authenticated custody identity and genuine grants,
actual complete sealed inventory/semantics/exposure, field/import/dependency joins,
filesystem locking/link/race/atomicity/crash/fsync effects, expiry/revocation races,
budget and provider/scanner behavior, real data separation and independent product
acceptance. The regression file is source only, using public artificial plumbing
bytes and incomplete metadata for refusal-order checks; it is not a hidden corpus,
valid seal, approval or evidence of execution.
