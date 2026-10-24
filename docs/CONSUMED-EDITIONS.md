# Local consumed-edition preparation

Source construction only; **runtime unverified**. No oracle, hidden input,
measurement payload or release artifact was opened or created during construction.
All seven arms D/L/P/M/C/C-custom/T remain **NOT MEASURED**. This is a future
explicit local preparation interface, not publication, a gold author or acceptance.

[edition_release.py](../eval/runner/edition_release.py) reuses the existing
[ReleaseAuthorization and AssemblySelection](../eval/runner/bundle.py),
[PreflightPins](../eval/runner/preflight.py) and existing custody, exposure and
eligibility records unchanged. A missing authorization is not repaired with a
Boolean, a self-generated receipt or synthetic replacement data.

The independent controller must separately freeze and supply seven CLI digest
arguments: selection, manifest, authority, semantic-suite, eligibility, release
and completion. Submitted metadata cannot authenticate its own approval. The
existing release authorization must appoint the custodian, identify the exact
consumed edition/manifest/exposure and permitted synthetic/secret-free artifacts,
and have a valid bounded interval. The selection pins the exact local source and
destination roots and byte/time bounds. No automatic unblinding follows from
preflight or a consumed state alone.

The narrow additional `CompletionReference` is externally pinned separately. Its
fields are schema_version (`2`), run_manifest_sha256, authority_sha256, seal_sha256,
input_exposure_authorization_sha256, input_exposure_commit_sha256,
input_exposure_receipt_file_sha256, post_measurement_exposure_sha256,
eligibility_sha256, rubric_sha256, row_inventory_sha256, row_inventory, arms and
consumed_at. Version 1 documents, with one ambiguous `exposure_sha256`, are refused
by the closed schema and never reinterpreted.

Two exposure events are bound separately (contract S1, see
[EXPOSURE-LEDGER.md](EXPOSURE-LEDGER.md)):

| Event | Record | Pin meaning | Completion fields |
|---|---|---|---|
| Pre-access input exposure | D6 journal `InputExposureCommit` / `InputExposureReceipt` (`m4-input-exposure-v1`) under `metadata/input-exposure*.json*` | per-arm declared measurement **intents**, frozen before any heldout input was read | `input_exposure_authorization_sha256`, `input_exposure_commit_sha256`, `input_exposure_receipt_file_sha256` |
| Post-measurement, pre-oracle exposure | legacy `custody.ExposureReceipt` list, manifest `exposure` artifact | `measurements_sha256` = actual measured-results file hash | `post_measurement_exposure_sha256` |

Each `ArmCompletion` binds arm, artifact_id,
artifact_sha256, score_status, score_result_sha256 and expected_rows. The complete
ordered row inventory contains case/resource/rule triples. Its digest uses ASCII
JSON, compact separators, with tuples represented as arrays. All seven rows point
to one exact unfiltered seven-arm scorer-result digest; arm measurement artifacts
are distinct. Hashes identify records, not actors or actual execution.

`prepare_consumed_edition(root, out, manifest, pins, selection,
expected_selection_sha256, authorization, expected_authorization_sha256,
completion, expected_completion_sha256)` performs these bounded stages:

1. Validate fresh disjoint local `gold/editions/<32 lowercase hex digits>` scope,
   exact selection and external completion pin. Require the entire consumed case
   inventory, all seven arms and genuine terminal invocation/eligibility coverage.
2. Run metadata-only preflight. Bind actual authority/seal/global build, policy,
   corpus, prompt/rubric, semantic and eligibility identities; require all seven
   post-measurement exposure receipts. The completion pins the exact post-measurement
   exposure artifact and seven actual measured artifacts separately. Require all seven
   distinct post-measurement arms first (ValueError otherwise). Then verify the
   committed pre-access input-exposure journal (metadata only, through the public
   `exposure_journal.verify_input_exposure_commit` seam) against the completion's
   three input-exposure pins and current custody: same run/edition/authority/seal/
   build/oracle/custodian and authorization policy/build, all seven arms, committed at or after the seal and no later
   than each arm's post-measurement exposure or completion. Intents are never treated
   as result hashes and results never as intents. Preserve both original pin sets.
   Reuse the separate release authorization before payload access.
3. Require exactly one approved input per consumed case hash, one exact pinned
   oracle artifact and seven exact approved measurement artifacts. Reject missing,
   extra or duplicate payload scope and bounds. No unused heldout input is read.
4. Read only approved measurement artifacts first. Each has the closed envelope
   `{"rows": [...ArmRow...], "score_result": ...existing score result...}`. Validate
   every original row against the frozen identities, raw-source/build pins and
   actual existing eligibility records. No detector or scorer is run and no labels
   are read to manufacture a favorable result. Missing/not_run/unmapped/mock rows
   refuse; genuine invalid/error/timeout, unknown outcomes and abstentions remain.
   A recorded failure, including a failed D exact gate, must retain `FAIL` status.
5. Only then read approved input/oracle bytes. Verify exact hashes and copy bytes
   unchanged; never scrub or derive labels. Finalize a fresh local candidate with
   `edition-state.json` COMPLETE last. A failure leaves ABORTED authoritative and
   attempts cleanup only of files created by this invocation.

The candidate contains hashed opaque input/expected filenames, exact approved
input/oracle bytes, full sealed lineage inventory, complete row inventory, and
bounded edition controls with every arm's counts/failed rows/predictions/unknowns,
all declared attempts and costs, original result/artifact pins and lineage pins.
`edition.json` is `schema_version` 2. It carries `input_exposure` (schema version,
authorization/commit/receipt-file pins, seven `intent_pins`) and
`post_measurement_exposure` (`artifact_sha256` of the legacy exposure artifact, seven `result_pins`) as separate
blocks. The v1 field `exposure_measurement_pins` is gone. `check_edition_receipt(value)`
is the pure reader gate, and the writer runs it on its own record before writing. It
also requires the exact `m4-input-exposure-v1` receipt schema and 64-lowercase-hex
values for every exposure pin. It refuses v1, unversioned and mixed records rather than
reading their pins as either intents or results.
It does not copy raw model prose, private maps, actor/assessor identity records,
credentials, arbitrary metadata files or original measurement envelopes. The
original unfiltered score results remain pinned in private custody; every failed
row is retained in candidate controls, without free-text reasons. Candidate
hashes do not prove synthetic origin or absence of secrets; external secret-free
synthetic approval remains necessary. Missing billing stays unknown, never zero.

For later authorized activation, from the outer shell, the explicit script is
[prepare_consumed_edition.py](../scripts/prepare_consumed_edition.py). Its required
options are `--root`, `--out` and `--selection-sha256`, `--manifest-sha256`,
`--authority-sha256`, `--semantic-suite-sha256`, `--eligibility-sha256`,
`--release-sha256`, `--completion-sha256`. The script itself reads only fixed controls under
`metadata/`: run-manifest.json, assembly-selection.json, release-authorization.json,
edition-completion.json. The library it calls additionally reads, as metadata only:
the preflight allowlisted metadata (authority, seal, semantic receipt, eligibility,
legacy post-measurement `exposure.json`) and the D6 input-exposure journal files
`metadata/input-exposure-commit.jsonl` and `metadata/input-exposure.json`. A present
legacy WIP journal (`metadata/exposure-commit.jsonl` or `.exposure-commit.lock`)
blocks release. Only after those gates does it read approved measurement, then
input/oracle payloads. There is no default destination, discovery, execute-arm,
oracle-generation, overwrite, scrub, push or publish option. A successful command
would return 0 for local preparation, even with retained score FAIL; refusal is 3.
No command or candidate has actually been executed/generated.

[Development regression source](../tests/eval/test_edition_release.py) checks
external-pin refusal before access, missing/mock/pending arms, eligibility/inventory
loss, inconsistent full-result pins and measured-failure distinctions, v1 completion
refusal, edition.json v2 intent/result separation, and input-exposure ordering and
custody binding. It has not
run and cannot satisfy real custody. Later activation must exercise independently
authorized complete records, exact byte copies, privacy/cost/failure retention,
deadline/expiry, filesystem races, partial writes and crash recovery. Cooperative
checks do not prove hard I/O interruption, crash durability or authorization.
