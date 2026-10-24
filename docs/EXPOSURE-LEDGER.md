# Pre-access input-exposure journal (contract S1)

Status: source only, Dirty Mode construction, runtime unverified. Frozen type and
consumer signature below, 2026-10-23 (D6, run PB-M4-CLAUDE-INT-20261023).

## Two exposure events, two records

| Event | Record | Hash it carries | Written by |
|---|---|---|---|
| Pre-access input exposure, before any heldout case input is read; no results exist | `eval.runner.exposure_journal.InputExposureReceipt` (`schema_version="m4-input-exposure-v1"`) | `measurement_intents_sha256`: the externally declared per-arm measurement intent/config pin | this journal |
| Post-measurement, pre-oracle (scoring) exposure | legacy `eval.runner.custody.ExposureReceipt` (unchanged) | `measurements_sha256`: SHA256 of the actual measured-results file, checked by `scripts/eval.py` before the oracle is decoded | the scoring path (D4 NEXT), not this journal |

The journal never constructs a legacy `ExposureReceipt` and never writes an intent
into `measurements_sha256`. The two records live in different files:
`metadata/input-exposure.json` (this journal) versus the manifest's legacy
`exposure` metadata artifact (preflight/scoring).

## Frozen type

```python
class InputExposureReceipt(Record):          # strict, frozen, extra="forbid"
    schema_version: Literal["m4-input-exposure-v1"] = "m4-input-exposure-v1"
    event: Literal["pre_access_input_exposure"] = "pre_access_input_exposure"
    run_id: Identity
    edition_id: Identity
    authority_sha256: Digest
    seal_sha256: Digest
    build_sha256: Digest
    oracle_sha256: Digest
    arm: Literal["D", "L", "P", "M", "C", "C-custom", "T"]
    measurement_intents_sha256: Digest       # intent pin, never a result hash
    state: Literal["consumed_holdout"] = "consumed_holdout"
    custodian: Identity
    committed_at: AwareDatetime              # timezone-aware; same instant for all seven rows, >= seal.sealed_at
    durable_receipt_id: Identity             # unique per row
    committed_before_access_attested: Literal[True]

class InputExposureCommit(Record):
    schema_version: Literal["m4-input-exposure-commit-v1"]
    state: Literal["CONSUMED_HOLDOUT_INPUT"]
    commit_sha256: Digest                    # metadata_digest of the durable CommitEnvelope
    receipt_file_sha256: Digest              # SHA256 of metadata/input-exposure.json bytes
    authorization: ExposureCommitAuthorization
    receipts: tuple[InputExposureReceipt, ...]   # exactly seven, one per arm
    payload_permission_granted: Literal[False]
    oracle_permission_granted: Literal[False]
    scoring_permission_granted: Literal[False]
    authorship_authenticated: Literal[False]
    product_acceptance: Literal[False]
```

`ExposureCommitAuthorization` (schema_version 1) is unchanged: its
`measurement_intents_sha256: dict[arm, Digest]` (exactly the seven arms) is the
external pre-access intent declaration the receipts copy per arm.

## Consumer seam (D4)

```python
verify_committed_exposure(
    root: Path, manifest: RunManifest, pins: PreflightPins,
    authorization: ExposureCommitAuthorization, *,
    expected_authorization_sha256: str,
    expected_commit_sha256: str,
) -> InputExposureCommit
```

D4's input-access check (`HeldoutAuthorization`, `schema_version="m4-heldout-input-access-v2"`)
compares, for every arm,
`HeldoutAuthorization.measurement_intents_sha256[arm] == row.measurement_intents_sha256`,
plus `input_exposure_authorization_sha256 == metadata_digest(authorization)`,
`input_exposure_commit_sha256 == commit.commit_sha256` and
`input_exposure_receipt_file_sha256 == commit.receipt_file_sha256`. The v1 fields
`measurements_sha256`/`exposure_artifact_sha256` are retired there, not reinterpreted.
Raises `ValueError` on any mismatch, partial, torn, ambiguous or legacy-shaped journal.
A verified commit is consumption evidence only: it is never input, oracle or scoring
permission, and preflight/commit success is never payload permission.

## Durable sequence

`commit_exposure(root, manifest, pins, authorization, *, expected_authorization_sha256) -> InputExposureCommit`
validates the external authorization pin, run/edition/root/build/policy/intent pins and
a metadata-only preflight (manifest edition state `sealed`, zero payloads opened), then
under a kernel-released nonblocking exclusive lock:

1. appends a bounded `prepared` event (with the full `CommitEnvelope`) to
   `metadata/input-exposure-commit.jsonl`, fsyncs, reads back;
2. exclusively creates the seven-row `metadata/input-exposure.json`, fsyncs, reads back byte-for-byte;
3. appends the `committed` event and re-verifies the whole journal.

Exact replay with the same authorization returns the committed record. No overwrite,
unconsume, force-unlock, retry or automatic recovery path exists. Any torn, partial,
conflicting or legacy/unversioned state fails closed. `exposure_status(root, expected_authorization_sha256=None)`
is read-only and reports `UNCONSUMED`, `COMMITTED` or `BLOCKED`; a leftover lock file
alone (nothing written) is `UNCONSUMED`.

Paths from the earlier unaccepted WIP journal (`metadata/exposure-commit.jsonl`,
`metadata/.exposure-commit.lock`) are never silently ignored: their presence makes
status `BLOCKED` and commit refuse, because such a ledger copied intents into legacy
`measurements_sha256`. A pre-existing legacy `metadata/exposure.json` also makes
commit refuse: post-measurement exposure before pre-access commit means the edition
is already consumed or contaminated.

The `scripts/record_exposure.py` `record`/`status` commands are source only.

## Limitations and deferred validation

- No exposure record was created or read for this implementation. Runtime, locking,
  crash durability, Windows/POSIX lock semantics, permissions and consumer integration are unverified.
- Committing input exposure does not change the manifest's declared `edition_state`;
  preflight derives `consumed_holdout` only from legacy post-measurement receipts.
  The consumed-edition release (`eval/runner/edition_release.py`, `CompletionReference` v2,
  `edition.json` v2) binds both records as separately named fields; see `docs/CONSUMED-EDITIONS.md`.
  Input access is admitted from `sealed` plus a verified `InputExposureCommit` (INT decision S1.6, D4).
- Metadata digests and actor/custodian fields do not authenticate a person.
