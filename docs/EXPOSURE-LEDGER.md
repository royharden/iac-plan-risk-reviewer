# Metadata-only holdout exposure commit

`eval.runner.exposure_journal.commit_exposure(...)` creates one durable
all-seven-arm consumption commit before any heldout payload access. It reads the
run manifest and pinned custody/semantic/eligibility metadata through existing
preflight APIs only. It never opens case-input, oracle, outcome, prose, or
measurement payload files; it does not run any arm or authorize payload access.

The externally pinned `ExposureCommitAuthorization` is preserved in the commit
envelope and binds run/edition, the exact pre-access
manifest and local root pins, authority/seal/semantic/eligibility, policy/build,
inventory lineage, prompt/rubric, all-arm invocation inventory, custodian, and one
externally pinned per-arm measurement-intent reference. These intent references
are identities declared before access; they are not inferred from inputs or
requests, and are never substituted for future output/artifact hashes. Metadata
digests and actor fields do not authenticate an actual person.

The commit writes a bounded `prepared` event to
`metadata/exposure-commit.jsonl`, fsyncs and reads it back, creates the seven-row
`metadata/exposure.json` receipt list with exclusive create, fsyncs and reads it
back byte-for-byte, then appends and verifies the final `committed` event. The
receipt file hash is bound into the commit envelope. A kernel-released exclusive
lock prevents simultaneous writers. The journal is one-shot per run root; it has
no overwrite, unconsume, force-unlock, retry, or automatic recovery path.

Any torn, partial, conflicting, or ambiguous state reports BLOCKED and stays
consumed-or-blocked. `exposure_status(...)` is read-only and never repairs a
record. `verify_committed_exposure(...)` is the narrow metadata-only consumer seam
for D4: call it before any separate permission-gated input/oracle reader. A
successful commit result still returns `payload_permission_granted=false`; D4's
explicit input-versus-scoring-only authorization remains an independent gate.

The `scripts/record_exposure.py` record/status commands are source only. No
exposure record was created or read for this implementation. Runtime, locking,
crash durability, permissions, and consumer integration remain unverified.

The receipt `exposed_at` is the irreversible consumption-commit time; it does not claim that any arm ran or that any payload was read. `measurements_sha256` receives only the externally pinned pre-access intent/reference identity per arm. Future result and artifact hashes stay separate.
