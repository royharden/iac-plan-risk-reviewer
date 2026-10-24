# Future consumed-heldout access controller

Source construction only, Dirty Mode OPEN. Nothing here has been imported or run;
no hidden input, oracle, grant, receipt, output, key or service has been accessed or
created. All seven arms remain NOT_MEASURED. This is separate from the coordinator,
which still rejects heldout. There is no automatic unblinding or experiment launch.

`eval.runner.benchmark_access.authorize_heldout_access` requires an actual shared
RunManifest and PreflightPins, a separate externally pinned HeldoutAuthorization,
an exact local bundle root and a fresh private/access-events log path. The caller
must create that log's parent directory later under separate explicit activation.
Flags or successful preflight alone cannot create permission.

The authorization's purpose is consumed_heldout_evaluation. It pins exact run,
edition, manifest, root, authority, seal, executed semantic suite, build, independent
inventory, prompt, rubric, all-seven-arm component/case bindings and persisted
exposure-artifact bytes. It names exact private synthetic case-input and scoring-only
oracle artifacts, case/raw identities, time interval, custodian/authorizer and
actual exposure measurement hashes per arm. Consumption committed before access
and no tuning are mandatory true fields. The external custodian must supply the
independent expected canonical authorization digest, not a submitted self-hash.
Hash agreement cannot authenticate identity, independence or permission origin.

Before any payload open, the controller calls actual D6 preflight (metadata-only),
then loads only its actual allowlisted authority/seal/exposure metadata and calls
actual validate_exposure. Preflight delegates to actual validate_seal,
validate_independence and validate_semantics. These enforce independent qualified
author/checker/custodian lineage, sealed disjoint family/configuration/mutation/raw
input partitions, raw-identity scenario cardinality/balance, frozen build/policy/
prompt/inventory and executed mandatory semantics. No detector/scanner-generated
labels, weakened inventory, derived raw hashes or producer repinning is introduced.
The additional controller gate requires consumed_holdout state and exactly seven
distinct durable-before-access exposure receipts, not merely receipts for whichever
arms happened to succeed. Frozen arm inventory binds actual invocation case sets
and actual version/config components. D invocations use kind rules, with a separate
primary source component, matching current actual D6 preflight.

The controller accepts ONLY already externally committed and persisted consumption
metadata. Actual custody validators attest metadata; no pre-access durable
consumption writer is exposed by those APIs. This implementation does not mint
one, infer consumption from preflight, or flip sealed state itself. The external
custodian must commit and separately pin the actual metadata before this API can
open anything. Existing ExposureReceipt.measurements_sha256 meanings are preserved:
the external permission must match each original value. Unknown/unavailable values
remain a source/admission gap, never invented input/request digests or fake future
measurement pins. D6 edition_release.prepare_consumed_edition is a post-completion
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
This source does not open a heldout route through coordinate or perform inference.
`deliver_oracle_to_scoring(scoring_sink)` is separate and explicit: it sends bytes
only to a trusted scoring callback, discards its return and never attaches oracle,
expected outcomes, split labels, scanner results or private maps to inference.
Callback identity/purpose is an external authorization obligation; Python callbacks
are trusted local code, not a security sandbox or authenticated role system.

Still deferred: external writer/authenticated custody identity and genuine grants,
actual complete sealed inventory/semantics/exposure, field/import/dependency joins,
filesystem locking/link/race/atomicity/crash/fsync effects, expiry/revocation races,
budget and provider/scanner behavior, real data separation and independent product
acceptance. The regression file is source only, using public artificial plumbing
bytes and incomplete metadata for refusal-order checks; it is not a hidden corpus,
valid seal, approval or evidence of execution.
