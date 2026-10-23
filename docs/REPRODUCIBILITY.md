# Reproducible bundle metadata source

Dirty Mode construction: the manifest, preflight CLI and regression cases are
SOURCE ONLY. No bundle, schema export, oracle, scanner/model measurement or test
execution was produced here. No hidden input/label was read or authored. A future
operator must first obtain runtime authorization and the independently appointed
custodian's exact metadata and receipt pins. Metadata is not proof of authorship,
actual execution, permissions, secret absence or durable consumption ordering.

## RunManifest v1

Import the dedicated module `iac_review.contracts.manifest`; no re-export or change
to contracts/__init__.py is needed. Wires are strict, frozen and extra-forbid.
Opaque IDs and bounded hashes replace source paths, model text and credentials.

The manifest binds run/edition/split/build/policy; source/parser/rule/prompt/config/
corpus component versions and hashes; per-invocation model/scanner versions;
case/configuration/family/mutation identities; separate raw-source and safe-
projection hashes; invocation/attempt identity, status, origin and exact receipts;
known billing and unresolved upper bounds; allowlisted artifact references; and
existing v2 evaluation eligibility digests. Version pins are declared compatibility,
not an assertion of tested tool/provider support. Missing model/scanner components
are allowed only when no invocation purports to use them. Each invocation selects
its config and component explicitly; no defaults silently turn mock into live.

Costs retain every declared attempt. Missing known charges are not zero total
cost; missing upper bounds are null. Pending or unknown liabilities stay visible.
The inventory still needs external all-attempt verification and cumulative journal
reconciliation. A fingerprint of an omitted artifact does not make it reproducible.

## Read-only metadata preflight

Intended later invocation from a configured product checkout:

```text
python scripts/validate_bundle.py --root <private-bundle> --manifest <private-bundle>/metadata/run-manifest.json --manifest-sha256 <approved-canonical-manifest-pin> --authority-sha256 <approved-authority-pin> --semantic-suite-sha256 <approved-suite-pin> --eligibility-sha256 <approved-eligibility-pin>
```

This command has NOT been executed. Pins must come from the authorized external
scope owner, not be self-approved from incoming records. Canonical metadata hashes
use sorted keys, compact separators, ASCII escapes and JSON-mode model values;
artifact file hashes bind exact bytes. A new optional wire field changes canonical
model hashes, so metadata must be deliberately re-pinned against the adopted
schema rather than silently reusing an old approval.
The manifest itself must be at the fixed metadata/run-manifest.json path under
the selected bundle root; supplying an oracle/input path as --manifest is refused
before opening it. Declared metadata-role truth and ACLs still require custody.

The only readable artifact roles and paths are:

| Role | Exact relative path |
|---|---|
| authority | metadata/custody-authority.json |
| seal | metadata/seal.json |
| semantic_receipt | metadata/semantic-receipt.json |
| eligibility | metadata/eligibility.json |
| exposure | metadata/exposure.json |

Each metadata file is bounded by both its declared size and 4 MiB, checked for
duplicate JSON keys/nonfinite values, hashed and parsed through its closed typed
wire. Full parent/fork/session custody, exact semantic receipt, build/policy/prompt/
inventory bindings and evaluation eligibility are checked. Consumed editions
require actual exposure metadata; every eligible heldout arm needs a receipt.
A sealed edition can be inspected as metadata without unblinding. Any existing
exposure consumes it for later tuning; no preflight operation restores freshness.

All artifact paths reject traversal, drive/UNC/alternate-stream paths, Windows
device aliases, duplicate case aliases, symlinks and junctions. Only explicitly
shareable reports under shareable/ may be outward references. Private maps, raw
cases, oracle labels and private reports cannot be outward refs. The preflight
does not open case, oracle, measurement, utility, producer, report, schema or
private-map payloads. Their hash fields are declarations, not verified bytes.
It does not scan directories, invoke tools, create output, mutate custody, unblind
later automatically or authorize any experiment. The separate later scorer is
the controlled consumer that persists exposure before reading payloads.

JSON output always states payloads_opened=0 and product_acceptance=false.
Metadata consistency is separate from evaluation eligibility. Missing arms,
unknown billing or unfinished measurements remain INCOMPLETE; CLI exit 2 denotes
that incomplete metadata eligibility and exit 3 a refused/malformed selection.
Exit 0 means metadata-eligible only, never finished-product acceptance.

Filesystem race exclusion, ACLs, externally authenticated registry history,
single-owner custody and actual producer receipt truth remain external duties.
The source's path checks cannot provide cross-process isolation or authenticate
an actor who asserts a fabricated history.

## Binary scanner target and authoritative model accounting

ArmRow keeps compatible defaults prediction_target=full_outcome and
introduced_prediction=null. A binary scanner sets prediction_target=introduced_risk
and a Boolean/null, leaving outcome null. A binary false means introduction-negative;
it cannot distinguish clear from unchanged risk. Only declared supported,
executed/pinned v2 evidence enters confusion counts. Null/unmapped/unknown or
mock/legacy rows abstain. A definite Boolean on indeterminate gold is a certainty
error. D's exact full applicability/outcome/reason/evidence gate stays separate;
binary D cannot close it. Counts distinguish decidable and unknown-gold abstentions.

D5's existing ExportBundle.accounting_json is the authoritative invocation scope:
all started attempts, failed outputs, missing-row calls, tokens, pending IDs, known
spend and unresolved upper bounds. ProducerAccounting validates that exact wire
against every attempt snapshot; mismatched counts/amounts/usage/liabilities reject.
UtilityRequest's optional producer_exports carries the payload-free ExportBundle
projection with bounded JSON strings and rows. Each export is hash-checked and
never live-eligible. Full accounting and per-arm all-attempt aggregates propagate
even when every model ArmRow is not_run. Unknown total remains null; zero live
successes leaves cost/success null. Cumulative journal scope remains separately
bound and unreconciled, not assumed complete from one invocation.

The scorer preserves row_known_usd_subtotal as explicitly partial. For model arms,
known_usd is null without authoritative accounting, rather than silently publishing
zero from skipped rows. CLI attaches real utility all-attempt receipts or the
validated producer invocation accounting; fake/protocol exports remain INCOMPLETE.
No producer source edits or provider calls were required for this bridge.

## Later activation and validation

After Dirty Mode closes and INT authorizes runtime, resolve/pin dependencies,
generate schemas into a fresh directory and inspect them, then run the authored
regression sources and actual metadata/CLI journeys. The schema-export allowlist
includes manifest/preflight and producer-accounting wires; none were generated now.
Independently authored oracle/semantic/rubric evidence and real measurement arms
remain unfulfilled obligations. Authoritative bundle assembly, hidden-file hash
verification, publication and independent finished-product acceptance are separate
authorized phases. Retain negative measurements and explicit non-reproducible
withheld portions; do not substitute this metadata checker for those obligations.

## Guarded private assembly source

eval.runner.bundle and scripts/assemble_bundle.py now define bounded assembly
SOURCE. Neither was imported/executed for this package; no bundle was generated.
The ordinary core report has a separate private deterministic descriptor and
eight-file receipt inventory; see REPORT-PROVENANCE.md. Evaluation preflight and
this assembler do not promote deterministic reports into benchmark inputs.

The default assembler performs metadata-only preflight and copies only the five
fixed allowlisted custody metadata paths plus a canonical metadata/run-manifest.json.
It preserves omitted artifact IDs explicitly; a hash of an omitted payload is not
proof that it was included or made reproducible. No directory walk, source plan,
oracle, report, private map, model text, provider key or other-project path is
automatically copied. All reads remain under an exact externally pinned source
bundle root, and destination scope is separately pinned. Metadata roles/content
and actual project ownership still require the external custodian's verification.

An externally approved AssemblySelection binds product/run, canonical manifest,
exact local source/output root hashes, total byte cap and cooperative deadline.
CLI reads only metadata/run-manifest.json, metadata/assembly-selection.json and,
on explicit payload opt-in, metadata/release-authorization.json. Root hashes use
normcase(absolute local path) encoded as UTF-8; these are local private scope pins,
not outward identities or authentication. The selected source/output roots cannot
overlap, and the destination must not exist under an already-existing parent.
Canonical source manifest/selection metadata must be approved independently of
the invocation; computing new pins yourself does not create that authority.

Copying consumed synthetic payloads additionally requires BOTH the explicit
--include-consumed-synthetic-payloads flag and --release-sha256 naming the externally
approved ReleaseAuthorization. That strict record binds edition/manifest, actual
custodian and exposure artifact, authorizer/release record, valid time interval,
private-reproducibility purpose, exact artifact IDs/roles/hashes and independent
synthetic-only/secret-free/owned-project attestations. These are external claims,
not facts authenticated by this Python metadata checker. Actual custody and release
authorization must exist before the command is authorized; none was created here.

Only the exact consumed_holdout edition can pass that opt-in. Permitted payload
roles/paths are case_input under private/synthetic/inputs/, oracle under
private/synthetic/oracle/, and measurements under private/synthetic/measurements/.
Private maps, credentials, arbitrary private reports, unlisted files or non-synthetic
paths cannot be released by this API, even if someone supplies another role name.
Matched bytes are bounded and hash-checked before destination creation. No automatic
hidden unblinding, authoring, scoring, new model request or public publication occurs.
Secret-free/project-ownership attestation truth cannot be inferred from a digest.

The output receipt binds the exact copied manifest/metadata/payload bytes and lists
omissions; a detached receipt digest avoids a self-hash. assembly-state.json stays
ABORTED until every bounded file is fsynced and the final COMPLETE replacement
occurs within the deadline/authorization window. Failures roll back exact
invocation-created files/directories only; no recursive deletion or repair of an
existing destination occurs. Filesystem race isolation, directory durability and
authentic authorization remain external duties. Completion means local assembly
integrity only, never product acceptance or permission to publish.

Intended later CLI shape (NOT EXECUTED):

```text
python scripts/assemble_bundle.py --root <approved-private-bundle> --out <approved-fresh-output> --selection-sha256 <approved-selection> --manifest-sha256 <approved-manifest> --authority-sha256 <approved-authority> --semantic-suite-sha256 <approved-suite> --eligibility-sha256 <approved-eligibility>
```

The optional consumed-payload flag/release pin must be separately authorized, not
inferred from this example. Focused regression SOURCE covers metadata-only reads,
missing/expired/mismatched release, private-map refusal, root scope, digest mismatch
and fail-closed publication rollback. Those tests remain unexecuted.
