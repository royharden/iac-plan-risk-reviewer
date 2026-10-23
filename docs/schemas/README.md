# Boundary schemas and scoring v2 source

No generated schema files exist from this Dirty Mode package. The exporter and
regression tests are source only; they have not been imported, executed or used
to claim schema compatibility. Later, after dependencies/runtime are authorized,
call `python scripts/export_schemas.py --out <fresh-directory>` from the inner
product root. Keep generated artifacts separate from this authored README.
The destination parent must exist; existing destinations and symlink ancestors
are refused. Nothing is loaded/written by merely importing export_schemas.py.

The exporter lists known strict/frozen/extra-forbid Pydantic boundary models
explicitly: core evidence/decision records, finite selector, model-only/rubric,
scanner capture/mapping, scorer/eligibility, custody, utility and bridge wires.
It emits validation-mode JSON Schema per model and a SHA-256 file manifest.
There is no plugin discovery, filesystem scan or generated-schema claim here.
JSON Schema cannot encode all custom validators, Python strictness, identity
authentication, secret handling or custody write ordering. The runtime Pydantic
model and external scope/custody approval remain authoritative.

## Scoring v2 compatibility

ArmRow constructors remain compatible: schema_version defaults to 1,
measurement_kind to unverified and eligibility_ref to null. Such rows can be
imported for development/plumbing but never satisfy measured/live obligations.
No old row is silently upgraded. D5 fake/protocol exports remain not_run.

New eligible rows explicitly use schema_version=2, measurement_kind=executed
for D/scanners or live/replay for model arms, and eligibility_ref equal to
`record_digest(EligibleMeasurement)`. The separately approved EligibilityManifest
binds edition, arm, measurement_ref, raw source/build hashes, provenance digest,
kind and actual-execution attestation. Replay additionally identifies its pinned
original live receipt; it does not establish a new build's inference. The scorer
requires the manifest's externally supplied digest, rejects duplicate provenance
identities and treats mock/legacy/ineligible predictions as abstentions, never TN
on a positive. Missing/not_run/unmapped arms remain INCOMPLETE. A real executed
timeout/error/invalid result is a recorded failure/abstention, not a good score.
D's exact gate still requires exact applicability/outcome/reason/decision facts
and zero recorded evidence/certainty/privacy/mutation/effect violations.

The CLI now requires independently pinned custody authority/seal, exact semantic
receipt/suite pin, eligibility manifest/pin and UtilityRequest/pin. The old minimal
CLI invocation must be reconciled; score(oracle, rows, split) remains callable but
returns INCOMPLETE for unverified legacy imports. Library score alone does not
establish custody or utility: CLI provides that integrated boundary.

Heldout requires custodian-issued durable exposure receipts before any hidden
oracle/measurement/utility read; the CLI also fsyncs its own fresh output's
exposure.json before opening those payloads. Every accessed arm needs an exposure
receipt pinning the measurement artifact. Failure after that boundary retains
the consumption record. External exclusive custody/permissions and directory
durability are still required: local metadata cannot authenticate a claimed
pre-access write, discover omitted prior exposure or prohibit another process.
Any exposure consumes the edition for later tuning; fresh claims need new gold.

UtilityRequest holds separate L/P/M pins and all-attempt records; absent sections
are INCOMPLETE. Its pins must match the authority's build/prompt/rubric/edition and
sealed inventory hash. L/P denominator inventory must exactly include every
sealed eligible heldout scenario and match independently supplied risky oracle
rows. L's D/model ArmRows must be identical to the scored detection artifact.
Model measurement_ref is the utility Attempt canonical digest (optional sha256:
prefix); eligibility provenance_sha256 is that Attempt's terminal record digest.
This prevents an unrelated live receipt from upgrading mock model rows.
P appointments still require external registry/lineage custody verification;
the CLI additionally checks every assessor/adjudicator pair through the approved
authority's parent/fork/session graph against all implementation actors. Metadata
names and graph attestations alone are not identity authentication.

The authority prompt hash denotes the locked experiment prompt-manifest edition;
all utility pins name that same edition. Original per-request prompt and input
hashes remain in D5 attempt snapshots. Later live exporters must retain that
relationship under the independently approved prompt manifest rather than infer
it from a model name or a reused digest.

## D5 bridge

model_bridge.bridge_bundle consumes the preserved D5 ExportBundle. It verifies
the producer's attempt/accounting/observation hashes, keeps exact decimal amount
snapshots and all unknown liabilities, and never makes the producer live-eligible.
Raw case source_sha256 stays distinct from request/projection input_sha256.
Real externally supplied JournalLinks are needed to construct utility Attempts;
missing start/terminal journal digests remain explicitly unconverted. No missing
digest, L word count, P generated claim inventory or rubric annotation is invented.
The current producer therefore closes source plumbing only, not live evidence.

Focused tests are authored under tests/eval/test_custody_scoring.py and
tests/contracts/test_schema_export.py. They use public synthetic metadata, not a
hidden oracle or gold generator. Test execution, generated schema inspection,
real model/scanner receipt import, independent semantic execution, authenticated
custody and finished-product acceptance remain deferred.
