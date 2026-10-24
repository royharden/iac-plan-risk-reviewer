# Boundary schemas and scoring v2 source

No generated schema files exist from this Dirty Mode package. The exporter and
regression tests are source only; they have not been imported, executed or used
to claim schema compatibility. Later, after dependencies/runtime are authorized,
keep the cwd at the outer shell and explicitly select the inner script:

```powershell
uv run --project .\iac-plan-risk-reviewer python .\iac-plan-risk-reviewer\scripts\export_schemas.py --out .\iac-plan-risk-reviewer\reports\schemas-new
```

This is a future authorized command, never run in Dirty Mode. Keep generated files
separate from this authored README. The parent must exist; existing destinations,
parent aliases, UNC paths and symlink/junction ancestors refuse. Importing the
exporter or data-only registry does not load application/provider modules or write
files. Calling schema generation later explicitly imports canonical wire modules;
that is separate from the offline product's default import graph.

The [fixed registry](../../eval/runner/schema_registry.py) declares core/report
wrappers, provenance/RunManifest, accounting, existing finite selector, model-only,
scanner, scorer/eligibility, custody, utility/producer bridges, private prose/rubric/
assessment/catalogue/fact/capture-index/batch, assembly/completion release and
disabled provider-activation metadata. It reuses actual canonical classes. Completed
strict/frozen/extra-forbid Pydantic roots get their actual validation schemas;
frozen ordinary dataclasses use their actual TypeAdapter descriptions, with no
duplicate model or configuration that pretends their runtime parser is closed.
Runtime clients/callbacks, HTTP body wrappers and private Result/Observation/
PrivateCapture collections are excluded. No instance, environment/config/approval
or real artifact is read. D5's unfinished finite-selector extension is excluded;
the previously completed finite selector wires remain unchanged.

The [exporter](../../scripts/export_schemas.py) emits validation-mode schema files,
a data-only catalogue and an explicitly version-2 SHA256 file manifest.
There is no plugin discovery, filesystem scan or generated-schema claim here.
JSON Schema cannot encode all custom validators, Python strictness, identity
authentication, secret handling or custody write ordering. The runtime Pydantic
model and external scope/custody approval remain authoritative.

## Registry and exporter compatibility

`declarations()` and `catalogue()` return fixed metadata without loading app
modules. Entries have stable ID, contract_version, canonical type_name,
private/shareable_shape classification, representation, literal wire_versions and
wire_version_field, plus declared runtime-unverified compatibility. Catalogue
contract version `1` is a description revision, not a payload schema upgrade.
`shareable_shape` does not authorize sending an instance; product semantic/privacy
validation is still required. All custody/prose/assessment/capture/provider/release
types and the whole ReviewReport wrapper are classified private.

`resolve(id, contract_version="1", *, wire_version=None)` dispatches metadata
explicitly and refuses unknown IDs/contract/wire versions. It never parses or
admits a payload. `boundary_models()` explicitly imports fixed canonical types;
`schema_documents(models=None)` generates their descriptions only on invocation.
Missing required completed types, duplicate IDs, version/classification/type
substitution and actual Literal-version drift fail rather than silently omit.
Unversioned wires have no invented schema_version. Capture index uses its actual
`schema` alias; batch transport accepts exactly
`m4-assessment-batch-transport-v1`. The batch wire is independent of the private
assessment request, canonical D4 provenance version and catalogue version.

Legacy exporter `boundary_models()`, `schema_bundle()`, `export_schemas(out)` and
`main(argv=None)` call signatures and required `--out` flag remain. Existing schema
filenames remain stable. The output manifest changes explicitly from version 1 to
2: `files` still hashes schema files only; `catalogue` separately hashes
`catalogue.json`. `schema-export-state.json` must be COMPLETE before consumption.
It starts ABORTED, writes fresh files with cooperative bounds, and finalizes last;
partial failure attempts cleanup of only files created by that invocation. Output
failure/crash/ACL/race behavior remains unverified. Schema-only output cannot grant
payload admission, actor authentication, execution, provider activation, release
authorization or product acceptance; all those claims are explicitly false.

The real ReviewReport has private/shareable `dict[str, Any]` fields. No completed
canonical closed per-artifact inventory type exists. Its schema therefore does
not prove report shape/privacy, and no duplicate model was invented to claim
otherwise. Actual legacy manifest 1.0.0 versus bound 1.1.0 report inventory/version
checks remain in [source_view.py](../../src/iac_review/source_view.py). Likewise,
RunManifest version 1 has separate deterministic/evaluation stages enforced by
its Python validator; schema availability cannot replace custody/eligibility.
VerifiedCaptureIndex validation schema can describe private artifacts excluded
from default serialization. Opaque JSON-string/dict fields stay opaque to schema;
no instance/payload/authority verification follows from their presence.

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
