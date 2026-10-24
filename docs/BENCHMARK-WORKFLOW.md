# Fixed seven-arm benchmark source

The coordinator is source construction only. No coordinator, producer, corpus,
model/scanner runner, CLI, journal, import or test was executed during Dirty Mode.
Fake/protocol plumbing is NOT_MEASURED and never product or comparison acceptance.

`eval.runner.benchmark.coordinate` fixes D/L/P/M/C/C-custom/T; there is no plugin
registry, arbitrary command or adapter-import string. The CLI fixes actual product
load_plan/evaluate/build_report, actual D5 run_experiments/export_bundle and actual
scanner compare/manifest adapters. D5 run_driver owns a fresh per-call journal, so
the coordinator uses its actual lower-level producer API with ONE owned
AttemptJournal across ALL cases. No journal/cap reset or automatic reconciliation
occurs. All requests, failed/invalid/timeout attempts, reported tokens and unknown
liability bounds remain in the cumulative journal; unknown liability blocks later
model starts even when the fake price is zero. Per-invocation accounting is not
summed as if each cumulative journal snapshot were a separate run.

The default entrypoint accepts only explicitly attested public development-synthetic
cases and non-network fake/protocol model identity. Scope rejects BEFORE raw payload access.
There is no heldout accessor or scoring/gold phase. A future heldout controller must
have external freeze/custody pins and durable consumption authorization BEFORE any
payload read; metadata preflight success or changing a split flag is insufficient.
This source grant does not open that path or authorize live model/scanner calls.

Exact raw plan digests are checked before/after D, every L/P/M transport request,
and before/after the scanner producer; scanner compare checks each C/C-custom/T
arm itself. Hash mutation aborts that case and retains explicit not_run statuses
for later cases, with started attempts preserved. Other case/admission failures
retain all seven status entries. Missing/unmapped/unknown arms are never true
negatives. D's frozen baseline is checked around model export; model invalidity or
timeouts cannot modify its risk outcomes. No expected labels or hidden inputs are
accepted or produced. Actual admission still requires external execution eligibility.

Transport receives Request only. L/P must exactly match frozen capsules from D's
allowlisted shareable projection. M must match the independently normalized safe
RAW plan projection with opaque IDs; it gets no D findings, outcomes, gold, split,
scanner results, private map or provenance. Private raw CaseSpec paths/ancestry and
case joins stay local. Scanner results are constructed after model
inference returns and are never passed into the producer/transport. Models have
less information than raw-JSON scanners by design; this asymmetry is explicit.

Only D5's allowlisted ExportBundle is serialized; its transient P claims/private
model map are discarded. Private provenance retains cumulative journal attempts,
per-case attempt-index spans, safe producer accounting and normalized scanner
receipts. Candidate manifest remains draft when actual authority/semantic/eligibility
or component/artifact pins are missing; no dummy hashes, fabricated execution
receipts or invented source labels fill those gaps. A separate public summary has
fixed arm statuses/counts only, no private map, raw values/paths or model prose.

The later CLI requires a closed m4-seven-arm-benchmark-config-v1 JSON object with
run_id, edition_id, build_sha256, input_scope=development_synthetic, fake_only=true,
synthetic_input_attested=true, cases and run-wide budget. Each case contains only
case_id, absolute plan_path, plan_sha256, configuration_id, family_id and
mutation_lineage, with optional externally supplied case_record_sha256. Budget uses
max_requests, max_input_tokens, max_output_tokens and decimal
max_usd; model_limits and scanner_arms are optional fixed-shape settings. Scanner
settings accept check_ids and explicit pinned fake_fixtures only. No gold/split,
provider key, HCL, live scanner binary or arbitrary import option is accepted in
this default configuration.

`scripts/run_benchmark.py --config <metadata> --config-sha256 <external raw-file pin>
--out <new product results/run>` is a
future fake-only activation interface. It opens one journal, preserves partial
output and writes private rows/provenance/manifest candidate separately from a
shareable status summary. Exit 2 means still unmeasured; a fake success never yields
a live-eligible row. Do not run it during Dirty Mode. Real runtime/dependency,
data-separation/effect, custody/measurement and independent acceptance work remains.

The CLI checks the actual fixed source-tree fingerprint before any case/output
access and the coordinator checks it again at completion. `source_build_digest()`
hashes product Python/configuration source, excluding hidden/cache/link directories;
it does not inspect Git, corpus or private lanes. Changed source invalidates all
statuses while preserving started attempts. The exact operator configuration-file
hash is retained separately from the normalized coordinator configuration hash.

An optional `--manifest-context` requires `--manifest-context-sha256`, the external
canonical digest of the actual shared RunManifest record. Its development case
inventory, run, edition and build must match exactly before case access. It cannot
import prior invocation/attempt/eligibility records or hidden/oracle payload refs.
Fixed component IDs are `<arm>_version` and `<arm>_config`; version kind is source
for D's primary build component, rules for D_version, model for L/P/M and scanner
for C/C-custom/T, matching actual preflight invocation bindings. Configuration kind is config.
All mandatory authority/semantic/eligibility/component pins come from the external
caller; missing pins remain DRAFT_INCOMPLETE. A complete metadata candidate still
sets every all_attempts_attested and claimed_eligible flag false. No execution
proof, billing proof or eligibility receipt is invented for missing producer data.
The provenance ArtifactRef pins exact UTF-8 bytes with one LF, as written by the
future CLI. Public summary and private metadata are separate files.

Raw saved-plan SHA256, canonical model-request hash (`hashes.input`), safe projection
hash (`hashes.projection`) and external case-record digest have distinct meanings.
Context.source_sha256 remains each case's actual raw plan identity. Per-case model
exports retain that identity and their original receipts. Repeated findings, calls
or case records on identical plan bytes count once in the diagnostic distinct-raw
count; that count never establishes the >=24 eligible-scenario requirement. The
summary leaves eligible_scenario_count null pending the externally frozen eligible
inventory. No request/projection digest substitutes for a raw plan or case record.
Run-wide totals use the one cumulative journal; per-invocation ExportBundle totals
are retained for reconciliation and are never added to cumulative totals again.
Unexported or interrupted attempts remain visible with explicit unmatched/draft
reasons rather than invented arm receipts. Unknown liability blocks later model
starts. Cancellation retains all seven statuses for untouched cases.

## Serialized benchmark v1 consumer contract

`BenchmarkResult.private_provenance_json` is the existing D5 `canonical(object)`
string (sorted keys, compact separators, ASCII escaping), whose top-level version
key is `schema_version="m4-seven-arm-benchmark-provenance-v1"`, not `schema=1`.
Pin its canonical string with `digest(private_provenance_json)`. The persisted
producer ArtifactRef separately pins `(private_provenance_json + "\n").encode("utf-8")`.
These digests have different byte domains.

- `run_id`, `build_sha256`, `corpus_metadata_sha256`, `config_sha256`: strings.
  `operator_config_file_sha256`: external raw-file digest or null.
  `transport_kind`: mock/protocol; `source_build_check`: not_performed/matched/mismatch.
- `case_records`: list of `{case_id: string, raw_input_sha256: string,
  case_record_sha256: string|null}` from the declared local CaseSpec inventory.
  `case_bindings`: separate list of actual shared CaseBinding JSON records
  (case_id, split, configuration_id, family_id, mutation_lineage,
  raw_source_sha256, safe_projection_sha256). Split is dev; an absent projection
  pin is null. Neither inventory itself establishes eligibility or execution.
- `model_exports`: list of `{case_id: string, raw_input_sha256: string,
  rows: list<ArmRow JSON>, attempts: list<original D5 attempt receipt object>,
  accounting: object, provenance: object, observations: list<object>}`. The nested
  fields are exactly JSON-decoded existing ExportBundle strings, with no producer
  hash repinning. Case identity and raw hash come from the local invocation, not
  rows[0]. Even an empty or rejected export is retained with original receipts;
  rejection leaves explicit model_export_admission_incomplete and missing rows.
- Reconstruct an existing ExportBundle with
  `ExportBundle(tuple(ArmRow.model_validate(r) for r in e["rows"]),
  canonical(e["attempts"]), canonical(e["provenance"]),
  canonical(e["accounting"]), canonical(e["observations"]))`.
  Name `digest(canonical(e["provenance"]))` **provenance_only_sha256**.
  It binds only the original nested producer provenance record, not the whole
  ExportBundle. Name D5 `eval.model.capture_index.export_digest(bundle)`
  **whole_export_sha256**: this is the required separately pinned whole-export
  identity for capture verification. Its actual existing implementation hashes
  canonical row objects, digests of the original attempts/accounting/observations/
  provenance strings and live_eligible. Use that helper after reconstruction;
  do not replace it with provenance_only_sha256 or a new duplicate wire formula.
  The original strings are reconstructed with the same canonical helper, retaining
  their byte identity. Neither computing a pin nor matching it authenticates origin.
  An outer case/raw binding does not override differing original provenance;
  mismatch is incomplete. An empty export remains empty, never fabricated rows.
- `attempt_case_spans`: list of `{case_id: string, start_index: int,
  stop_index: int}`. Index interval is half-open into final journal_snapshot.attempts
  in durable start order. No span is manufactured for a later untouched case.
- `journal_snapshot`: original final AttemptJournal.snapshot object; if unavailable,
  explicit fallback summary/empty attempts plus snapshot_unavailable=true,
  all_attempts_retained=false and fixed reason. Missing snapshot is incomplete.
- `model_attempts`: one object per retained snapshot attempt, containing attempt_id,
  nullable case_id/arm, original snapshot object, nullable original producer receipt,
  nullable raw_input_sha256/case_record_sha256/request_input_sha256/
  safe_projection_sha256. Case derives solely from a unique span; arm derives
  solely from a unique original receipt by attempt_id. Duplicate/unmatched receipts
  cause explicit missing reasons. Raw hash is the case input; request/projection
  are original producer hashes.input/hashes.projection. Unknowns remain null.
- `scanner_manifest_parts`: list of original scanner adapter safe summary objects;
  `scanner_exports`: list of `{case_id: string, normalized_report: object}` retaining
  accepted fake-only scanner reports and capture metadata. Invalid forged scanner
  records are rejected rather than admitted as producer evidence.
- `run_accounting`: object with basis string, summary (single cumulative journal
  summary) and complete_snapshot bool. `aborted`, `product_acceptance`, `live_eligible`
  are booleans; the latter two always false. Do not add invocation accounting to
  these cumulative totals or infer a raw scenario denominator from request counts.

For clarity, **outer_benchmark_provenance_sha256** is the digest of the canonical
top-level private_provenance_json string; **written_provenance_file_sha256** includes
the persisted final LF. These are separate from both whole_export_sha256 and
provenance_only_sha256. Existing serialized field names remain unchanged: consumers
can derive each explicitly named identity from its original byte domain and must
require the appropriate independent external pin. No substitution or repinning.

This v1 wire retains compatible field names/types. The case-binding correction
removes dependence on nonempty rows and keeps original failed exports intact.
The default route keeps the D5 complete_started provider seam disabled: it uses
the shared journal and fake/protocol Request-only transport. The separate explicit
approved-synthetic source route below still cannot claim live eligibility. D6 owns the separate consumer,
assessment and bounded batch CLI; this producer does not read gold or authorize it.

## Future explicitly approved synthetic route (SOURCE ONLY)

No activation, approval, price/version pin, credential, connector, scanner process,
corpus or output has been created or exercised. Dirty Mode remains OPEN. This route
is future source for use only under a later genuine external execution grant.
Fake is still the CLI/API default. Setting config.fake_only=false alone refuses.
The separate `coordinate(..., execution_mode="approved_synthetic", ...)` mode needs
config.fake_only=false plus exact external SyntheticAuthority, an enabled actual
D5 ProviderTransport with PinnedController, existing ApprovedScanner bindings for
every case and an actual owned shared AttemptJournal. Injected replacement product,
model or scanner producers are refused in this mode. Heldout remains refused.

`load_synthetic_authority(raw_bytes, expected_sha256=external_raw_byte_pin)` checks
the bounded closed record `m4-approved-synthetic-benchmark-v1`. Fields are run_id,
edition_id, build_sha256, config_file_sha256, configuration_sha256, corpus_sha256,
arm_inventory_sha256, provider_sha256, price_sha256, budget_sha256,
model_limits_sha256, data_transfer_sha256 and scanner_grants (case_id -> externally
pinned original scanner-grant bytes digest). It requires dirty_mode_closed,
synthetic_only and execution_explicitly_approved all true. These are declarations,
not identity authentication. The code never manufactures them or closes Dirty Mode.
Configuration SHA is `benchmark_config_digest(config)`, binding complete normalized
case metadata including raw paths/external case-record pins and exact configured
limits. Corpus SHA retains the existing canonical case/raw/config/family/mutation
inventory convention. Arm SHA binds all seven IDs. Provider SHA binds actual
ProviderConfig asdict via D5 canonical/digest; price and budget SHA bind actual
model_dump_json strings of the one journal. Model limits use canonical asdict.
Raw configuration-file and external data-transfer pins remain separate identities.

Use the existing D5 ProviderTransport(config, enabled=True,
controller=PinnedController(authority, externally_owned_controller), ...).
No second provider transport exists here. Before each possible key/connector read,
the guarded fixed Request boundary checks its safe capsule/projection and raw
input, then delegates complete_started with the SAME actual journal, durable
attempt_id and original deadline. D5's actual controller returns Admission after
the durable start. PinnedController requires its approval/provider/price/budget/
transfer identities match this run; D5 separately validates the original permit,
exact start/request/journal/endpoint/IP/deadline before reading a key or creating a
connector. Refusal preserves the started attempt and unresolved liability; no retry
or journal reset occurs. Model exports remain unverified/not_run for scoring.

Each ApprovedScanner carries an immutable original manifest_json and the existing
BoundedSubprocessRunner with externally pinned LocalExecutionGrant. Exact synthetic
case path/raw/build, all three C/C-custom/T arms, grant identity and manifest hash
are checked before inference. The existing runner verifies invocation argv,
environment, executable/dependency/config/policy/check pins and bounds before its
sole subprocess implementation. No scanner runtime code is duplicated. Manifest
resource IDs may be predeclared scanner-local opaque IDs: exact raw address-set
equality supplies only a local ID join to the product's fresh public IDs. This join
is validated before model key access and again before scanners. No D facts/labels
or safe model projection enrich scanner input. The original normalized_report and
its capture pins are retained unchanged; approved-only scanner_exports adds
resource_aliases as a private list of records with exact fields
`{case_id: string, arm: C|C-custom|T, raw_input_sha256: string,
scanner_resource_id: string, public_resource_id: string}`. Each case/arm/raw domain
has a bijective join; ambiguous addresses, duplicate IDs and many-to-one public IDs
refuse. No record crosses case/arm/raw identity or overwrites another domain.
The original bridge rows remain unchanged in approved-only private
`unadmitted_rows: list<ArmRow JSON>` alongside normalized_report. The separate
`alias_status` is incomplete or bijective_unadmitted. Main comparison output uses
explicit not_run/unverified placeholders with no prediction, rather than rewriting
original scanner-local row IDs or treating a join as execution eligibility. Original
capture/report/mapping/measurement pins stay intact. A later externally admitted
consumer must validate alias bindings separately; no receipt is repinned to conceal
a changed source report. Missing/foreign/ambiguous joins preserve available original
reports/rows/attempts privately and retain explicit incomplete comparison cells.
Aliases never enter inference or public summary output.

Approved-only v1 optional top fields are execution_mode=
approved_synthetic_unverified and execution_authority_sha256 (original external
approval bytes pin). Existing fake v1 fields are unchanged. Actual capture attempts
remain unverified in typed metadata, with all_attempts_attested=false and no
eligibility claim; an actual process return or provider response cannot establish
correctness, genuine measurement, semantic coverage or independent acceptance.

The CLI source accepts explicit --mode approved_synthetic and separately pinned
--execution-authority/--execution-authority-sha256 metadata. Its programmatic
main(argv, approved_transport=..., approved_scanners=..., approved_price=...) must
also receive already configured external objects. Bare CLI flags cannot construct
an external controller, load arbitrary modules, discover prices or enable provider
credentials; absent objects refuse before key/process start. Price is the exact
caller-supplied PriceIdentity, never the default mock-zero price. Output remains
private metadata plus status-only summary; exit 2 still means NOT_MEASURED. No part
of this source interface is permission to run during Dirty Mode.
