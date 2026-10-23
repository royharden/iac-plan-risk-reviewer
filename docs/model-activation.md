# Model experiment source and later activation

This is Dirty Mode source construction, **runtime unverified**. No model experiment,
provider request, dependency setup, app import or test was run for this package.
L/P/M remain **NOT MEASURED**. The existing CLI entrypoint remains INT-owned and
unchanged; these functions do not silently enable it.

`eval.model.experiment.run_experiments` accepts a pinned `PlanDocument`, shareable
projection, immutable D `ArmRow` baseline, local `FindingLink`/`ResourceLink` joins, SHA256-only
`Context`, injected `Transport`, already exclusively owned `AttemptJournal`, and
bounded `Limits`. It returns a frozen `Result`. The caller supplies D; the executor
does not run detectors or invent D findings. D rows must have the same build/source
hashes as Context. Each L/P link must match its real baseline rule/outcome. Joins
also reconcile the report's freshly randomized public resource IDs to the parser's
separate local opaque keys; they must cover exactly this plan without collisions.
They are local metadata and never enter inference. An existing journal can be reused:
per-invocation attempt receipts are separate from the cumulative journal summary.

L uses `build_capsule` and `validate_selection` from the product finite selector.
P receives that same capsule and produces transient JSON `claims`; its shape is
checked, its truth is **not** verified. Claims must be withheld from the product
and supplied to two independently appointed assessors using `protocol.prose_metrics`
after activation; no assessor, rubric, successful quality score or productivity
gain is asserted here. P claims are deliberately absent from the receipt export.
An authorized later assessment tool must keep generated claims, including withheld
claims, in a separate access-controlled artifact; this package writes none.

M uses only `protocol.model_only_input(plan)`, built before L/P callbacks, and
`validate_predictions`. No D findings/outcomes, oracle labels, split IDs, scanner
outputs, private maps or provenance enter its request. Missing predictions remain
abstentions. The private resource join is returned locally as opaque M ID to local
resource ID; raw addresses/pointers/values never enter that join. Existing protocol
coverage loss (including non-world CIDR withholding) remains explicit; no guessed
false values fill it. Caller-supplied corpus IDs must be trusted local metadata,
not addresses or secrets. Baseline export requires safe case/resource tokens,
fixed reason codes, and a SHA256 measurement reference, not a path.

`transport.FakeTransport` implements keyless plumbing: finite L, template-copy P,
empty M predictions. A supplied fixed `Reply` can represent invalid/timeout/error
paths later. Mock accounting is accounting for the fake only; a zero mock charge
does not establish provider cost. Match its identity (`mock`, `finite-fake`, version
`1`) to an explicitly mock `PriceIdentity`; choose a dated mock price and bounded
mock budget rather than pretending a provider price was measured.

The only other transport kind is `protocol`, also live-ineligible. Trusted injected
code is a caller responsibility; it must honor request limits and must have no
tools. There is no HTTP/SDK/provider implementation, environment lookup, retry or
network/process launch in these modules. `IAC_REVIEW_PROVIDER`, `IAC_REVIEW_MODEL`
and `IAC_REVIEW_API_KEY` are names only, never read. Arbitrary Python injection is
not a sandbox. Do not inject a live callable under this construction grant.

For every started call, journal `start` durably records the worst-case reservation
before transport invocation, followed by `terminal` with shape/transport status,
duration, available usage/cost and response digest. Exceptions use fixed codes,
never exception messages or payloads. Failed/invalid calls retain known costs and
unknown liabilities; no automatic reconciliation occurs. All timeouts halt further
calls and require operator reconciliation, even when accounting is complete (the
journal repair is D7/INT-owned). Unknown usage also blocks new starts through the
journal. Cancellation stops the batch. If a terminal append itself fails, the
executor raises and the durable unmatched start remains pending. A crash is never
converted into a free request. This code does not manage the caller's journal lock.

The timeout is cooperative: elapsed time is checked on return, so an uncooperative
injected callable cannot be forcibly interrupted. Enforce actual transport deadlines
and token caps in any future approved adapter. Byte caps bound serialized inputs and
outputs here; no tokenizer or universal token-bound proof is claimed. Price/model
versions, actual token counting and worst-case exposure need validation before live use.

`provenance.export_bundle(result)` is the only intended serialization boundary.
Its frozen `ExportBundle` holds canonical JSON strings for allowlisted immutable
attempts, metadata, observation counts/IDs and accounting, plus tuple `ArmRow` wires.
It binds build/source/corpus/config, exact prompt/projection/input/model/version,
response/usage/price and baseline hashes. It never exports prompts, responses, P
claims, plan bytes, raw source map or exception text. Hash binding is integrity
metadata, not independent measurement authentication. Do not use generic
`dataclasses.asdict(Result)` or serialize transient observations.

All L/P/M rows are `not_run` for live scoring even if their plumbing status is `ok`;
actual plumbing status stays in attempt/observation receipts. L preserves D outcomes
and limitations even on fallback; P cannot emit product decisions; M uses only its
own returned predictions. D baseline rows are preserved exactly, and are not a new
D measurement. Each shared M attempt's cost is assigned at most once across scorer
rows, while every receipt is retained even without a matching prediction. Aggregate
known portions and unresolved upper bounds are separate. Unknown total cost and
cost per live success remain null, rather than a fabricated zero.

Shared seam: `ArmRow` lacks a live/mock discriminator and `score()` excludes
`not_run` rows from cost aggregation. Therefore **use `accounting_json` for every
attempt**, not the existing scorer's model cost totals. INT owns any future scorer
admission/CLI integration. D6 can consume the immutable attempts/provenance/accounting
and normalized observations without inference payloads; independent P assessment
requires the separately controlled transient claims, not these summaries.

After Dirty Mode closes, INT must authorize actual dependency/environment setup,
meaningful journal/timeout/cancellation/privacy/invariance/bridge checks, producer and
model pins, independent sealed oracle/rubric custody and assessors, real fixed-provider
transport deadlines, audited caps/prices and approved spend. Live eligibility needs
an explicit new adapter/admission path; flipping a field on a mock cannot qualify it.
Only then execute the required D/L/P/M measurements with exact provenance. No
mock result closes those obligations or product/runtime acceptance.
