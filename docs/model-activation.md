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

Shared seam: this bridge conservatively uses `not_run` for every L/P/M plumbing
row independently of evolving scorer eligibility defaults. **Use `accounting_json`
for every attempt**, not model cost totals from rows excluded from scoring. INT/D6
own scorer admission and its v2 schema reconciliation. D6 can consume immutable attempts/provenance/accounting
and normalized observations without inference payloads; independent P assessment
requires the separately controlled transient claims, not these summaries.

After Dirty Mode closes, INT must authorize actual dependency/environment setup,
meaningful journal/timeout/cancellation/privacy/invariance/bridge checks, producer and
model pins, independent sealed oracle/rubric custody and assessors, real fixed-provider
transport deadlines, audited caps/prices and approved spend. Live eligibility needs
an explicit new adapter/admission path; flipping a field on a mock cannot qualify it.
Only then execute the required D/L/P/M measurements with exact provenance. No
mock result closes those obligations or product/runtime acceptance.

## Synthetic driver continuation (source only)

`scripts/eval_model.py` now delegates to `eval.model.driver.main`. It resolves
development imports relative to the script and keeps the caller's cwd. It accepts
no `--manifest`, hidden corpus, gold, split, scanner record, provider configuration,
key or arbitrary transport loader. The input is a user-attested synthetic plan;
synthetic origin cannot be inferred reliably from JSON and remains the user's
responsibility. The CLI requires `--fake`, a fresh output directory with an existing
parent, and explicit request/input/output/USD caps. There is no live mode.

For later authorized activation, an example interface is:

```text
python scripts/eval_model.py --synthetic-plan fixtures/demo/public-ssh.json --fake --out model-plumbing-run --max-requests 20 --max-input-tokens 2000000 --max-output-tokens 200000 --max-usd 0
```

This is an interface example, **not a command run during construction**; choose an
actual synthetic file. Per-request token bounds, byte caps, timeout and
`--fake-scenario valid|invalid|timeout|error|unknown-usage` are configurable. A
reported timeout requires reconciliation even with the fake's known zero cost.
Invalid/error responses retain all available accounting. Unknown usage halts later
starts through the journal. The driver never retries or reconciles automatically.

The driver computes D with the actual parser/rules/evidence/report source, joins
public resource IDs to parser keys by checked evaluation order (never addresses),
and constructs the safe baseline/projections for the executor. It fingerprints
relevant source bytes and config; its single-case corpus hash asserts no independent
oracle or sealed edition. It rechecks plan/source pins before exporting. Runtime setup,
producer compatibility and all these joins remain unverified under Dirty Mode.

Only the fresh output directory receives `attempts.jsonl` and `plumbing.json`.
The latter contains safe D summary/rows, mock model rows, metadata-only observations,
all-attempt receipts/costs and cumulative journal state, without source paths, raw
addresses, pointers, P text or plan bytes. Existing files/directories and symlink/
junction paths are rejected. A failed run preserves its journal for inspection;
it does not remove, reuse or automatically repair that directory. Errors emit fixed
codes rather than exception/request text. A completed plumbing invocation returns
exit **2** because L/P/M measurement remains incomplete; invalid invocation/source
returns **3**. D's own risk/coverage exit is retained in the deterministic summary,
and is never promoted into an L/P/M measurement result.

Focused regression **source** in `tests/eval/test_model_driver.py` covers canary
boundaries/M isolation, D invariance, always-ineligible bridges, input byte caps,
failed charges/usage, known-accounting timeout and unknown liabilities, explicit
fake mode and fresh output preservation. These tests were authored but **not run**.
