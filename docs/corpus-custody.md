# Corpus custody and utility source boundaries

Dirty Mode construction only: these sources have not been imported or executed.
No hidden input, expected label, corpus generator or actual execution receipt was
created for this package. Metadata validation cannot authenticate authorship,
permissions, execution, timestamps, a durable write or an attestation's truth.

## Custodian-owned freeze

`eval.runner.custody` uses the existing strict/frozen `Record` and `Edition`
contracts. Its new records are proposed public metadata wires. They contain
opaque inventory identities and hashes, never raw cases, expected outcomes,
source locations or label values. Keep even these metadata records under the
custodian's permissions until the independently authorized release boundary.
Implementation actors must not inspect hidden cases to populate these records.

The INT/custodian supplies an externally approved SHA-256 of a
`CustodyAuthority`; taking that pin from the submitted seal is insufficient.
Canonical metadata hashing uses sorted keys, compact JSON separators, ASCII
escaping, JSON-mode model values and no nonfinite numbers. Inventory hashing
uses the same encoding over the ordered list of InventoryRow JSON objects.
Hash identity is not correctness or proof of source independence.

The authority pins policy, build, prompt, rubric, oracle and lineage inventory
before sealing. Qualified registry identities, sessions and complete parent/fork
edges are required. Author and checker must be distinct from each other and
implementation; custodian must be separate from implementation. This initial
validator conservatively excludes connected parent/fork/session lineages,
including siblings. Incomplete registry history cannot establish independence.
This is stricter than a bare different-callsign check and does not replace
appointment and external identity verification by INT.

`validate_seal` checks those pins/attestations and the bounded opaque inventory.
Family, configuration, mutation ancestry and identical input digests cannot cross
partitions. Public/upstream examples are development-only. Each fixed v1
semantic cell must appear in both dev and heldout under disjoint ancestry.
At least 24 distinct explanation-eligible heldout inputs are required, with at
least six per rule and representation of all six change-action classes and
known/unknown/sensitive states across the inventory. This is a proposed concrete
balance contract: independent author/checker must establish actual eligibility,
positivity, semantic coverage and sufficient diversity. A Boolean supplied by a
detector author is not an eligibility oracle. The independent inventory may
need expansion beyond the provisional 96 cases before exposure.

`validate_semantics` requires a separately pinned exact-suite hash, the appointed
checker, actual execution origin, every mandatory cell, positive discovered
counts with no skips/failures and zero exact/evidence/certainty/privacy/effect
violations. It checks a reported receipt, not real execution. No receipt exists
from this Dirty Mode package. Future suites must independently author exact
outcomes, reasons, applicability and decision facts; cell names alone cannot
prove their coverage or assertions. A green aggregate confusion score is
insufficient.

## Exposure consumes the whole edition

An external single-owner custody controller must persist an irreversible
`ExposureReceipt` BEFORE reading hidden input, labels or results. It pins the
authority, full seal, build, oracle, measurement artifact and arm, with aware
timestamps and a distinct durable receipt identity. Parse/score failure after
exposure still consumes the edition. `validate_exposure` accepts at most one
receipt per arm and returns consumed_holdout; any requested fresh claim with
an exposure receipt is rejected. Subsequent builds/tuning require a newly
independently sealed edition. Consumed replay is regression only. Read-only
validation here cannot persist consumption, establish write ordering or discover
a withheld receipt: external custody storage/permissions must enforce this.

## Integration seams owned by INT

- `scripts/eval.py` currently uses Edition plus an older exposure object. It
  does not call these sidecars. INT must wire authority/seal/semantic receipt
  validation and durable pre-access custody before eligible scoring. Its current
  source reads oracle bytes before writing exposure.json; the stronger boundary
  must record exposure before that read. Current CLI output does not become a
  custody-validated measurement merely because these files exist.
- `scoring.ArmRow` lacks mock/live eligibility, full attempt provenance and
  denominator inventory. It cannot by itself establish live utility evidence.
  `utility.py` will consume ArmRow and separate pinned metadata, not modify it.
- `protocol.prose_metrics` supplies claim/rubric counts; a wrapper must bind the
  complete generation inventory, appointments, adjudication and all attempts.
  D5/D4 own the model/scanner source adapters. No hidden labels go to them.

Later validation must exercise altered pins, ancestry cycles/missing edges,
split bridges, duplicate inputs, missing semantic cells, insufficient eligible
inventory, stale exposure and consumed-edition replay. Runtime, independent gold
author/checker appointment, authenticated custody and product acceptance remain
pending. No publication or paid experiment is authorized here.

## Utility sidecar contract

`utility.MeasurementPin` binds build, corpus, complete expected explanation
inventory, prompt, rubric, model version, price identity and expected attempt
identities. The controller supplies its externally approved digest. The inventory
hash is `explanation_inventory_digest(cases)`, over the ordered JSON-mode case
list using the canonical encoding above. This includes required/allowed fact and
limitation IDs; the independent custodian supplies them. No oracle was populated
in this package. The pin and appointments still need external verification.

`Attempt` separates raw `source_sha256` from model projection `input_sha256`,
requires start/terminal provenance, and retains invalid, timeout, rejected,
cancelled and pending attempts. Replay must reference original live evidence for
the same pins; mock and not_run never qualify as live measurements. No automatic
retry is performed. Missing attempts, pending billing and unknown upper bounds
remain explicit; unknown billing never becomes zero cost/success. Costs sum
unique attempts, not ArmRows (one attempt may explain multiple findings). Zero
successes gives null cost/success. p50/p95 are nearest-rank/median attempt latency,
with observed denominators; total duration needs every expected duration. These
are not human reviewer timings or total report-generation wall time.

`l_utility` pairs existing D/L ArmRows with an independent expected scenario
inventory. Missing observations remain failures in that inventory's denominator.
It checks D decision invariance, selected identifier scope, essential facts and
limitations, finite-template predicate attestation, critical errors and nonempty
word counts. A failed explanation conservatively retains zero essential facts in
task-completion recall. Median word reduction is the median of paired fractional
reductions, using exact fractions for the 20% boundary. Missing pairs make the
median criterion inconclusive; ranges are descriptive, not confidence intervals.
Enabling L additionally requires >=24 balanced distinct scenarios, full essential
coverage, no critical errors and fully known all-attempt cost within an externally
approved per-success limit. Until then D remains the default. A genuine measured
negative result is valid; mocks cannot satisfy measurement eligibility.

`p_utility` wraps existing `protocol.prose_metrics` with explicit two-assessor and
third-party adjudicator appointments, complete scenario inventory and attempt
binding. Each attempt's `generated_claim_inventory_sha256` pins the ordered list
of all generated claim IDs, including withheld claims. Independent response
parsing must establish that list; this metadata validator cannot inspect absent
response text or detect a dishonest inventory. Support denominator includes all
generated claims, including withheld/unresolved; zero claims gives null support
and a failed explanation. Missing cases cannot become perfect support. Visible
necessary facts/limitations exclude withheld claims. Critical false-claim IDs
are independent rubric input, not inferred labels from a detector. Per-case
rubric, unresolved disagreements, agreement/adjudication counts, all-attempt
cost and latency remain visible. P remains experimental and never enables prose.

Both summaries set product_acceptance=false. These source functions are not yet
wired into scripts/eval.py in this first package. Follow-on source integration
is separately granted to D6; generated schemas and actual execution remain
unperformed. Future independent tests must cover source/raw projection mismatch,
exact 20% equality, missing denominator/attempts, mock/replay provenance,
zero-success/unknown billing, withheld claims and empty generation.
