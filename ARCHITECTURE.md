# Architecture

The product accepts one bounded saved JSON file. Ingress retains a raw-byte digest and ordered resource changes, distinguishes missing/null/unknown/sensitive values, and rejects malformed structures. Rule evaluation emits one of introduced risk, unchanged risk, clear or indeterminate, independently of any model. Coverage records remain separate from those outcomes.

Evidence uses RFC6901 locations in that pinned local document and checks masks and identity. Decision evidence must resolve before a determinate finding can ship; missing optional evidence removes that fact and adds a limitation. The source is reopened only locally, with digest checks; it is never executed, fetched or embedded wholesale.

Private reports preserve exact addresses and pointers as an explicitly sensitive local artifact. Shareable reports and model capsules contain random IDs and whitelisted typed facts, excluding addresses, pointers, filenames, tags, arbitrary strings and private mappings. HTML escapes all text and loads no external assets.

The default CLI is read/export only. No Terraform, cloud SDK, subprocess, network, database or server is part of the review pipeline. A future optional provider transport has a separate approval boundary and all-attempt budget journal; finite selectors cannot mutate rule outcomes. Free prose and model-only prediction remain isolated experimental arms.

Evaluation sources import independently authored gold and measured rows. A fresh hidden corpus must be independently sealed and lineage-disjoint before tuning; it is consumed after exposure. Detector authors have supplied no hidden oracle here. Static construction acceptance does not close release acceptance.

## Source map and boundaries

| Stage | Canonical source | Responsibility |
|---|---|---|
| Wires | `src/iac_review/contracts/` | Strict/frozen/closed Pydantic records; raw input is not a report wire |
| Ingress | `src/iac_review/ingest/` | Regular bounded local bytes, SHA256, action order/deposed identity, malformed rejection and coverage inventory |
| Decisions | `src/iac_review/rules/` | Fixed R1–R4 applicability/outcome/severity; unknown required facts remain indeterminate |
| Evidence | `src/iac_review/evidence/` | Reopen pinned bytes; verify resource, side, pointer, masks and expected value state |
| Report | `src/iac_review/report/` | Bind references to their evaluation resource, withhold failed required evidence, aggregate exit precedence, allowlisted projections and escaped HTML |
| Private viewer | `src/iac_review/source_view.py` | Verify the closed COMPLETE bundle inventory; optionally check source digest and one explicitly selected private fact |
| Explanation | `src/iac_review/explain/` | Finite relation/polarity/ID/limitation validation; deterministic fallback and immutable rule decisions |
| Accounting | `src/iac_review/attempts/` | Exclusive worker, durable starts/reservations and terminal history; every unreconciled timeout blocks subsequent calls |

`write_report(report, out, *, deadline=None)` preserves two-argument consumers.
CLI supplies the whole-review monotonic deadline; other callers receive a separate
export budget. The writer installs ABORTED first, stages artifacts, checks time
between operations, then atomically publishes COMPLETE last. Exceptions remove
only created artifact paths where cleanup succeeds. A killed process or refusing
filesystem can leave remnants; ABORTED remains authoritative. This is a cooperative
source protocol, not proven crash durability or preemptive I/O cancellation.

The report manifest hashes the exact four report artifacts and pins parser/policy
and plan identity. Private/shareable rows join through random finding/fact/resource
IDs. The local private mapping resolves those IDs to exact locations; shareable
IDs alone cannot reopen raw source. `verify_report` verifies integrity, not detector
truth, trusted producer identity or independent acceptance. `view_evidence` takes
an explicit original-plan path, rechecks its digest and exposes only a selected
allowlisted fact rather than an unrestricted raw-document viewer.

## Development evaluation, outside default imports

`eval/model/` contains injected fake/protocol transport, isolated M/P inputs,
finite L validation, all-attempt provenance and synthetic driver source. Mock or
protocol transport is always live-ineligible. P prose is transient experimental
material for later independent rubric assessment; it cannot enter product decisions.

`eval/scanners/` contains fixed-argument bounded runner/adapters, comparison rows
and a scorer import bridge for C/C-custom/T. This separate harness deliberately
contains subprocess capability. Its existence does not authorize execution or make
the default product launch a scanner. Hashes/mapping receipts alone do not prove
that a tool ran, or that a configuration PASS represents an action transition.

`eval/runner/` owns imported oracle/ArmRow scoring, custody/consumed-edition metadata,
utility and all-attempt model bridges. It must retain missing measurements and
abstentions. No hidden oracle is supplied here. `contracts/manifest.py` now declares
RunManifest and `eval/runner/preflight.py` exposes explicit read-only metadata/link
validation. Preflight reads only allowlisted metadata, not plan/HTML/prompt/response
payloads, and requires external pins. The scorer explicitly separates full-outcome
predictions from binary introduced-risk predictions. These sources and schema-export
bindings exist but have not run; report manifests remain separate from integrated
experiment run metadata. Hash/metadata consistency is not execution authentication.

ArmRow defaults to `prediction_target="full_outcome"` with
`introduced_prediction=None`. The explicit introduced-risk target accepts Boolean
introduction predictions without fabricating a complete outcome; null is an
abstention and a definite answer on indeterminate gold is a certainty error. D
exact correctness remains full-outcome only. V2 eligibility/pins still apply;
legacy/mock records are not promoted by the new target.

`ProducerAccounting` consumes D5's `accounting_json` and every immutable attempt
snapshot, including failed attempts and attempts without scorer rows. Model totals
are absent without that all-attempt account; row subtotal is explicitly partial.
Optional `UtilityRequest.producer_exports` consumes the exact ExportBundle
allowlist and remains live-ineligible. No producer change is needed merely to
invent eligibility. The accounting library is present; its operator ledger CLI
remains in progress and is not documented as an available command.

`scripts/check_source_boundaries.py` contains a bounded stdlib checker for product AST/import edges
without importing product modules. It excludes the development scanner harness.
Even a clean static result cannot establish dependency behavior, runtime effects,
authorization, filesystem confinement or product acceptance. See [testing](docs/TESTING.md)
and [activation](docs/ACTIVATION.md) for the later evidence boundary. Its source and
synthetic contract-test source exist; neither checker nor tests have run.
