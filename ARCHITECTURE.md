# Architecture

Status: construction source. Nothing described here has been imported, executed or
tested; see the status section of the [README](README.md). This file maps the source as it
exists, not verified behavior.

## Product review pipeline (`src/iac_review/`)

The review path is a chain of pure stages joined by strict, frozen, closed Pydantic v2
records (`strict=True`, `extra="forbid"`):

```
plan file -> ingest -> rules -> evidence -> report -> write_report -> bundle
                                         \-> (optional) explain: finite selection only
```

| Module | Responsibility |
|---|---|
| `contracts/__init__.py` | Core wires: `PlanIdentity`, `ResourceChange`, `ValueState`, `EvidenceRef`, `RuleEvaluation`, and the `ReviewReport` dictionary facade, which validates through `report_wire` and refuses non-canonical input |
| `contracts/manifest.py` | Payload-free `RunManifest` and shared types (`Digest`, `Arm`, `Split`); metadata, not authentication |
| `contracts/report_wire.py` | Canonical private/shareable report projections, a separate legacy (unbound) private type, strict JSON ingress and pair checks |
| `contracts/report_inventory.py` | Bundle inventory types: bound manifest 1.1.0 (8 files), legacy 1.0.0 (7 files), `COMPLETE`/`ABORTED` export markers, `classify_bundle` |
| `ingest/` | Bounded local bytes, raw SHA256, strict JSON, ordered actions and deposed identity, format/coverage inventory; never runs Terraform or HCL |
| `rules/` | R1-R4 applicability, outcome, severity and reason codes; unknown required facts stay indeterminate |
| `evidence/` | Reopens only the digest-pinned document; resolves RFC 6901 pointers with mask, side and identity checks (`resolved`, `unknown`, `sensitive`, `missing`, `mismatch`) |
| `report/` | `build_report`: binds references to their resource, withholds unverified decision evidence (outcome becomes indeterminate), computes exit precedence, builds both projections and escaped HTML; `write_report` stages and publishes the bundle |
| `provenance.py` | `ReportProvenance` descriptor (`run-manifest.json`) pinning installed core source files; source profile v2 (ten files, including `report_wire.py`) is current, while v1 (nine files) descriptors keep verifying against v1 |
| `source_view.py` | Read-only verification of COMPLETE bundles; legacy bundles stay explicitly unbound; one selected fact via an explicitly supplied original plan |
| `shareable_export.py` | Regenerates safe-only output with fresh IDs from a bound private bundle and the original plan; no retained mapping |
| `explain/` | Validates finite template/fact/limitation selections; deterministic fallback; cannot change a rule outcome |
| `attempts/`, `ledger_cli.py` | Single-worker append-only attempt journal with conservative unresolved liabilities; read-only status and pinned reconciliation (no retry or unlock) |
| `cli.py`, `__main__.py` | `inspect`, `verify-report`, `evidence`, `share`, `explain`; no provider, scanner, network or shell path |

Import direction for the report types: `provenance` imports `contracts` and
`contracts.manifest`; `contracts.report_wire` imports those plus `provenance`;
`contracts.report_inventory` imports `report_wire`, `contracts.manifest` and `provenance`.
`contracts/__init__.py` imports `report_wire` lazily, so there is no cycle. `report_wire` never imports `report/`,
`rules` or `source_view`.

### Export protocol

`write_report(report, out, *, deadline=None)` writes `export-state.json` as
`{"state": "ABORTED", "reason": "export_not_finalized"}` first, stages every artifact under
`.pending/`, publishes with exclusive creation, and finally replaces the marker with
`{"state": "COMPLETE", "exit_code": N}`. On failure it removes only paths it created.
`manifest.json` hashes the payloads (the four reports and `run-manifest.json` in a bound
bundle) and `manifest.sha256` hashes the manifest. Deadlines are cooperative between
operations; this is not proven crash durability. Formats are in
[report wire](docs/REPORT-WIRE.md).

## Development evaluation harness (`eval/`, `scripts/`)

Separate from the product package and never imported by the review path. It consumes
independently supplied labels and measurements; it does not derive gold from detectors.

| Package | Responsibility |
|---|---|
| `eval/model/` | D/L/P/M arm orchestration (`experiment`, `driver`), injected `transport`, finite selector adapter, private P prose capture and manual annotation wires, payload-free provenance (always live-ineligible for mock/protocol transport), and a disabled provider path (`provider_wire`, `provider_http`, `provider_activation`) that needs external activation pins and a durable journal start |
| `eval/scanners/` | Opt-in C/C-custom/T comparison: fixed-argument `runner`, Checkov and Trivy plan adapters, capability metadata, synthetic development inputs, `run_manifest` adapter and a target-aware `scoring_bridge`. This package contains subprocess capability; its presence authorizes nothing |
| `eval/runner/` | Custody and scoring: `custody` (authority, seal, semantic and post-measurement exposure receipts), `preflight` (read-only metadata/link checks; never opens payloads), `exposure_journal`, `benchmark` (fixed seven-arm development coordinator), `benchmark_access`, `frozen_run`, `scoring_handoff`, `scoring` (pure scorer over oracle and arm rows), `utility`, `model_bridge`, `fact_mapping`, `bundle`, `assessment_import`/`assessment_batch`, `edition_release`, `results`, `schema_registry` |

`scripts/` holds the thin entrypoints for these (for example `eval.py`, `run_benchmark.py`,
`run_frozen_benchmark.py`, `record_exposure.py`, `eval_model.py`, `eval_scanners.py`,
`prepare_consumed_edition.py`, `demo.py`, `export_schemas.py`,
`check_source_boundaries.py`). None has run.

## Held-out exposure: two events, two records

A held-out run passes through two distinct, separately recorded exposure events:

1. **Pre-access input exposure** (`eval/runner/exposure_journal.py`). Before any held-out
   case input is read, the custodian commits `InputExposureReceipt` rows
   (`m4-input-exposure-v1`) for all arms. They bind per-arm *measurement intents*
   (`measurement_intents_sha256`, a hash of declared intent/config), never result hashes,
   together with edition, authority, seal and build pins. A partial commit stays blocked
   until a custodian resolves it; editions are never rolled back or reused.
   `verify_committed_exposure` checks the exact authorization and commit digests and
   returns the committed `InputExposureCommit`.
2. **Post-measurement, pre-oracle exposure** (`eval/runner/custody.py::ExposureReceipt`).
   After the frozen run, `measurements_sha256` is the SHA256 of the actual measured-results
   file. `scripts/eval.py` checks it before decoding the oracle.

**Input access** (`benchmark_access.py`, `HeldoutAuthorization` schema
`m4-heldout-input-access-v2`, which binds intents, not results) always requires a verified
committed input-exposure record whose authorization, commit, receipt file and per-arm intent
digests match the explicit permission, for the same run and edition, with no payloads opened.
In addition the edition state must be either the legacy `consumed_holdout`, or `sealed` with
`preflight` reporting `input_exposure_committed`. `preflight` reads the journal read-only and
creates no new manifest state; `frozen_run` also verifies the commit before the gate. Input access covers case inputs only; the oracle is never readable there,
and a committed input-exposure record is never oracle, scoring or tuning permission.

## Frozen run and scoring handoff

`frozen_run.run_frozen` requires the committed input exposure and explicit payload
permission, takes one in-memory input snapshot, and reuses the existing coordinator,
transport and runner. `scoring_handoff` then turns the private outcome into:

1. the immutable measured-results file (LF-terminated canonical ArmRow JSONL, every row
   kept, including failed and unknown);
2. a pinned `ScoringHandoff` (`m4-scoring-handoff-v1`) inventory of every required case x
   arm status, error and unknown state, plus cumulative journal accounting; incomplete arms
   stay INCOMPLETE;
3. the seven post-measurement `ExposureReceipt` rows carrying the actual results hash.

Oracle access happens only through the separately authorized `scripts/eval.py` path.
Scoring separates `prediction_target="full_outcome"` from binary `"introduced_risk"`;
a binary prediction never fabricates a full outcome, and model totals require every
attempt, including failed and no-row attempts. `edition_release` prepares a consumed
edition only from externally pinned completion references for all seven arms.

## Boundaries that remain unverified

Hash and metadata agreement do not authenticate a producer, an execution or oracle
independence. The bounded AST boundary checker (`scripts/check_source_boundaries.py`)
has not run and is not a runtime sandbox. See [limitations](docs/LIMITATIONS.md) and
[testing](docs/TESTING.md).
