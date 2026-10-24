# IaC Plan-Risk Reviewer

Review a saved Terraform JSON plan locally with four bounded AWS change rules. Findings retain verified before/after evidence; unknown or unsupported input stays visibly inconclusive.

**Construction snapshot — runtime unverified.** Source was built under Roy's Dirty Mode instruction. No dependency installation, product execution, tests, scanner runs or provider calls have occurred. Commands below describe the intended activation journey after that mode closes; they are not execution evidence. No remote repository has been created.

## Quickstart after authorized activation

Use Python 3.12 and uv after the activation owner authorizes environment setup. Resolve and audit dependencies and retain a legitimate `uv.lock`; resolution is deferred in this snapshot. These future commands keep the shell in the outer project directory and select this inner product explicitly:

```powershell
uv sync --project .\iac-plan-risk-reviewer
uv run --project .\iac-plan-risk-reviewer iac-review inspect .\iac-plan-risk-reviewer\fixtures\demo\public-ssh.json --out .\iac-plan-risk-reviewer\reports\public-ssh
```

Require `reports/public-ssh/export-state.json` to say `COMPLETE` before opening or copying reports. An `ABORTED` marker or pending remnants are not a completed invocation. A successful risk review deliberately returns exit 1; coverage uncertainty returns 2. Neither is a command-crash signal.

Open the inner `reports/public-ssh/private.html` locally. It is sensitive: exact resource addresses and JSON pointers are intentional. Use the explicit [share exporter](docs/SHARING.md) with the original plan and a fresh separate destination. It verifies a COMPLETE bound bundle/current source pins, then regenerates canonical safe files with fresh IDs. Never share the whole private/demo directory. Marked values remain masked. Intended default behavior runs no Terraform/apply, model, scanner, server or cloud SDK. It does not copy the source plan into a report. Runtime effect/privacy validation remains pending.

Expected by policy, not observed output: standalone ingress opening TCP/22 to `0.0.0.0/0` produces R1 introduced risk with exact source references. HTTPS/443 alone is outside R1's admin-port predicate. Unknown required facts produce an indeterminate result. Follow the [two-minute synthetic walkthrough](docs/DEMO.md), [activation order](docs/ACTIVATION.md) and [limits](docs/LIMITATIONS.md).

## Rules and signals

| Rule | Declared change predicate | Severity |
|---|---|---|
| R1 | Standalone `aws_security_group_rule`: new world IPv4/IPv6 exposure on 22 or 3389 | 4 |
| R2 | `aws_db_instance.publicly_accessible` newly true | 3 |
| R3 | RDS/EBS encryption flag true → false | 3 |
| R4 | Existing RDS/EBS delete or either ordered replacement | 4 |

Unchanged declared risk remains visible and counts toward the severity threshold. Default `--fail-on 3`. Exit precedence is 3 malformed/internal error, 2 unsupported/inconclusive required coverage, 1 threshold risk with otherwise complete coverage, 0 complete named scope without threshold risk. `risk_present` remains true when risk coexists with exit 2. These signals do not certify infrastructure safety, deployed state, routing, backup availability or apply success.

## Architecture

`ingest` bounds and validates local JSON → `rules` evaluates frozen predicates → `evidence` resolves exact pinned source facts → `report` produces escaped self-contained artifacts. Strict frozen Pydantic v2 records connect these stages. Optional `explain` accepts finite template selections only; it cannot change a finding. `attempts` implements a single-worker append-only accounting contract. Product review source has no model/network/process/scanner entrypoint. Separate development provider source is disabled by default and requires external admission plus an active journal start. It has not run; the ordinary model CLI remains explicitly fake-only.

Development evaluation sources live in `eval/` and `scripts/`, outside default product imports. They consume independently supplied labels/measurements; they do not manufacture gold from detectors. See [evaluation](docs/EVALUATION.md), [compatibility](docs/COMPATIBILITY.md) and [architecture](ARCHITECTURE.md).

## Source entrypoints

These interfaces exist as source; none is claimed executed or accepted at runtime.

| Entry | Current source behavior / activation boundary |
|---|---|
| `iac-review inspect PLAN --out DIR [--fail-on 1..4]` | Parser → rules → pinned evidence → private/shareable static reports; staged output finalized by local marker |
| `iac-review explain SHAREABLE --finding ID --selection FILE` | Validate an offline finite selection; exit 0 accepted, 2 deterministic fallback, 3 malformed input; no implicit model call |
| `iac-review verify-report BUNDLE [--plan PLAN]` | Confirm complete local bundle/hash integrity; optional explicit source digest check; exit 0 integrity result or 3 failure, not a risk verdict |
| `iac-review evidence BUNDLE --plan PLAN --finding ID --fact ID` | Resolve one selected safe fact; stdout deliberately contains private exact locations and must stay local; exit 0 or 3 |
| `iac-review share BUNDLE --plan PLAN --out DIR` | Regenerate safe-only output from bound current source/config pins; preserve review exit 0/1/2, refuse with 3 |
| `iac_review.source_view.verify_report(bundle, original_plan=None)` | Verify COMPLETE bundle/hash integrity and optionally an explicitly supplied source digest; does not authenticate the producer or prove rule correctness |
| `iac_review.source_view.view_evidence(bundle, original_plan, finding_id, fact_id)` | Reopen only the explicitly supplied pinned plan; return one mask-safe fact with a clearly private exact location |
| `scripts/demo.py --fake --synthetic --out DIR` | Fixed four-case PRIVATE offline journey, strict viewer/finite fallback/mock journal; all seven arms NOT MEASURED |
| `scripts/eval_model.py` | Explicit `--fake` synthetic D/L/P/M plumbing with bounded journal/provenance; mock/protocol results are live-ineligible and completed plumbing returns 2 |
| `scripts/eval_scanners.py` | Explicit manifest/output and pending/fake-only/live modes; live runner source requires separate runtime authorization and confinement, unavailable under construction |
| `scripts/eval.py` | Import independently supplied oracle/measurements plus pinned custody, seal, semantic, eligibility and utility records; no bundled hidden corpus or invented results |
| `iac_review.contracts.manifest.RunManifest`; `eval.runner.preflight.preflight(root, manifest, pins)` | Closed run metadata and explicit read-only metadata preflight source; verifies declared links/pins, not payload truth or execution authenticity |
| `scripts/ledger.py status JOURNAL`; `scripts/ledger.py reconcile ...` | Explicit bounded read-only status/pinned append-only receipt reconciliation source; no retry/unlock/provider; see [ledger](docs/LEDGER.md) |
| `scripts/prepare_consumed_edition.py` | Externally pinned local consumed-synthetic candidate gate; no inference/publication; see [consumed editions](docs/CONSUMED-EDITIONS.md) |
| `scripts/export_schemas.py --out DIR` | Explicit schema-export source, not generated schemas or evidence that every validator is represented |
| `scripts/check_source_boundaries.py [--package PATH]` | Bounded stdlib AST/import-graph policy source for `src/iac_review`; not executed, not a runtime effect sandbox |

The viewer CLI wiring, RunManifest/preflight library source, explicit binary introduced-risk scoring target and schema-export bindings are now present in source; none has runtime evidence. No integrated preflight `iac-review` command is advertised. The local report `manifest.json` is a separate artifact: it hashes reports and binds the plan digest; it is not the experiment RunManifest. Self-consistent hashes and imported metadata do not authenticate execution.

Scoring distinguishes `prediction_target="full_outcome"` from binary
`"introduced_risk"` with `introduced_prediction`. A binary prediction cannot
invent a full outcome; null abstains and indeterminate gold can expose certainty
errors. D exact agreement still requires full outcomes. Model totals require
all-attempt producer accounting, including failed/no-row attempts and pending
liabilities; row subtotals alone are partial. Imported fake producer exports remain
live-ineligible; no producer change should fabricate eligibility.

## Results and cost

[Results status](results/README.md) records all seven required arms D/L/P/M/C/C-custom/T as **NOT MEASURED**. No precision, recall, speed, cost/success or productivity result is claimed. A synthetic fixture or mock does not close a live measurement obligation. There were no provider attempts in this construction phase; runtime costs and performance remain unmeasured.

## Limits and verification

Only managed canonical AWS resources in the named shapes are intended. JSON formats 1.0/1.1/1.2 are parser targets; none has yet been fixture-tested here. Inline/newer SG shapes, database ports, broader stateful types, IAM and cross-resource reachability remain outside this edition. Missing completeness flags remain unknown. Real Terraform/AWS producer pins, dependency lock/audit, independent oracle, semantic assessors, scanner mappings and live provider budgets remain open.

Coding agents wrote this source and [development regression source](docs/TESTING.md). Actual verification is limited to static syntax parsing and focused source inspection; no passing test, runtime or security assurance follows. Independent final product acceptance, licensing and publication remain pending.
