# Activate and validate after Dirty Mode

This repository is a source construction snapshot. No application, test suite, model/scanner experiment, package build or schema export has been run. Hand-authored demo files and fake transports demonstrate intended plumbing, not independent accuracy, compatibility, security or live-cost evidence.

The local product needs Python 3.12 and Pydantic v2. It does not need a listening server, database, container, Terraform apply or cloud account. Dependency ranges in pyproject.toml are not a resolved/audited lock. Later setup must resolve compatible versions, preserve the resulting lockfile and record actual tool versions. Do not infer tested producer support from parser target formats.

When Roy closes Dirty Mode through INT, use the recorded deferred list in the outer run status to order validation:

1. Resolve/audit dependencies and run the meaningful source tests that now exist. Establish parser, rule, evidence and private/shareable output semantics before benchmarking. Exercise a multi-resource wrong-evidence case, timeout with complete accounting, interrupted/failed export, masks/unknowns and exit precedence.
2. Exercise the keyless CLI and demo end to end with separate new output directories. Confirm the input is never modified/copied/executed, sensitive values remain masked, shareable output has no private identity/map, and aborted invocations cannot leave a finalized clean-looking report. Validate file races, cooperative deadlines and crash/restart accounting.
3. Appoint independent oracle author/checker and rubric assessors. Seal configuration and mutation lineage before tuning; keep hidden labels out of inference and implementation. Metadata validators check consistency; they do not authenticate independence. An exposed hidden edition remains consumed even if the run fails.
4. Pin scanner versions, executable/config/custom-policy hashes and supported mappings against development inputs. Checkov built-ins, action-aware custom checks and compatible Trivy remain separate arms with identical raw synthetic input and enrichment disabled. Missing tools/mappings are incomplete work, never true negatives or proof of incompatibility.
5. Keep fake model/scanner runs visibly ineligible for live measurements. Later L/P/M execution requires an approved provider/model/price/cap and all-attempt accounting; no approval follows from a driver accepting an injected transport. Pending timeout/unknown-cost liabilities block subsequent calls until explicit operator reconciliation.
6. Freeze the integrated build, schemas, prompts, mappings and rubric before the one-shot held-out run. Publish every failure/abstention, unresolved cost and missing arm. Finish independent nonauthoring product acceptance before any readiness claim. Publication, real accounts, spending and deployment need their own current authorization.

No generated schema, test output, screenshot or benchmark result is supplied as evidence by this document. The scorer's imported records and structural metadata do not independently prove the original execution. Keep private reports/plans and agent coordination material out of any future public repository.

## Product walkthrough and source handoffs

Use the [demo walkthrough](DEMO.md) only after the keyless journey is activated.
The [testing guide](TESTING.md) lists proposed outer-cwd-safe commands and remaining
checks. Do not run documentation examples while Dirty Mode is open.

The pinned viewer library is present: `verify_report(bundle, original_plan=None)`
and `view_evidence(bundle, original_plan, finding_id, fact_id)`. Main CLI
`verify-report BUNDLE [--plan PLAN]` and
`evidence BUNDLE --plan PLAN --finding ID --fact ID` wiring now exists in source.
Exercise it after activation; no observed successful invocation is claimed.
Bundle verification is integrity checking, not an authenticated producer or
product verdict. Private evidence stdout stays local and out of shared logs.

RunManifest/preflight/binary-scoring source and schema-export bindings now exist.
Exercise their integration before schema export or any integrated run. The report `manifest.json` is only the
local artifact/digest binding; it does not close experiment provenance, authentic
execution, consumed-edition custody or required arm completion. Reconcile model
and scanner bridges against the final scorer wire without promoting fake rows.
The preflight library reads allowlisted metadata, not plan/HTML/prompt/response
payloads. Its external pins/link checks do not authenticate the original execution.
No integrated `iac-review` preflight command or generated RunManifest is claimed.

Respect scorer target semantics during activation: full-outcome is the default;
binary introduced-risk predictions must not invent a full outcome. D exact checks
require full outcomes. Null binary predictions abstain; definite predictions on
indeterminate gold produce certainty errors. Retain v2 eligibility/pins and never
promote mocks/legacy rows to satisfy a missing measurement.

Use strict ProducerAccounting over D5 accounting_json plus every attempt snapshot,
including failed/no-row attempts, usage and pending liabilities. A row subtotal
cannot stand in for model total cost. Optional producer_exports consumes only the
exact allowlisted ExportBundle and remains live-ineligible. The operator ledger
CLI is still in progress; do not invent commands or infer its completion from the
existing start/terminal/reconcile library. Later activation must exercise the
actual completed interface and operator reconciliation boundary.

After later authorization, verify the new AST boundary-checker source and tests
before using its result. The intended checker reads default product source and
import edges without loading application modules; development scanner subprocess
code is deliberately outside its scope. Runtime dependencies/effects still need
the actual sandbox checks in step 2 above. No static pass replaces those checks.
