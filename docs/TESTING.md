# Core regression activation

Dirty Mode authored regression-test source only. No tests, application imports,
dependency installation, runtime effects or compatibility checks have run in this
package. Syntax parsing and source review do not establish passing tests.

These are development regressions against the frozen public policy. Expected
outcomes and synthetic builders were authored in the implementation lineage.
They are not the independently authored hidden oracle, consumed holdout edition,
producer/provider provenance or independent final product acceptance. Illustrative
Terraform version strings in test inputs do not claim tested compatibility.

| Source group | Meaningful boundaries |
|---|---|
| `tests/ingest/` | Action order, deposed/duplicate identity, duplicate JSON keys, invalid UTF-8/nonfinite/depth, malformed versus unsupported actions, missing flags/minor version |
| `tests/evidence/` | Null/absent/unknown/sensitive, ancestor masks, checked absence, escaped pointers, digest/resource/side/value mismatch, mutation |
| `tests/rules/` | Small R1–R4 public truth-boundary examples, IPv4/IPv6 exposure transitions, unknown short circuits, unsupported coverage, no context suppression |
| `tests/report/` | F1 resource binding, F3 export finalization, canary projections/HTML escaping, risk/coverage/threshold/no-change precedence |
| `tests/explain/` | Required facts/limitations, reversed relation, foreign IDs, forbidden outcome field, oversized output and deterministic fallback |
| `tests/attempts/` | F2 timeout pending/replay/conservative accounting and explicit reconciliation |
| `tests/integration/` | CLI 3/2/1/0, finalization deadline, occupied output, default model/network/process guards, mutation abort, offline explain boundary |

Shared `tests/eval/` and other `tests/contracts/` files generally belong to other
leads. D7 has individual grants for its annotation/assessment bridge tests,
`tests/eval/test_edition_release.py` and `tests/contracts/test_product_boundaries.py`;
no directory-wide ownership or independent acceptance follows.
`tests/conftest.py` supplies only uniquely prefixed
`core_change`/`core_plan_file` helpers; no global autouse behavior or environment
mutation affects other test groups.

## Later commands, after Dirty Mode closes and INT authorizes activation

Resolve/audit dependencies and a legitimate lock under INT's activation package
first. The commands below are proposed future execution, not an instruction to
run setup or tests during construction. Keep the shell cwd at the outer shell;
the package invocation can select the inner project explicitly:

```powershell
uv run --project .\iac-plan-risk-reviewer pytest --import-mode=importlib `
  .\iac-plan-risk-reviewer\tests\ingest `
  .\iac-plan-risk-reviewer\tests\evidence `
  .\iac-plan-risk-reviewer\tests\rules `
  .\iac-plan-risk-reviewer\tests\report `
  .\iac-plan-risk-reviewer\tests\explain `
  .\iac-plan-risk-reviewer\tests\attempts `
  .\iac-plan-risk-reviewer\tests\integration
```

Use importlib mode because several owned and shared test directories can have
matching module filenames without Python package markers. Packaging/import path,
actual pytest availability and dependency pins remain unverified; if activation
cannot resolve `iac_review`, INT must configure the audited package environment
rather than modifying test expectations or silently using another checkout.
Record exact source hash, dependency/producer profiles, collected/run counts,
failures and actual commands before claiming a test pass. Zero collected cases
and AST-only checks are not passes.

The effect guards deny common Python network/process call paths and inspect the
synthetic input/output footprint. They are bounded regression guards, not an
OS sandbox or proof against every native side effect. Later independent effect
validation must deny process/network use at the environment boundary and check
authorization, journal crash/concurrency, filesystem races and report privacy.

Before consuming reports, verify local `export-state.json` is COMPLETE. ABORTED
or pending remnants are not completed invocations. Later activation must exercise
real rendering/write failures and deadline behavior on the target filesystem,
including cleanup refusal and process termination. Static source cannot establish
those outcomes. No model/scanner measurement, paid request, hidden corpus access
or publication is authorized by this document.

## Bounded source-policy checker (authored, not run)

`scripts/check_source_boundaries.py` reads only a selected `iac_review` package,
parses syntax and builds local import edges without loading application modules.
It limits files, file/total bytes, AST nodes, directory depth and visited entries;
an incomplete scan is an explicit finding. Default graph roots are `iac_review`
and `iac_review.cli`. Source checks cover all discovered product modules, including
lazy imports; graph closure overapproximates runtime loading and is not an observed
module inventory. The intentional `__main__` command module is excluded only
from import-time declaration checks. Network/process/cloud imports, selected
dynamic/effect calls, missing local modules and nondeclarative import-time
statements/mutations are findings. Unknown external dependencies are rejected;
standard-library declarations and Pydantic are not dependency audits.

Exactly `tests/contracts/test_product_boundaries.py` is this checker package's
new contract test. Other contracts tests belong to another lead and were untouched.
The synthetic cases include transitive import edges, forbidden imports/dynamic
loaders, top-level effects, allowed declarations/main guard, dev-harness exclusion
and a bounded-scan failure. Neither checker nor these tests was executed.

For later separately authorized activation, the outer-cwd-safe interfaces are:

```powershell
python .\iac-plan-risk-reviewer\scripts\check_source_boundaries.py
uv run --project .\iac-plan-risk-reviewer pytest --import-mode=importlib .\iac-plan-risk-reviewer\tests\contracts\test_product_boundaries.py
```

The checker prints a static report to stdout, with 0 for no policy findings and
1 for findings. Those exit meanings are distinct from product risk exits. No clean
checker result has been observed. Declarative dataclass/Pydantic/regex calls are
trusted syntax; aliases/rebinding, reflection, generated/native code, dependency
behavior and filesystem races prevent this from proving runtime isolation. Dev
scanner/provider/edition harness code is intentionally outside the product-package
scan. A product import of evaluation code remains forbidden even when lazy. Direct
product environment lookup is a finding. The checker neither inspects nor admits the
disabled external provider nor grants authorization or publication.

## Demo, safe export and consumed-edition source

[Demo](DEMO.md) requires fake/synthetic flags and a PRIVATE root marker, with strict
viewer, finite fallback, mock journal and declared scanner capabilities.
[Sharing](SHARING.md) requires the original plan/current bound core pins and
canonical regeneration into a fresh safe-only directory. Focused sources:
[demo journey](../tests/integration/test_demo_journey.py) and
[share exporter](../tests/shareable/test_export.py). Neither has run.

[Consumed-edition preparation](CONSUMED-EDITIONS.md) has separate external release
and completion pins. Missing/mock/not-run arms cannot close it; measured
negative/unknown/error results and costs remain. Its [regressions](../tests/eval/test_edition_release.py)
are public metadata examples, not custody, oracle labels or release evidence.
The [ledger](LEDGER.md) and [disabled provider](PROVIDER-ACTIVATION.md) now have
source interfaces; ordinary model CLI stays fake-only and product review offline.

Additional future authorized selection, from the outer shell:

```powershell
uv run --project .\iac-plan-risk-reviewer pytest --import-mode=importlib `
  .\iac-plan-risk-reviewer\tests\shareable `
  .\iac-plan-risk-reviewer\tests\eval\test_edition_release.py `
  .\iac-plan-risk-reviewer\tests\contracts\test_product_boundaries.py
```

Do not run under open Dirty Mode. A later positive edition test needs separately
approved independent records and exact-copy/privacy/failure/cost/expiry/rollback/
crash checks. Tiny metadata examples cannot close that obligation. All seven arms
remain NOT MEASURED.

## Fixed schema descriptions and compatibility

The [actual-wire registry](../eval/runner/schema_registry.py) and
[exporter](../scripts/export_schemas.py) remain unexecuted source. Their focused
[export regressions](../tests/contracts/test_schema_export.py) and
[registry/compatibility regressions](../tests/contracts/test_schema_registry.py)
cover fixed canonical types, missing/duplicate/version conflicts, private versus
shareable-shape classification, data-only catalogue without application imports,
legacy exporter API/--out retention, explicit unsupported versions, closed root
unknown fields, partial-write ABORTED state and detached catalogue/file hashes.

Compatibility cases distinguish seven-file legacy report inventory 1.0.0 from
eight-file bound 1.1.0; changing a version cannot retain the wrong inventory or
upgrade a legacy bundle's trust. They also distinguish deterministic RunManifest
from schema-valid evaluation declarations requiring separate preflight admission.
Batch transport requires its exact explicit version; dataclass descriptions do not
gain strict/unknown-field rejection from being listed. Dictionary report projections
and private fields excluded by serialization remain documented schema limits.

Future selection after authorization, with outer cwd unchanged:

```powershell
uv run --project .\iac-plan-risk-reviewer pytest --import-mode=importlib `
  .\iac-plan-risk-reviewer\tests\contracts\test_schema_export.py `
  .\iac-plan-risk-reviewer\tests\contracts\test_schema_registry.py
```

No test, import or schema generation was run. Later activation must inspect real
validation/serialization schema output and references, aliases/strictness/custom
validators, frozen dataclass limitations, version drift and filesystem failures.
See [schema source documentation](schemas/README.md). Descriptions never admit
payloads, authenticate actors/execution or authorize provider/release activity.
