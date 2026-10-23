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

Shared `tests/eval/` and other `tests/contracts/` files belong to other leads.
Only the later explicitly granted `tests/contracts/test_product_boundaries.py`
belongs to this package; no other shared test was edited or validated.
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
scanner subprocess code is intentionally outside the product-package scan.
