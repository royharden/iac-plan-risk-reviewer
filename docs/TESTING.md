# Keyless development testing

## Recorded validation (2026-10-25)

An independently executed combined code snapshot, using Python 3.12.13,
Pydantic 2.14.1 and pytest 9.0.3, recorded:

| Check | Recorded result | Scope |
|---|---|---|
| Full development suite | 946 passed; zero failures, errors or skips | Public synthetic tests, including metadata/fake evaluation workflows |
| Public development matrix | 24/24 passed | Four-rule outcomes, evidence and privacy checks against declared public expectations |
| Host CLI journeys | 4/4 passed | Risk, clear, unknown and malformed paths; inspect/verify/share where applicable |
| Combined-code Docker journey | 24 public cases and 4 CLI journeys passed | Network-disabled, non-root, read-only Linux container; no host ports or mounts |
| Independent batch review | 50 batch and 222 compatibility checks passed | Ordered snapshot evidence, closure refusal, privacy/effects and report integration |
| Original large-CIDR case | 420 R1 facts, four source reads; completed through export within the unchanged 30-second budget | One synthetic 200-before/201-after-CIDR input; not a general performance guarantee |

These counts overlap and must not be added into a unique-case total. Source,
configuration, imports, test inputs and dependency versions were pinned for the
recorded runs. Re-run affected checks when those inputs change. The large case
recorded about 1.2 seconds from input through export in the full-suite run; machine,
filesystem and workload differences limit extrapolation.

Development tests include independently authored specification cases, but they are
not an independently sealed hidden oracle or a human productivity study. All seven
comparative arms D/L/P/M/C/C-custom/T remain NOT MEASURED. Genuine producer profiles,
held-out custody, live comparisons and final product acceptance remain incomplete.
A schema-valid receipt or imported result does not prove its original execution.

## Repeatable local commands

Run from the repository root. Use new output files/directories on every run;
existing output is preserved, and pytest temporary roots must also be fresh.
The dependency lock supports Python 3.12; the recorded patch version was 3.12.13.

```powershell
uv sync --frozen --python 3.12.13
New-Item -ItemType Directory -Force reports | Out-Null
uv run --frozen pytest tests -p no:cacheprovider --basetemp reports/pytest-tmp-01 --junitxml reports/pytest-01.xml
uv run --frozen python -m evals.run_public --out reports/public-dev-01.json
uv run --frozen python -m evals.docker_journey
```

The last command runs the four public CLI journeys on the host despite its module
name. Actual container construction uses the separate `scripts/docker_e2e.ps1`,
which requires an explicitly pinned base image and a valid local resource claim;
it is not needed for ordinary review. Its machine-specific registry parameters
must be configured by the environment owner, not copied from another machine.
The container test's offline runtime does not imply that dependency installation
or image building is network-free.

For an evidence-producing PowerShell subset runner:

```powershell
pwsh -File scripts/check_local.ps1 -Python .venv/Scripts/python.exe -EvidenceDirectory reports/check-local-01
```

`check_local.ps1` selects its own repository, binds that source into PYTHONPATH,
requires Python 3.12 and a fresh evidence directory, and records dependency
inventory, candidate, command, log, JUnit and exit status. Its subset excludes
`tests/eval` and `tests/corpus`; it is not the full-suite command above. Read the
collected/executed counts and failures in the reporter, rather than treating an
exit code or zero collected cases as a pass. Confirm imports belong to the chosen
checkout when using a shared interpreter. Duplicate module basenames require the
configured importlib mode.

## Coverage and boundaries

| Tests | Main checks |
|---|---|
| `tests/ingest/` | Ordered actions, deposed identity, duplicates, strict JSON/UTF-8, limits, missing flags and unsupported versions |
| `tests/evidence/` | Masks, exact JSON types, pointers, checked absence, digest/identity mismatch, standalone reopening and atomic batch closure |
| `tests/rules/` | Public R1-R4 truth boundaries, IPv4/IPv6 transitions, short circuits and explicit unsupported coverage |
| `tests/report/` | Foreign-reference withholding, duplicate/ordered batch positions, privacy canaries, escaping, exit precedence and ABORTED publication |
| `tests/source_view/`, `tests/shareable/` | Bound/legacy inventory, tamper refusal, explicit source pin and safe regeneration |
| `tests/integration/`, `tests/e2e/` | Real CLI paths, occupied outputs, source mutation, finite fallback and default effect guards |
| `tests/attempts/` | Conservative all-attempt accounting, unknown liabilities, replay and reconciliation |
| `tests/contracts/` | Closed wires, source boundaries, schema export and version/legacy compatibility |
| `tests/eval/` | Public metadata/fake scoring, exposure, handoff and release-admission boundaries; no genuine hidden edition |

The batch cases in `test_report_batch_transaction.py` and `test_batch_consumer.py`
exercise entry/exit reads, deadlines, duplicate references, stale `plan.raw`,
mutation/link/read failures and positional association. Standalone `resolve`
still reopens per call. A transient change restored between observations may be
missed; [the transaction boundary](EVIDENCE-BATCH.md) makes no continuous-monitoring
claim. Neither deadlines nor passed cases prove every OS race or crash outcome.

Default-path effect guards deny common Python network/process paths and inspect
synthetic input/output footprints. They do not constitute an OS sandbox or prove
all native/dependency effects absent. The bounded source-policy checker reads a
fixed product tree, parses AST/import edges and emits explicit findings for
forbidden effects, dynamic loading and incomplete scans:

```powershell
uv run --frozen python scripts/check_source_boundaries.py
```

Its 0/1 exits mean no static-policy findings/findings, separately from product risk
exits. Evaluation scanner code is outside that product scan. Reflection, native
code, dependency behavior and filesystem races remain limits.

## Schemas, demo and remaining evaluation work

Schema export and its fixed-registry tests have executed. To generate descriptions
into a new directory with an existing parent:

```powershell
uv run --frozen python scripts/export_schemas.py --out reports/schemas-01
```

The catalogue has 121 declarations and export-manifest version 2. Descriptive
schemas, especially dataclasses and nested Any/dict fields, do not replace actual
validators, privacy checks, payload admission or actor/execution authentication.
Bound report inventory 1.1.0 remains distinct from legacy unbound inventory 1.0.0;
provenance profiles 1 (nine files) and 2 (eleven files) are not silently migrated.

The [synthetic demo](DEMO.md), safe sharing and schema tests pass in development.
Held-out exposure/authorization, frozen-run, scoring-handoff and consumed-edition
regressions use synthetic metadata only. A real edition still needs independent
oracle author/checker and rubric assessors, genuine external pins, sealed lineage,
input exposure before access, post-measurement results receipts, all seven genuine
arms and all-attempt accounting. Missing/mock/failed/unknown results are retained;
none becomes a measured negative, true negative or completed comparison by default.
See [activation](ACTIVATION.md), [compatibility](COMPATIBILITY.md) and
[limitations](LIMITATIONS.md). No test command grants hidden access, provider calls,
spending or publication.
