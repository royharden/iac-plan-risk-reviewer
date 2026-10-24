# IaC Plan-Risk Reviewer

A local reviewer for saved Terraform JSON plans. It evaluates four bounded AWS change
rules and links every finding to before/after facts in that exact input file. Unknown or
unsupported input stays visibly inconclusive. A model may later explain a finding; it can
never create, delete, reprioritize or clear one. The report never says infrastructure is
secure or reflects deployed state.

## Status: source construction only, nothing has run

Read this before anything else.

- This source was written by coding agents in a static-only construction phase. **No
  dependency has been installed and no code has been imported, executed or tested.** The
  only checks performed were syntax parsing and focused source inspection.
- The regression tests under `tests/` are authored source; **none has run**, so none passes.
- No Terraform, AWS provider or JSON format version is claimed as tested. Version lists in
  [compatibility](docs/COMPATIBILITY.md) are parser targets, not test results.
- All seven evaluation arms (D, L, P, M, C, C-custom, T) are **NOT MEASURED**. No
  precision, recall, latency, cost or productivity result exists. See [results](results/README.md).
- No independent oracle, sealed held-out corpus, rubric assessment or independent
  product acceptance exists yet.
- Dependencies are declared as ranges in `pyproject.toml`; nothing is locked or audited.
- There is no deployment, hosted service or published package.

Everything below describes intended behavior of the source, not observed output.

## What it does

Input: one local saved plan (`terraform show -json` output). The reviewer validates a
regular file within fixed limits (16 MiB, 10,000 resource changes, depth 64, 256 KiB
strings, 30-second review budget). It rejects duplicate keys, non-finite numbers,
malformed action arrays and duplicate resource identity, and it never runs Terraform,
evaluates HCL or fetches anything referenced by the plan.

| Rule | Declared change predicate | Severity |
|---|---|---|
| R1 | Standalone `aws_security_group_rule`: new world-open IPv4/IPv6 TCP (or all-protocol `-1`) ingress covering port 22 or 3389 | 4 |
| R2 | `aws_db_instance.publicly_accessible` newly true | 3 |
| R3 | RDS/EBS encryption flag changed true to false | 3 |
| R4 | Existing RDS/EBS delete or ordered replacement | 4 |

Each rule emits one of `introduced_risk`, `unchanged_risk`, `clear` (for that named
predicate only) or `indeterminate` per supported resource. Missing or unknown required
facts are never treated as false. Full predicate text: [policy](docs/rules/POLICY-v1.md).

### Two reports

- **Private report** (`private.json`, `private.html`): exact resource addresses and RFC 6901
  JSON pointers into the input. Marked sensitive values are masked, but addresses and
  pointers can themselves contain secrets, so the whole private report is sensitive and
  stays local.
- **Shareable report** (`shareable.json`, `shareable.html`): opaque random IDs and only
  allowlisted Boolean, numeric and fixed-enum facts. It is not source-resolvable without the
  private mapping, which is never included.

Both are self-contained static files: escaped HTML, no scripts, no external assets. A
bundle also contains `run-manifest.json`, `manifest.json`, `manifest.sha256` and
`export-state.json`. Treat a bundle as complete only when `export-state.json` says
`COMPLETE`; `ABORTED` or leftover pending files mean the export did not finish. Bundle and
report formats: [report wire](docs/REPORT-WIRE.md).

### Exit codes (`inspect`)

| Code | Meaning |
|---|---|
| 3 | Malformed input, usage error, internal failure, time budget exceeded or cancelled (no report) |
| 2 | Unsupported or inconclusive required coverage (unknown facts, withheld evidence, incomplete or errored plan, unsupported targeted shape) |
| 1 | A definite risk at or above `--fail-on` (default 3) with otherwise complete coverage |
| 0 | Complete evaluated scope with no threshold risk |

A risk that coexists with unknowns gives exit 2 with `risk_present=true`, so both stay
visible. None of these codes means "secure" or authorizes an apply. Other commands:
`share` returns the stored review exit code (0/1/2); `verify-report` and `evidence` return 0
on success; `explain` returns 0 for an accepted selection and 2 for deterministic fallback;
every command returns 3 on error.

## Intended use (not yet run)

Requires Python 3.12 and [uv](https://docs.astral.sh/uv/). From the repository root:

```sh
uv sync
uv run iac-review inspect fixtures/demo/public-ssh.json --out reports/public-ssh
```

Expected by policy, not observed: the `public-ssh` fixture opens TCP/22 to `0.0.0.0/0`
and should produce an R1 `introduced_risk` with exit 1. Open `reports/public-ssh/private.html`
locally. To share, use the explicit share command with the original plan and a destination
directory that does not exist yet (its parent must exist); never upload the whole report
directory. See the
[synthetic walkthrough](docs/DEMO.md), [sharing](docs/SHARING.md) and
[activation order](docs/ACTIVATION.md).

| Command | Intended behavior |
|---|---|
| `iac-review inspect PLAN --out DIR [--fail-on 1..4]` | Parse, evaluate, resolve evidence, write private and shareable reports; finalize `export-state.json` last |
| `iac-review verify-report BUNDLE [--plan PLAN]` | Check a COMPLETE bundle's inventory and hashes, optionally the source digest; not a risk verdict |
| `iac-review evidence BUNDLE --plan PLAN --finding ID --fact ID` | Show one mask-safe fact; output contains private exact locations |
| `iac-review share BUNDLE --plan PLAN --out DIR` | Regenerate safe-only files with fresh IDs from a bound bundle and the original plan |
| `iac-review explain SHAREABLE --finding ID --selection FILE` | Validate an offline finite explanation selection; no model call |

The default review path has no network, model, scanner, subprocess, database, server or
cloud SDK code. Development evaluation source lives separately in `eval/` and `scripts/`
and is not imported by the product; see [evaluation](docs/EVALUATION.md).

## Repository layout

- `src/iac_review/`: the product package and CLI.
- `eval/`, `scripts/`: development evaluation harness (model arms, scanner comparison,
  custody, scoring). Separately gated; nothing has run.
- `tests/`: authored regression source (not run).
- `fixtures/demo/`: small synthetic development plans. They are not hidden evaluation data.
- `docs/`: design notes and limits. Start with [architecture](ARCHITECTURE.md) and
  [limitations](docs/LIMITATIONS.md); test plans are in [testing](docs/TESTING.md).

## Scope limits

Managed AWS resources in the named shapes only. Inline and newer security-group shapes,
prefix-list or security-group sources, database ports, other stateful types, IAM and
cross-resource reachability are out of scope. R2 does not establish routing; R4 does not
establish actual data loss or missing backups. Full list: [limitations](docs/LIMITATIONS.md).
