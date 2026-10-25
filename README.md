# IaC Plan-Risk Reviewer

A local reviewer for saved Terraform JSON plans. It evaluates four bounded AWS change
rules and links every finding to before/after facts in that exact input file. Unknown or
unsupported input stays visibly inconclusive. A model may later explain a finding; it can
never create, delete, reprioritize or clear one. The report never says infrastructure is
secure or reflects deployed state.

## Status: keyless development validation

The tested code snapshot recorded on 2026-10-25 passed 946 development tests with
zero failures, errors or skips using Python 3.12.13, Pydantic 2.14.1 and pytest 9.0.3.
Its public synthetic matrix passed 24/24 cases, with four CLI journeys passing on
the host and in a network-disabled Linux container. Imports, package/CLI execution,
schema export, evidence verification and private/shareable workflows have run.
Dependencies are pinned in `pyproject.toml` and `uv.lock`.

These are development checks, not an independently sealed accuracy benchmark or
whole-product acceptance. JSON format 1.2 and the named AWS shapes have synthetic
test evidence; real Terraform/AWS producer compatibility remains unestablished.
See [testing](docs/TESTING.md) and [compatibility](docs/COMPATIBILITY.md) for scope.

All seven comparative evaluation arms (D, L, P, M, C, C-custom, T) remain
**NOT MEASURED**. Deterministic development execution does not close those benchmark
obligations. Independent oracle custody, a sealed held-out corpus, semantic rubric
assessment, genuine producer profiles and required live comparisons remain incomplete.
No model-value, accuracy, live-cost or productivity claim follows from the checks.
There is no hosted service or published release. Dependency audit and final acceptance
requirements are listed in [limitations](docs/LIMITATIONS.md).

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

## Local use

Requires Python 3.12 and [uv](https://docs.astral.sh/uv/). From the repository root
in PowerShell:

```powershell
uv sync --frozen --python 3.12.13
New-Item -ItemType Directory -Force reports | Out-Null
uv run --frozen iac-review inspect fixtures/demo/public-ssh.json --out reports/public-ssh
uv run --frozen iac-review verify-report reports/public-ssh --plan fixtures/demo/public-ssh.json
```

The synthetic `public-ssh` fixture opens TCP/22 to `0.0.0.0/0` and produces an R1
`introduced_risk` with inspect exit 1; successful verification returns 0. The risk
exit is an expected review result. Output directories must be fresh; choose another
name for another run. Open `reports/public-ssh/private.html`
locally. To share, use the explicit share command with the original plan and a destination
directory that does not exist yet (its parent must exist); never upload the whole report
directory. See the
[synthetic walkthrough](docs/DEMO.md), [sharing](docs/SHARING.md) and
[activation order](docs/ACTIVATION.md).

| Command | Behavior |
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
- `eval/`, `evals/`, `scripts/`: development harness, public synthetic checks and
  separately gated model/scanner/custody workflows.
- `tests/`: development regression and independent specification-derived test cases;
  these are not a sealed hidden oracle.
- `fixtures/demo/`: small synthetic development plans. They are not hidden evaluation data.
- `docs/`: design notes and limits. Start with [architecture](ARCHITECTURE.md) and
  [limitations](docs/LIMITATIONS.md); test plans are in [testing](docs/TESTING.md).

## Scope limits

Managed AWS resources in the named shapes only. Inline and newer security-group shapes,
prefix-list or security-group sources, database ports, other stateful types, IAM and
cross-resource reachability are out of scope. R2 does not establish routing; R4 does not
establish actual data loss or missing backups. Full list: [limitations](docs/LIMITATIONS.md).
