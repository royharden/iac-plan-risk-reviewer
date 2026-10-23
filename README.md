# IaC Plan-Risk Reviewer

Review a saved Terraform JSON plan locally with four bounded AWS change rules. Findings retain verified before/after evidence; unknown or unsupported input stays visibly inconclusive.

**Construction snapshot — runtime unverified.** Source was built under Roy's Dirty Mode instruction. No dependency installation, product execution, tests, scanner runs or provider calls have occurred. Commands below describe the intended activation journey after that mode closes; they are not execution evidence. No remote repository has been created.

## Quickstart after activation

With Python 3.12 and uv, resolve and audit dependencies, create a legitimate `uv.lock`, then install the project. No lockfile is supplied because dependency resolution was explicitly deferred.

```powershell
uv sync
uv run iac-review inspect fixtures/demo/public-ssh.json --out reports/public-ssh
```

Open `reports/public-ssh/private.html` locally. That report is sensitive: it deliberately contains exact resource addresses and JSON pointers. Share only `shareable.html` or `shareable.json`; they replace identifying locations with random opaque IDs. Marked values remain masked in both. Report generation never runs Terraform or applies anything. An input plan is never copied into the report.

Expected by policy, not observed output: standalone ingress opening TCP/22 to `0.0.0.0/0` produces R1 introduced risk with exact source references. HTTPS/443 alone is outside R1's admin-port predicate. Unknown required facts produce an indeterminate result. See [demo fixtures](fixtures/demo/) and [limitations](docs/LIMITATIONS.md).

## Rules and signals

| Rule | Declared change predicate | Severity |
|---|---|---|
| R1 | Standalone `aws_security_group_rule`: new world IPv4/IPv6 exposure on 22 or 3389 | 4 |
| R2 | `aws_db_instance.publicly_accessible` newly true | 3 |
| R3 | RDS/EBS encryption flag true → false | 3 |
| R4 | Existing RDS/EBS delete or either ordered replacement | 4 |

Unchanged declared risk remains visible and counts toward the severity threshold. Default `--fail-on 3`. Exit precedence is 3 malformed/internal error, 2 unsupported/inconclusive required coverage, 1 threshold risk with otherwise complete coverage, 0 complete named scope without threshold risk. `risk_present` remains true when risk coexists with exit 2. These signals do not certify infrastructure safety, deployed state, routing, backup availability or apply success.

## Architecture

`ingest` bounds and validates local JSON → `rules` evaluates frozen predicates → `evidence` resolves exact pinned source facts → `report` produces escaped self-contained artifacts. Strict frozen Pydantic v2 records connect these stages. Optional `explain` accepts finite template selections only; it cannot change a finding. `attempts` implements a single-worker append-only accounting contract. Default product imports expose no network/process launch or cloud SDK path. The model transport remains a fake/protocol until explicit future approval.

Development evaluation sources live in `eval/` and `scripts/`, outside default product imports. They consume independently supplied labels/measurements; they do not manufacture gold from detectors. See [evaluation](docs/EVALUATION.md), [compatibility](docs/COMPATIBILITY.md) and [architecture](ARCHITECTURE.md).

## Results and cost

[Results status](results/README.md) records all seven required arms D/L/P/M/C/C-custom/T as **NOT MEASURED**. No precision, recall, speed, cost/success or productivity result is claimed. A synthetic fixture or mock does not close a live measurement obligation. There were no provider attempts in this construction phase; runtime costs and performance remain unmeasured.

## Limits and verification

Only managed canonical AWS resources in the named shapes are intended. JSON formats 1.0/1.1/1.2 are parser targets; none has yet been fixture-tested here. Inline/newer SG shapes, database ports, broader stateful types, IAM and cross-resource reachability remain outside this edition. Missing completeness flags remain unknown. Real Terraform/AWS producer pins, dependency lock/audit, independent oracle, semantic assessors, scanner mappings and live provider budgets remain open.

Coding agents wrote this source. Actual verification is limited to recorded static syntax parsing and focused source/logic inspection; no runtime or security assurance follows. Independent final product acceptance remains pending. Product licensing is proposed MIT, with final repository licensing approval deferred; no third-party source was copied or vendored.
