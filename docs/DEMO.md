# Synthetic local walkthrough

The fixed synthetic demo and keyless CLI workflows have executed in development.
They demonstrate declared rule outcomes, evidence, finite fallback and safe sharing;
they are not a human timing study, hidden benchmark, real producer-compatibility
check or model-value result. Use the shipped handwritten fixtures, never private
real plans or hidden acceptance inputs for a portfolio demonstration.

From the repository root in PowerShell, after installing the pinned environment:

```powershell
uv sync --frozen --python 3.12.13
New-Item -ItemType Directory -Force reports | Out-Null
uv run --frozen python scripts/demo.py --fake --synthetic --out reports/demo-01
```

Both flags are mandatory. The script has no live/provider/scanner mode or arbitrary
input-plan option. Use a fresh destination with an existing private parent on each
run. Require root `demo-state.json` COMPLETE before opening `index.html`, then
check each child's `export-state.json`. ABORTED/pending output is not a completed
demo. The entire demo directory is PRIVATE: it contains source-location evidence,
private bundles and mock accounting. Never share that whole folder.

| Open in the local demo | What it illustrates |
|---|---|
| `public-ssh/private.html` | Standalone world-open TCP/22 produces R1 introduced risk with review exit 1 |
| `port-443/private.html` | Port 443 alone is clear for R1 only; no general safety conclusion |
| `unknown-port/private.html` | Necessary unknown facts stay indeterminate, with coverage exit 2 |
| `stateful-replacement/private.html` | Ordered destructive intent and prior-existence evidence, not asserted data loss or missing backups |
| `index.html` and the shareable projection | Private versus opaque safe identities; all comparative arms remain NOT MEASURED |

The script also records a private pinned-evidence response, valid and deliberately
invalid finite fake selections, and an exclusive local mock attempt journal. An
invalid selection falls back while deterministic findings remain unchanged. Mock
zero-cost/token counters are not provider usage or live economic evidence. The
scanner capability table executes no scanner and establishes no binary mapping.
The cooperative 120-second script deadline is not a promised presentation duration
or OS cancellation boundary.

## Verify and share an individual synthetic review

These commands use the implemented CLI. Keep all output roots fresh:

```powershell
uv run --frozen iac-review inspect fixtures/demo/public-ssh.json --out reports/ssh-01
uv run --frozen iac-review verify-report reports/ssh-01 --plan fixtures/demo/public-ssh.json
uv run --frozen iac-review share reports/ssh-01 --plan fixtures/demo/public-ssh.json --out reports/ssh-share-01
```

Inspect and share return the expected risk exit 1 for this fixture; verify returns
0 on success. The detached share directory contains safe projections and its own
integrity controls, not private mapping, source digest or a resolvable raw source.
Hash agreement is integrity, not producer authentication or detector acceptance.

To inspect one fact, get the actual random finding/fact IDs from that run's
`private.json`, then invoke:

```text
iac-review evidence BUNDLE --plan PLAN --finding ID --fact ID
```

Replace the placeholders with that bundle, its original synthetic plan and actual
IDs; do not guess or reuse IDs across exports. Evidence stdout includes exact
private locations and must stay out of shared logs. A shareable ID alone cannot
open raw source. Optional `iac-review explain SHAREABLE --finding ID --selection
FILE` validates a saved offline finite selection and never calls a model; invalid
relations/foreign IDs use deterministic fallback.

The [test guide](TESTING.md) records the scope of executed demo/sharing regressions.
The [share exporter](SHARING.md) regenerates canonical safe content rather than
copying arbitrary stored HTML. The report's [evidence transaction](EVIDENCE-BATCH.md)
observes entry/exit source snapshots, not continuous mutation history.

The demo cannot satisfy [consumed-edition preparation](CONSUMED-EDITIONS.md),
independent hidden evaluation, genuine seven-arm measurement or release approval.
The [ledger](LEDGER.md) provides separate local operator status/reconciliation;
[provider activation](PROVIDER-ACTIVATION.md) remains externally gated and is never
activated here. Scanner development experiments, live calls, hidden corpus access,
accounts and publication require their own authorization. All comparative arms
D/L/P/M/C/C-custom/T remain NOT MEASURED.
