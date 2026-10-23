# Two-minute synthetic walkthrough after activation

These are future instructions, not a recorded demonstration. No output, screenshot,
runtime/test pass, model value, cost or productivity result has been observed in
this construction snapshot. Use hand-authored development cases only; never use
private real plans or hidden acceptance inputs for a portfolio demo.

After the activation owner authorizes environment setup and the core journey,
keep the shell at the outer project root and select the inner project explicitly:

```powershell
uv run --project .\iac-plan-risk-reviewer python .\iac-plan-risk-reviewer\scripts\demo.py --out .\iac-plan-risk-reviewer\reports\demo
```

Use a new output directory on each run. The script has four input names:
`public-ssh`, `port-443`, `unknown-port`, `stateful-replacement`. Inspect each
child's `export-state.json` before opening reports. A failed/ABORTED export or
pending remnant is not a completed demonstration.

| Time | Future action | Policy expectation, not observed output |
|---|---|---|
| 0–20s | Identify the synthetic saved plan and four-rule scope; show local plan digest | No Terraform execution, deployed-state check or permission to apply |
| 20–50s | Open `public-ssh/private.html`; inspect actions and safe before/after facts | Supported standalone world-open TCP/22 should be R1 introduced risk |
| 50–75s | Open `port-443` then `unknown-port` | 443 alone is clear only for this predicate; a necessary unknown stays indeterminate |
| 75–95s | Open `stateful-replacement`; show ordered actions and pinned prior-existence evidence | Supported destructive intent does not assert actual loss or missing backups |
| 95–120s | Compare private/shareable projections and open results status | Shareable IDs omit exact locations; D/L/P/M/C/C-custom/T all remain NOT MEASURED |

The pinned source-view library can later recheck a complete bundle or one chosen
fact using an explicitly supplied original-plan path. Do not promise that a
shareable ID alone opens raw source. Exact address/pointer output is private.
Main CLI viewer wiring now exists in source: `iac-review verify-report BUNDLE
[--plan PLAN]` and `iac-review evidence BUNDLE --plan PLAN --finding ID --fact ID`.
Use the original synthetic plan and actual IDs from that run's private report;
their random values cannot be guessed or reused across exports. These commands
remain unexecuted here. Evidence stdout is private; keep it out of shared logs.
Hash agreement is integrity, not producer authentication or detector acceptance.

Optional later offline `iac-review explain` validates a finite saved selection
against the shareable capsule. It does not call a model. Obtain the real opaque
finding/fact IDs from that run; random IDs cannot be copied between exports.
Invalid relation/foreign IDs must fall back to deterministic text. This is a
future regression demonstration, not an already passing semantic result.

For separately authorized fake-model plumbing, use the explicit fake driver
interface in [model activation](model-activation.md). Mock usage/cost is not live
usage/cost; completed plumbing returns 2 because L/P/M remain incomplete. Scanner
execution, live calls, hidden corpus, schema generation and publication are not
part of this walkthrough. Use [activation](ACTIVATION.md) for their later gates.
