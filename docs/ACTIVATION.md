# Local activation and remaining validation

The keyless development product has been installed, imported, built and exercised.
The recorded combined-code validation passed 946 development tests, 24 public
synthetic cases and four host CLI journeys; the same combined code also passed
24 public cases and four journeys in a network-disabled Linux container.
See [testing](TESTING.md) for versions, commands and the limits of these results.

The ordinary reviewer needs Python 3.12 and the locked Pydantic dependency. It
needs no server, database, container, cloud account or Terraform apply. From the
repository root, install the pinned development environment and use fresh outputs:

```powershell
uv sync --frozen --python 3.12.13
New-Item -ItemType Directory -Force reports | Out-Null
uv run --frozen iac-review inspect fixtures/demo/public-ssh.json --out reports/public-ssh
uv run --frozen iac-review verify-report reports/public-ssh --plan fixtures/demo/public-ssh.json
```

The synthetic SSH review returns 1 for threshold risk; verification returns 0.
The [demo](DEMO.md) and [testing guide](TESTING.md) provide other implemented commands.
A changed environment or code snapshot requires affected checks to be repeated.
Locked resolution is not a comprehensive dependency security/license audit.

## Product and data handling

Use complete bundles only: `export-state.json` must say COMPLETE. Private reports,
source filenames, exact addresses/pointers and `evidence` stdout remain local and
sensitive. Safe sharing requires the original pinned plan, a current bound bundle
and canonical regeneration into a separate fresh directory. Never upload a whole
bundle or treat a shareable ID as a raw-source locator.

`verify-report` checks integrity, optionally including the original source digest;
it does not authenticate a producer or certify infrastructure. `evidence` reads
one selected mask-safe fact with an explicit source path and actual opaque IDs.
The report evidence transaction observes one fresh entry/exit snapshot and retains
the 30-second budget; restored transient changes between observations may be missed.
Standalone resolution retains per-call reopening. [Transaction details](EVIDENCE-BATCH.md).

Development evidence covers strict ingestion, four-rule semantics, evidence,
private/shareable projections, finite explanation fallback, journal accounting,
schema export and selected failure/effect paths. It does not establish every
filesystem race, power-loss recovery, dependency/native effect or operating system.
Keep version/profile/schema tests with the source and verify actual import paths.

## Gates that remain open

1. Establish genuine Terraform/AWS producer profiles. Parser-tested JSON formats
   and synthetic resource shapes are separate axes; fabricated version strings
   are not producer provenance. Add the missing per-minor fixture evidence before
   extending tested claims. See [compatibility](COMPATIBILITY.md).
2. Complete dependency/license review and actual scanner compatibility work. Pin
   executable, config and custom-policy hashes and predeclare supported mappings.
   Checkov built-ins, action-aware custom checks and compatible Trivy are distinct
   arms over the same synthetic JSON without enrichment. Missing tools/mappings
   mean incomplete work, not true negatives or proven incompatibility.
3. Appoint independent oracle author/checker and semantic rubric assessors. Seal
   configuration, mutation lineage and hidden corpus before tuning. Structural
   metadata validates consistency, not independence. An exposed edition stays
   consumed even if execution fails.
4. Obtain separate explicit provider/model/price/cap approval before any live L/P/M
   experiment. The ordinary model CLI is fake-only, and the programmatic provider
   path remains disabled without external admission. Every attempted request,
   including failure/no-row/unknown billing, must enter conservative accounting;
   pending liabilities block more calls until explicit reconciliation. Mocks never
   become live-eligible results.
5. Freeze exact code, dependencies, schemas, prompts, scanner mappings and rubrics
   for the genuine held-out run. Preserve all failures, abstentions, missing arms
   and unresolved costs. All D/L/P/M/C/C-custom/T comparative measurements remain
   NOT MEASURED; deterministic development execution does not close that benchmark.
6. Complete independent product/release acceptance. Package/CLI and Docker
   development results do not authorize publishing, accounts, spending or deployment.
   The final distributable must be rebuilt and checked after documentation changes
   so packaged README metadata matches its source.

## Evaluation integrity order

The development harness is separate from default product review. Its preflight
reads allowlisted metadata, not plan/HTML/prompt/response payloads. Local artifact
manifests and schema-valid RunManifest declarations do not prove genuine experiment
execution, custody or completion. There is no `iac-review preflight` command.

For a separately authorized real held-out edition: commit the pre-access
[input-exposure intents](EXPOSURE-LEDGER.md) while sealed, verify committed input-only
`HeldoutAuthorization` v2, run frozen arms, pin the actual measured-results hash in
`ScoringHandoff`, then supply post-measurement `ExposureReceipt` rows for separately
authorized scoring. No step grants oracle/scoring/tuning permission implicitly.
Synthetic regression passes are not real custody or universal crash durability.

Full-outcome and binary introduced-risk predictions are distinct scoring targets;
a binary prediction must not invent a full outcome. D exact scoring requires full
outcomes. Strict producer accounting includes every attempt, not only row subtotals.
Unknown and negative measurements remain visible.

[Consumed-edition preparation](CONSUMED-EDITIONS.md) needs genuine completion for
all seven arms plus external release/completion pins. `CompletionReference` and
edition version 2 separate input-exposure intents from post-measurement results;
v1 is refused. No mock/not-run arm closes this gate. The [schema catalogue](schemas/README.md)
is descriptive, not payload admission or authority. Report JSON remains 1.0.0,
bound/legacy artifact inventories remain 1.1.0/1.0.0, and provenance profiles remain
v1 nine files/v2 eleven files without repinning old bundles.

Keep plans, private reports and operational coordination records out of public
artifacts. See [limitations](LIMITATIONS.md), [ledger](LEDGER.md) and
[provider activation](PROVIDER-ACTIVATION.md) for the remaining boundaries.
