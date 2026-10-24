# Limits and deferred validation

## Nothing has run

- This is construction source. No dependency was installed and no module was imported,
  executed or tested. The only checks were syntax parsing and focused source inspection,
  which do not establish runtime correctness, privacy behavior, effects, performance,
  memory bounds or crash behavior.
- All regression files under `tests/` are authored source; none has run or passed.
- Dependencies are declared ranges in `pyproject.toml`, not a locked or audited set.
  Licensing, publication and independent product acceptance are pending. There is no
  remote deployment.

## Deferred validation (in order)

1. Lock and audit dependencies; pin real Terraform/AWS producer and scanner tool versions.
   Then run the core, import, schema, CLI, privacy, effect, journal and crash regressions.
2. Exercise the held-out exposure split: the pre-access input-exposure commit (measurement
   intents) versus the post-measurement exposure receipt (actual results hash), and the
   sealed-plus-committed input-access path. These are source contracts only; runtime and
   custody behavior are unverified.
3. Exercise the strict JSON-mode assessment batch intake (exact pinned bytes after duplicate
   and non-finite checks); untested.
4. Appoint an independent oracle author, checker and rubric assessors; seal a lineage-
   disjoint held-out corpus; confirm provider prices and caps; then measure all seven arms
   (D, L, P, M, C, C-custom, T), keeping every attempt and its cost. All seven are
   **NOT MEASURED**. Independent final acceptance has not started.

## Product scope

- R1 covers world-open TCP (or all-protocol `-1`) 22/3389 in the standalone `aws_security_group_rule` shape only.
  It is not general exposure or reachability analysis. Prefix-list and security-group
  sources are unsupported, never assumed private. Inline and newer ingress shapes are out of
  scope.
- R2 is declared public accessibility, not proven routing. R3 is encryption-flag removal
  only. R4 is declared destructive intent; it does not prove data loss or missing backups,
  and no tag suppresses it.
- Unknown or sensitive required facts are never inferred from other fields; they make the
  predicate indeterminate. Omitted completeness/errored flags stay unknown and make the
  review inconclusive.
- JSON format versions listed in [compatibility](COMPATIBILITY.md) are parser targets, not
  fixture-tested support. No Terraform or AWS provider version is claimed as tested.
- An address containing a lone surrogate escape passes ingest but fails strict report
  validation, so that plan gets no report (fail closed).

## Privacy

- Private reports keep exact addresses and JSON pointers, which can themselves contain
  secrets even though marked values are masked. Treat the whole private report and the
  `evidence` command's output as sensitive and local.
- Shareable reports contain opaque IDs and allowlisted Boolean, numeric and fixed-enum facts
  only. The allowlist reduces outbound exposure; it is not a general secret detector.
- Never upload a whole report directory. Check that `export-state.json` says `COMPLETE`,
  then use the [share exporter](SHARING.md) with the original plan. Legacy (manifest 1.0.0)
  bundles stay unbound and need re-inspection.
- Demo fixtures are synthetic development data and must never be relabeled as held-out
  evidence.

## Integrity and verification

- Bundle hashes, the provenance descriptor and imported metadata check consistency only.
  They do not authenticate a producer, detector semantics, oracle independence or a live
  experiment.
- The four report artifacts are capped at 16 MiB by both writer and viewer (the viewer uses
  smaller caps for `run-manifest.json` and control files), so a very large review fails
  instead of producing an unreadable bundle. Report string bounds are enforced by the report
  wire. See
  [report wire](REPORT-WIRE.md).
- Export deadlines are cooperative between operations. Failed writes roll back created files
  where possible; a killed process or refused cleanup leaves the `ABORTED` marker as the
  authority. Journal locks and reconciliation need platform and concurrency validation.
- The bounded AST boundary checker is not an effect sandbox. Reflection, native code,
  dependency imports and indirect effects need later execution under an enforced boundary.

## Evaluation harness

- The ordinary model CLI is fake-only. The provider path is disabled source requiring
  external activation pins and a durable journal start; no credential, provider call, price
  table or budget approval exists.
- Scanner runner and adapters are development source with unverified pins, sandboxing and
  mapping semantics. Absence of a mapping is not evidence of incompatibility.
- Mock or protocol results are always live-ineligible. A binary introduced-risk prediction is
  not a full outcome. Row cost subtotals are partial; model totals need every attempt,
  including failed and no-row attempts and pending liabilities.
- A committed input-exposure record is input permission only, never oracle, scoring or
  tuning permission. Measured FAIL or unknown results stay recorded; missing or mock arms
  cannot close them. No hidden payload, oracle or label was authored or read here.
- No accuracy, latency, cost or productivity result follows from this source.
