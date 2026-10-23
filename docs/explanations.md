# Explanation and accounting boundary

The deterministic report is complete without a provider. It shows exact private
locations, strictly filtered safe values, coverage limits and unchanged versus
introduced declared risks. Sharing means copying only `shareable.json` and
`shareable.html`; private reports and their manifest contain sensitive provenance.
Opaque shared fact IDs are not independently resolvable without the private map.

`explain.build_capsule()` accepts only the narrow shareable projection and creates
a finite safe-fact request. The selection response contains template/fact IDs and
required limitation IDs, never free prose, changed findings or tool requests.
The validator checks known IDs, side/order/polarity, finite transition predicates,
all required facts/limitations and output bounds. Invalid responses fall back to
the full deterministic explanation. `FakeSelector` returns the full fact set and
is plumbing only; it does not establish model quality, cost or task productivity.
The selector remains optional and no live provider adapter is enabled.

`attempts.AttemptJournal` is a single-worker local append-only journal. A separately
authorized caller reserves worst-case token/USD exposure and flushes/fsyncs a
request-start record before attempting a provider call. Every attempt has its own
terminal outcome, duration, usage/known cost or explicit unknown liability, dated
price identity and input/build/prompt/projection hashes. Unknown bills, crashes,
timeouts without complete usage, and reservation overruns block new calls pending
operator reconciliation. Caps include failed attempts. No automatic retry exists.
The journal contains no raw prompt, response text, plan values or secret credentials.
It enforces accounting bounds; it does not confer spend authorization or prove an
external provider will honor a client timeout/token estimate.

An exclusive lock prevents a second instance from using the same journal. A lock
surviving a crash is not stolen by PID or age; an operator must first establish the
old worker is stopped, preserve the journal, reconcile billing and release the
stale lock explicitly. This construction edition has not exercised filesystem
crash/durability/concurrency behavior on any operating system.

Required D/L/P/M/C/C-custom/T comparison measurements remain **NOT MEASURED**.
Isolated free-prose P and model-only M evaluation do not write product decisions;
they belong to the evaluation harness. Provider/model prices, legal terms, caps,
semantic assessors, independent oracle custody and final product acceptance stay
open until their later authorized phase. No source-only or fake-backed result
closes those obligations.
