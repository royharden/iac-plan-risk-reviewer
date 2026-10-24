# Measurement status

No product or benchmark was executed during construction. These are obligation states, not generated measurements.

| Arm | Status | Missing evidence |
|---|---|---|
| D | NOT MEASURED | Independent semantic suite/heldout corpus and actual run |
| L | NOT MEASURED | Approved pinned model call and locked selector utility criterion |
| P | NOT MEASURED | Approved prose call, two independent rubric assessors and adjudication |
| M | NOT MEASURED | Isolated model-only safe inputs and actual predictions |
| C | NOT MEASURED | Pinned Checkov built-in mappings and identical-input execution |
| C-custom | NOT MEASURED | Independent action-aware policies and actual Checkov execution |
| T | NOT MEASURED | Compatible pinned Trivy mappings and actual execution, or evidenced incompatibility disposition |

No model/scanner accuracy, latency or cost figures are available. Later `scripts/eval.py` writes `results.md` and `results.jsonl` from independently supplied oracle rows and measurements, with hashes and explicit missing rows. Missing/unsupported arms cannot be counted as passing negatives.

The model driver can later produce `plumbing.json` plus an attempt journal under
explicit fake mode. That output is live-ineligible even when finite selection or
accounting looks valid; it is not a provider bill, quality score or new D benchmark.
Scanner pending/fake capture and scoring bridges likewise retain incomplete/mock
status rather than supplying measured negatives. Always include failed attempts
and unresolved cost bounds in a later all-attempt accounting summary.

The scorer requires independently supplied oracle/measurement/custody/seal/
semantic/eligibility/utility inputs and exact external pins. Those records are not
included here as hidden gold. An imported self-consistent record or a manifest
hash does not authenticate its original execution. RunManifest/preflight and
explicit binary-target scorer source now exist, with schema-export bindings;
their integrated execution and admission behavior remain unverified.

Keep introduced-risk Boolean predictions separate from full-outcome metrics.
Null abstains, indeterminate gold exposes certainty errors, and D exact remains
full-outcome only. `ProducerAccounting` requires D5 accounting_json plus every
attempt snapshot, including failed/no-row attempts and unresolved liabilities;
scorer row subtotals alone are partial and cannot produce a model total. Optional
producer-export imports remain live-ineligible under v2 eligibility/pins.

No output from a documentation example, hand-authored demo, AST parse, source
inspection or fake replay closes any row above. Independent semantic/effect
validation, required live measurements and product acceptance remain pending.

## Aggregate renderer source

`eval/runner/results.py` and `scripts/render_results.py` provide a bounded,
aggregate-only rendering path for the scorer's exact seven-arm envelope. It emits
four per-rule rows per arm, coverage and confusion counts, failure counts, D exact
gate status, utility summaries, and separate row-subtotal versus all-attempt cost
fields. A missing/ineligible measurement is `NOT MEASURED`; zero metric denominators
are `NA`; a recorded D exact-gate failure is `FAIL`. Negative and abstaining
outcomes remain visible in counts and do not become acceptance.

Model totals require the D5 all-attempt accounting record or a complete D6 utility
attempt summary. Without either, the renderer prints `NOT MEASURED` for the total
and labels any score-row amount as partial. It does not treat mock status as live
evidence, authenticate authorship, or infer product acceptance. When given private
assessment inputs, it emits aggregate values only; case IDs, resource IDs, prose,
and per-case failure details stay in the private source files.

The future CLI requires `--score` and a fresh `--out` directory. Optional inputs
are `--l-utility`, `--assessment-import`, and `--producer-accounting`. It writes
`results.md`, seven arm plus 21 pairwise failure-overlap `results.jsonl` records and a `render-state.json`
completion marker. The generated files are source-design outputs only; the CLI was
not run and no measurement data was rendered during construction.
