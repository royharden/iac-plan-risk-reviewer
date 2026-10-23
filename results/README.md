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
