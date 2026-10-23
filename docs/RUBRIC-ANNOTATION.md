# Offline rubric mapping and remaining staffing

This is workflow/test SOURCE, not an actual rubric annotation, hidden oracle,
assessor appointment, generated artifact, passing test or P measurement. No human
or model labels were produced during construction.

| Item | Meaning and denominator |
|---|---|
| Exact text inventory | Human-supplied contiguous code-point spans cover the whole pinned text, including punctuation/context/withheld portions; stable IDs depend on exact artifact/text/span |
| Factual claim IDs | All spans explicitly classified claim; includes generated claims even when withheld. Context classification correctness requires independent curation |
| Frozen rubric | Bounded exact instruction text plus its UTF-8 SHA256, required fact/limit IDs and declared independent receipt are included in the sheet's canonical rubric hash |
| Supported | Human finds every factual assertion in that claim supported by the independently checked safe evidence; not mere pointer/ID existence |
| Contradicted | Human finds the assertion contradicts evidence, including wrong side, polarity or transition; valid citations do not rescue it |
| Unsupported | Evidence is insufficient to support the assertion as stated; never silently relabel as supported |
| Unknown | Human cannot decide under the frozen rubric; distinct from a blank/uncompleted annotation |
| Withheld | Preserved inventory/producer state, never removed from generated-claim denominators or changed by an assessor |
| Critical false | Explicit assessor judgment alongside contradicted/unsupported label; never automatically inferred from an ID or every negative label |
| Necessary-fact/limitation IDs | Must belong to the artifact catalog; required sets come from separately frozen independent rubric, not a detector-generated gold import |
| Support rate | Supported / ALL generated factual claims, including withheld and unresolved; zero generated gives NA and incomplete explanation |
| Agreement | Matching semantic label/withheld/fact/limitation rows / all generated; criticality-only disagreement is additionally tracked outside existing prose_metrics |
| Recall | Existing prose_metrics reports supported-fact/limitation recall; its supported-withheld facts can count. D6 visible-retention utility separately excludes withheld claims/explanations |
| Disagreement | Preserve both exact original sheets. Third independent adjudication must bind their hashes. Missing/blank adjudication stays unresolved/incomplete |

Labels begin null. The tool does not split sentences automatically, suggest labels,
infer factuality/support/criticality, retrieve raw source, execute prose or call a
model judge. A malicious/incorrect curator can classify a factual statement as
context: whole-text coverage is a bookkeeping check, not proof of honest factual
decomposition. Actual curation, rubric validity and necessity judgments need
independent verification before any evaluation denominator is accepted.

The export retains ordered claim IDs and a generated_claim_inventory_sha256
compatible with the existing utility's ordered-list hash. It supplies existing
ClaimAssessment first/second records and semantic-disagreement adjudication for
prose_metrics. A critical-only dispute is kept unresolved in the outer export
until explicitly adjudicated; do not treat nested metrics.complete as overall
assessment completion. Overall complete/live_eligible/identity_authenticated/
live_provenance_verified remain false. Bookkeeping completion alone is not P
acceptance. The output supplies safe case/finding/attempt/rule metadata; any needed
resource join, ExplanationCase denominator, live attempt pins/usage/prices and
PObservation admission remain D6's explicit responsibility. Do not fabricate them.

Remaining independent staffing: appoint a genuine nonauthoring curator and two
distinct nonauthoring rubric assessors, plus a third independent adjudicator for
disagreement; establish trusted identity/custody and independently validated
rubric/evidence context. Actor-ID/receipt strings only prevent obvious collisions;
they do not authenticate appointments or semantic truth. Separately verify actual
live/replay provenance, every attempt/cost liability and withheld explanations.
Mock/unverified capture remains plumbing, not a required live P measurement.

Later authorized regressions should exercise exact hash/text changes, dropped and
duplicate claims, foreign facts/limits, colliding actors, controls/HTML escaping,
withheld denominator, blank labels, semantic and critical-only disagreement,
stale adjudication and fresh-output preservation. Source lives exclusively in
`tests/eval/test_prose_annotation.py`; it has not been run. Synthetic Alpha/Beta
fixtures and toy labels inside that source test bookkeeping only, not AWS truth.
