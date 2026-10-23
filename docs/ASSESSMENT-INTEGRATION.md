# Assessment catalogue and correspondence source

Source only: no actual catalogues, mappings, annotations, hidden inputs, CLI/test
or model execution occurred. All required arms remain NOT MEASURED.

`eval.model.review_catalogue.build_catalogue(artifact, projection_json)` consumes
the EXACT captured capsule JSON string. Its SHA256 must match the artifact's
projection pin; do not rebuild JSON with another ordering/whitespace convention.
The catalogue binds artifact, capsule and assessed-text hashes, all safe fact IDs
and limitation IDs. It reuses the actual product SafeFact and central allowlist;
it does not create a second fact schema/policy. Untrusted capsule baseline prose
is deliberately absent from the catalogue. Before/after/role/state/whitelisted
values and limitation IDs can be rendered as an escaped, script-free reference
table. Unknown/masked markers stay unknown; none becomes a benign false value.

Revalidation at consumption checks content hashes, including mutable Any-list
values in the existing product SafeFact wire. The catalogue has no raw addresses,
pointers, tags, filenames, source maps, expected facts, oracle labels or scanner
data. Whitelisted scalar values are intentional safe facts, not arbitrary raw
plan values. Catalogue integrity is not independently verified semantic truth.

`eval.runner.fact_mapping.map_facts` is a SEPARATE PRIVATE evaluator API. Only an
already authorized caller supplies independently authored expected fact locations,
their external pin, expected resource ID, private report pin, original plan and
bundle paths. No oracle files are discovered/read by this helper; inputs contain
locations only, not labels/outcomes. It uses the actual pinned evidence/viewer
APIs to verify exact resource/side/index/value/mask correspondence to displayed
per-run opaque IDs AND to the actual catalogue's field/side/role/state/typed value.
A safe but reversed Boolean in a pinned catalogue is still a correspondence
failure. Mapping receipts bind the catalogue hash too. Source locations never
enter the safe catalogue/model input.

Every expected location remains a row. Missing, masked, withheld, foreign,
ambiguous or unresolved correspondence is denominator loss/incomplete, not an
invented match or dropped requirement. Duplicate mappings cannot collapse two
independent expected facts into a single run fact. Expected absence stays a loss;
the tool does not derive expected semantics from detector outcomes. Pins are
consistency checks, not authentication of independent authorship or caller rights.

`render_worksheet(..., review_catalogue=catalogue)` is an optional compatible
library attachment, and the private writer permits fixed catalogue.json/html
names. Existing CLI signatures/artifact v1 remain unchanged; an authorized caller
must explicitly attach the catalogue. No implicit raw-source fetching is added.

After current source preservation, `eval.model.assessment_bridge.bridge_assessment`
consumes the actual outer workflow objects, revalidates catalogue/mapping pins and
the independent ExplanationCase denominator, and maps annotation references into
the existing D6 expected-ID space. No rows are silently pruned to create an
observation. The receipt preserves originals, all generated/withheld claims,
outer unresolved IDs, full assessor/adjudication sheets and every supplied Attempt.
Missing word counts/receipts, attempts, D reference or provenance remain missing.

An optional existing PObservation candidate is emitted only after all bookkeeping,
fact/limitation correspondence, immutable D-row, declared measurement/attempt pins,
word-count and origin gates pass. Mock/unverified origins produce no candidate.
Even a candidate is NOT admission: receipt live_eligible/complete remain false and
measurement_status remains INCOMPLETE. Origin/actor/pin strings cannot authenticate
live execution, identities or rubric truth. LiteralFalse capture cannot self-authorize.
The external D6 admission owner must validate actual evidence before consuming it.
Nested prose_metrics.complete alone cannot admit a critical-only unresolved dispute.

The receipt separates workflow_bookkeeping_complete from full bridge
bookkeeping_complete. It retains the original expected ExplanationCase and its
hash, complete fact-mapping receipt, full assessor sheets and every supplied
Attempt. It does not generate missing word counts, cost/provenance fields or
independent inventory. Batch-level independent inventory/custody and the real
24-case requirement are still D6's responsibility.

## Global and explicitly approved per-case content pins

`bridge_assessment` retains original global MeasurementPin prompt/rubric comparisons
by default. The optional keyword names are `case_rubric_sha256`,
`case_prompt_sha256`, `case_approval_ref`, and
`expected_case_approval_ref_sha256`. `CaseApprovalReference` contains an external
reference_sha256, case_id/case_sha256, artifact_sha256, global_pin_sha256 and the
local rubric_sha256/prompt_sha256 pair. Case SHA binds the exact existing
ExplanationCase wire via metadata_digest, not only a reused case name.

Both local hashes must match the actual Rubric/ExplanationArtifact content. Every
reference binding and the separately supplied externally expected reference hash
must match. Partial, missing, foreign or mismatched override inputs remain
INCOMPLETE, not a fallback to a forged local/global pin. D6 intake must authenticate
the case approval against its externally pinned authority BEFORE calling. Matching
strings/hashes here perform bookkeeping, not authentication or self-authorization.

An override never replaces global frozen prompt/rubric identities, mutates/clones
MeasurementPin, or clones/re-pins any Attempt. attempt_summary still receives the
same original global pin/hash and the same attempt inventory. The source tests
include 24 distinct local rubric/prompt examples under one unchanged global pin,
plus missing/forged refs and default-global checks. They deliberately reuse a
synthetic source to test wire semantics and are NOT 24 independent semantic or
hidden cases. None of those tests has been run.

Expected fact IDs and locations are private evaluator inputs and never flow into
catalogue/model requests. Explicit LimitationBinding records reconcile independent
IDs with existing finite limitation codes; missing correspondence remains loss.
The caller's expected Case/resource/required facts are never inferred from detector
outcomes. Existing producer/protocol/utility/scorer and artifact v1 APIs are unchanged.
