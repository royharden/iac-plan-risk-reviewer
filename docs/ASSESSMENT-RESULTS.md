# Private assessment intake and result status

`eval.runner.assessment_import.import_assessments` joins the D5 payload-free
`ExportBundle` and `VerifiedCaptureIndex` to D7's exact captured artifacts and
assessment bridge. It validates an externally pinned `AssessmentAuthority` before
calling D7. The authority binds each expected `ExplanationCase`, artifact digest,
local rubric digest, prompt/request digest, and external approval-record reference
to the unchanged global `MeasurementPin` digest. The per-case override never
replaces or clones the global manifest or attempt receipts.

The authority carries D7's canonical `CaseApprovalReference` object and the
separately pinned approval-reference identifier. Intake verifies every field
against the authorized case, captured artifact, global pin, local rubric digest,
and prompt digest before calling `bridge_assessment`; it does not synthesize an
approval reference.

The case approval reference is an externally assigned record identity. A matching
digest and identity string provide structural consistency only; they do not prove
who approved the case, assessor independence, correct labels, or real execution.
Raw case SHA256, safe projection/input SHA256, prompt SHA256, rubric SHA256,
artifact SHA256, and global pin SHA256 stay distinct. No report or oracle content is
read by the intake.

The intake retains every expected case, returned receipt, missing/incomplete case,
unconverted attempt, D5 all-attempt accounting record, per-arm cost summary, and
usage/liability completeness flag. It checks capture-index outer status and
`assessment_inputs_complete`, exact-response capture state, D7 outer
`bookkeeping_complete`, and a non-null D7 observation before passing a case into
the existing P utility scorer. Nested rubric metrics alone cannot make a case
complete. A zero or absent denominator stays incomplete; fewer than 24 independent
cases is called out explicitly. Missing word counts, attempt links, usage, billing,
annotations, adjudication, or fact correspondence are never replaced by zero or a
successful default.

`scripts/import_assessments.py` accepts an explicit request JSON, D5 export bundle,
optional private capture directory and journal-link records. Authority/export/index
digests are supplied separately on the command line and replace any values in the
request file. The CLI requires a fresh output path and writes a private result with
an fsync. Exit 0 means the source-level structural intake found no missing cases;
exit 2 means input rejection or incomplete intake. Neither code means semantic
truth, live eligibility, product readiness, or user acceptance.

Current D5 fake/protocol records and D7 artifact wires remain live-ineligible. The
intake always returns `live_eligible`, `identity_authenticated`,
`semantic_assessment_complete`, and `product_acceptance` as false. Its result is
private rubric material, not shareable report content. No actual capture, rubric,
annotation, hidden case, gold label, or evaluation result is embedded here.

Runtime checks, privacy/ACL review, real external identity and case-authority
verification, genuine assessment appointments, live/replay provenance admission,
and independent semantic evaluation remain deferred. The source result does not
establish any measured outcome.
