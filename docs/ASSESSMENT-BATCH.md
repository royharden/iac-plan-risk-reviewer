# Per-plan assessment batch intake

Batch intake binds an externally frozen scenario inventory, coordinator invocation
spans, D5 per-plan exports, D5 verified capture indices and D7 per-case approval
references. Raw saved-plan SHA256, request SHA256, safe projection SHA256 and case
record SHA256 are separate identities. Findings from one plan count once toward
the minimum 24 distinct raw scenarios; all findings remain in the assessment
denominator and report.

Each invocation's D5 accounting wire is retained at invocation scope. The single
read-only global journal is the batch-wide accounting boundary. The importer never
sums cumulative journal totals across plans, drops failed attempts, converts
missing evidence to zero, or promotes mock rows to live evidence. Missing exports,
capture data, raw bindings, or journal matches keep the batch incomplete.

The private CLI envelope is `m4-assessment-batch-transport-v1`: one typed
`AssessmentBatchRequest`, operator-bound `root_id` and `root_sha256`, and per-
invocation allowlisted D5 bundle objects, root-relative capture directories and
optional `PrivateFileReference` entries for D7 submissions. The CLI requires
independently supplied manifest and root SHA256 values, one explicitly authorized
root, a fresh output path inside that root, bounded file sizes, duplicate-key
rejection, normalized
root-relative paths, and a 120-second deadline. It validates authority and the
canonical D4 provenance/journal boundary before reading referenced D7 submission
files or invoking D5 capture verification. It performs no recursive discovery.

D4's outer canonical provenance digest, D5's canonical provenance digest, and
D5's whole `ExportBundle` digest are distinct pins. Its `model_exports` entries
reconstruct `ExportBundle` using `ArmRow.model_validate` and canonical JSON for
the nested attempts/accounting/provenance/observations. Empty row lists remain
empty; they never acquire fabricated rows. A zero-row D4 nested export still needs
its own case ID, raw/case-record pins, and attempt span in the producer wire.

The safe results renderer accepts the batch envelope directly. It reports distinct
raw scenarios separately from finding rows, renders P utility over the full batch,
and adds one ID-free global journal accounting row. Any missing capture, unmatched
attempt, pending liability, or unavailable snapshot prevents a complete total;
invocation detail is never added again to cumulative journal cost.

The source path is structurally verified only. Metadata pins do not authenticate
authors, assessors, semantic labels, or product acceptance. Runtime validation and
hidden-oracle evaluation remain unperformed.
