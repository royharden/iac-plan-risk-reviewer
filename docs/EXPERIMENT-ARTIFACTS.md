# Private P capture and finite L receipts

Dirty Mode source only: **runtime unverified**. No capture, driver, annotation,
provider request or regression has been executed. D7 owns the artifact/annotation
wires; D5 imports those exact types and does not create a second artifact schema.

`run_experiments(..., capture_private_prose=False)` retains no new raw response
bytes by default. With explicit opt-in it keeps bounded P bytes only, including
invalid/error/timeout output when actually returned. Exceptions/no response remain
missing; they are not replaced with invented text. Capture is at most 65,536 bytes
and the configured output byte cap. Oversized output retains an explicitly incomplete
prefix, never a falsely complete response. All original attempts/costs remain in
the payload-free journal and ExportBundle; neither serializes these private bytes.

`assessment_capture.build_capture` consumes the preserved result, explicitly
declared opaque generator actor IDs and origin `mock` or `unverified`. It uses D7's
actual ExplanationArtifact/DecisionReference/text_digest/digest helpers. Every P
outcome is represented, including not-run/no-response outcomes. Complete, permitted
UTF-8 response text is captured exactly, **including its JSON response envelope**.
Model-provided claim arrays are not joined, filtered, relabeled or promoted into a
human claim inventory. D7's independent curator must explicitly partition all text
into claim/context spans. There are no support labels or automatic judgments here.

Each artifact binds opaque case/finding/attempt/artifact IDs, immutable D outcome
reference, raw source hash separately from safe projection/prompt/build/response
hashes and attempt/price/usage refs. The fact/limitation catalog comes only from the
finite safe capsule, with no hidden requirements, gold labels, split IDs, scanner
outputs or private map. All P artifacts remain explanation_withheld and
live_eligible=false. Hash agreement and declared actors do not authenticate authorship,
live provenance or truth. D outcomes and product explanations are unchanged.

D7's wire deliberately rejects unsafe controls, invalid UTF-8 and text beyond its
limits. Those outputs are preserved as bounded **private diagnostic JSON/base64**
instead, with original response digest when available, retained-prefix digest,
completeness/length and failure state. They are not ExplanationArtifacts or successful
semantic assessments. No altered/sanitized text is sold as the exact original.
Missing or truncated bytes keep assessment incomplete. Private diagnostics can
contain arbitrary generated content; never share or render them as commands/HTML.

`write_private_capture` requires a fresh, separately chosen directory with an
existing parent and no symlink/junction traversal. It writes exclusive owner-mode
JSON files under opaque names; the final state is WRITTEN only after all writes.
Interruption retains INCOMPLETE state; directories are not reused or auto-cleaned.
There is no browser, HTML rendering, network or process execution. OS ACL/privacy
enforcement, hostile filesystem races and crash durability need later validation.
Limits are 10,000 P records, 1 MiB per serialized file and 64 MiB per sink. This
source construction has generated none of those artifacts.

L observations now bind actual finite baseline/rendered word counts (Unicode
non-whitespace runs), render source and required/selected limitation IDs. Invalid
attempts obtain the real deterministic finite fallback before counting. No attempt/
no rendered selection leaves an explicit missing rendered count. These are receipts
of the fixed language, not independently scored necessity/utility or hidden-oracle
labels. Full deterministic outcomes remain invariant; the selector stays optional.

The driver continuation adds an explicit separate private sink and generator actor
IDs. The private index records all P outcomes and file hashes without assigning
claim IDs/labels or dropping failed attempts. Final WRITTEN state pins the exact
index hash; incomplete/partial writes must not be treated as an assessment packet.
Ordinary plumbing gets only the index hash/count receipt. The source regressions
round-trip produced artifacts through D7's actual wire/inventory/blank-sheet/escaped
worksheet APIs while verifying that semantic and live completeness remain false.
None of those test calls was executed during construction.

## Whole-capture completeness verifier

`capture_index.verify_capture_index(directory, bundle, *, expected_export_sha256,
expected_index_sha256=None) -> VerifiedCaptureIndex` consumes the exact ExportBundle
and separately caller-pinned digests. `export_digest(bundle)` defines the canonical
payload-free export pin; it is not a signature or provenance authority. Omitting the
directory means disabled capture and returns incomplete without opening a capture
path. Missing external index pins or legacy exports without finding/catalog joins
also stay incomplete. Corruption, omissions, foreign joins and malformed inventories
raise fixed invariant errors. No source plan, hidden gold, key, provider or scanner
payload is opened.

The verifier reuses D6's authoritative attempt/accounting bridge, then checks the
D snapshot and new payload-free observation joins: case/resource/rule/D-row digest,
complete opaque fact catalog, required limitations and every L/P/M attempted receipt.
Every expected P observation, including not-run/failed/withheld/diagnostic entries,
must appear exactly once. The exact closed private file inventory, state/index/file
hashes, D7 artifact wire/text hashes, raw versus projection/prompt/build refs,
attempt/price/usage refs, catalog and diagnostic retained-byte hashes must match.
Files are re-read before return. Strict byte/depth/string/time/record caps apply;
no unlisted relative path from the index is opened.

`VerifiedCaptureIndex.status=verified` means only whole-index structural integrity
and inventory matching. `assessment_inputs_complete` is separate and false for
failed/missing/diagnostic P output, missing finite L renders or empty capture.
Identity/origin authentication, semantic completion and live eligibility remain
LiteralFalse in every result. The typed D7 `artifacts` tuple is available to explicit
private consumers but is excluded from default serialization/repr. L receipts and
outcome metadata are immutable typed projections; hashes alone do not authenticate
the source or ensure an independent rubric/assessor. No verification changes a
product finding or manufactures human claim/label decisions.

Regression source covers self-rehashed missing failed entries, altered raw/projection
or build/finding/catalog links, changed diagnostics, missing/extra/pending/traversal
files, separately wrong export pins, disabled/legacy paths and structurally sound
but unassessable captures. It has not been imported or executed in Dirty Mode.

Raw-case cardinality: this one-plan export keeps the same raw saved-plan
Context.source_sha256 across its findings. Distinct opaque finding IDs and
canonical model-request/projection hashes do not increase independent scenario
coverage. The frozen eligible raw-input inventory controls that denominator;
multi-plan consumers retain each per-case raw Context and ExportBundle. A case
RECORD digest (CaseApprovalReference.case_sha256) is a separate pin. Raw
case/artifact/mapping mismatches remain incomplete; no attempt is re-pinned.
