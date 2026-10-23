# Private offline P assessment source

Source construction only: no artifact, claim inventory, assessor label, worksheet,
CLI, test, model request or hidden input was generated/executed in this package.
Required P remains NOT MEASURED and product prose remains disabled.

The canonical wire is `eval/model/explanation_artifacts.py`. ExplanationArtifact
binds opaque artifact/case/finding/attempt and generator actor IDs, immutable D
decision reference, separate raw-input/projection/prompt/build/response hashes,
optional payload-free attempt/price/usage receipt hashes, exact assessed text and
its UTF-8 SHA256, safe fact-ID/finite limitation-ID catalogs and origin. Capture
is always `live_eligible=false`; mock/live/replay strings are not authenticated
provenance. The wire has no fields for hidden gold, split, scanner output, raw
addresses/pointers/tags, credentials or private source mapping.

Generated text is untrusted PRIVATE data. Structural field exclusion cannot
guarantee that arbitrary prose contains no hallucinated/sensitive strings. Future
opt-in capture must use only the approved safe capsule and separately enforce
private storage/content handling; never publish these artifacts or pass them to
a terminal, interpreter, Markdown renderer or HTML executor. Terminal/directional
controls are rejected. Worksheet HTML escapes every text/JSON value, uses no
scripts/links and has a restrictive CSP. This is not an executed XSS/privacy test.

## Explicit human workflow, after separate activation

1. D5's separately assigned producer can opt in to the declared private artifact
   wire. No producer code change or new transport is implicitly assigned here.
   Preserve exact assessed text without normalization; response hash pins the
   original response, prose_sha256 pins the exact span-addressed UTF-8 text.
   Any response wrapper/extraction relationship requires verified provenance.
2. An independently appointed curator supplies explicit code-point start/end
   SpanSpec rows classifying the WHOLE text as claim or context. No automatic
   sentence splitter, model decomposition or labels are provided. Exact slices,
   contiguous coverage and stable hash-derived IDs are checked. Context can hide
   factual claims if a curator is wrong: decomposition truth is an external check.
   Withheld claims remain claims; if the entire explanation is withheld, every
   claim span must be withheld. Empty text yields zero claims and incomplete work.
3. Freeze the artifact/inventory/rubric hashes, exact rubric instruction text and
   its UTF-8 SHA256, and independent curation/rubric
   receipts. The rubric supplies required safe fact/limitation IDs, not hidden
   gold. Catalog IDs alone do not establish facts; assessors need separately
   authorized, independently checked safe evidence/rubric context.
4. Prepare each distinct nonauthoring assessor's own packet separately. Rows cover
   EVERY claim, including withheld ones. Labels start blank (`null`), distinct from
   the semantic label unknown. Humans explicitly fill label, critical-false flag
   and necessary-fact/limitation IDs. No supported/unknown defaults are invented.
   Review receipts and actor strings must be authenticated independently.
5. Both completed sheets bind exact artifact/inventory/rubric hashes. Disagreement
   in label, fact/limitation coverage or criticality requires a third distinct
   nonauthoring adjudicator. Preserve both original sheets; bind adjudication to
   their exact hashes. Missing adjudication remains incomplete, never majority
   vote or automatic truth. Adjudication cannot drop or invent claim IDs.
6. Export existing ClaimAssessment records and prose_metrics-compatible inputs.
   Entire generated claim-ID order and its SHA256 retain withheld denominators.
   Partial labels do not become protocol records. Semantic-only metrics and
   critical-only disputes are distinguished. Full bookkeeping can be marked
   complete only with all rows/resolutions and declared receipts; overall complete,
   identity_authenticated, live_provenance_verified and live_eligible remain false.
   D6 owns external admission, utility, live provenance and authenticated staffing.

`scripts/annotate_prose.py` contains future explicit commands `inventory`, `prepare`,
`adjudicate` and `export`. Common options are `--artifact`, declared `--actor` and
fresh `--out`. Inventory additionally requires a human `--spans` file; other
commands require `--inventory`/`--rubric`; prepare needs `--other-assessor`;
adjudicate/export need `--first`/`--second`; export optionally accepts
`--adjudication`. No command executes during Dirty Mode. Schema inputs and example
annotations are not generated here. Use actual independently appointed actor IDs,
never fabricated identities for a real run.

Output uses fixed filenames in a fresh actor-labelled private directory with an
existing parent; no overwrite/reuse of another assessor's directory is allowed.
POSIX restrictive creation modes are requested, but Windows ACLs, ownership and
actual identity/custody remain external responsibilities. A failed write leaves
an incomplete packet; never reuse it or interpret WRITTEN as semantic acceptance.
Console output contains fixed status codes, never prose, paths or validation text.

The journal/provenance exports remain payload-free. Private artifacts are separate
opt-in evidence and never become product reports or automatic explanations. No
existing protocol, utility/scorer, producer, hidden corpus or product decision was
modified. See [rubric mapping](RUBRIC-ANNOTATION.md) for denominators and staffing.
