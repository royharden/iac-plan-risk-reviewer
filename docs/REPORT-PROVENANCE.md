# Private deterministic report provenance

Source construction only: no report, viewer invocation or test was executed for
this package. The descriptor binds local bytes and config; it does not authenticate
the producer or prove benchmark execution, source correctness or deployed state.

RunManifest now has an explicit stage, evaluation by default. Evaluation retains
its required authority/semantic-suite/eligibility pins and custody preflight.
The new deterministic stage is D-only, one local development case/invocation,
source/parser/rule/config components only, and no model/scanner/prompt/corpus,
attempt/usage, custody or benchmark eligibility claims. Its unavailable evaluation
pins are null, not fabricated hashes. Benchmark preflight rejects this stage
before opening metadata. Old evaluation constructors remain valid; canonical
model hashes change with the new stage/default edition and require deliberate
external re-pinning rather than reusing old digest approval.

The local descriptor in iac_review.provenance uses the actual typed RunManifest.
It hashes an explicit installed core source subset (the versioned source profile
below), the actual parser and rule modules and threshold config. That source identity describes the named
installed files, not a Git commit, full repository or authenticated executable.
No Git/subprocess/cloud/provider path is used. Missing installed source files or
deadline exhaustion fail rather than fabricating a build pin. The private raw
plan digest and local case ID bind the descriptor to the exact private report.

## Source profiles

`ReportProvenance.schema_version` selects the pinned source profile:

| Profile | Files | `source` component version | Status |
|---|---|---|---|
| 1 | Nine core files: contracts/__init__, contracts/manifest, ingest, evidence, rules, report, provenance, source_view, cli | `content-v1` | Existing bundles; still verify |
| 2 | Profile 1 plus `contracts/report_wire.py` (ten files) | `content-v2` | Written by new reports |

Adding the canonical report wire to the fingerprint is a deliberate profile
change (INT seam S3), not a silent repin. A profile 1 descriptor must list
exactly its nine files and `content-v1`; a profile 2 descriptor exactly its ten
files and `content-v2`. Mixed inventories are refused. The constructor default
stays profile 1, so only the local producer explicitly claims profile 2. No
archive is upgraded, re-hashed or reinterpreted. The shareable exporter compares
installed pins with the descriptor's pins, so a profile 1 bundle is refused for
safe re-export under profile 2 code (it came from different installed code) and
stays readable through `verify-report`.

The producer, writer and reader validate both projections against the canonical
`contracts/report_wire.py` pair (`validate_report_pair`): `build_report`
returns `ReviewReport.validated(...)`, `write_report` revalidates the mutable
dictionaries before staging, and `verify-report`/`evidence` revalidate bound
bundles (`bundle_report_wire_invalid`). Legacy unbound seven-file bundles are
checked with the separate `validate_legacy_private_report` plus
`validate_shareable_projection`; they stay unbound and are never promoted.

The graph is acyclic:

1. Private run-manifest.json describes source/config/input and contains no
   artifact references or report digest. Pinning report_wire.py hashes its
   bytes only; provenance never imports it (report_wire imports provenance).
2. private.json holds that typed descriptor and its exact serialized digest.
   Shareable/provider projections receive neither descriptor nor raw-plan/source
   identity or private mapping. Existing opaque run/finding IDs and safe facts
   remain unchanged.
3. Private export manifest.json v1.1.0 hashes the four report files plus the
   descriptor. It does not contain its own digest.
4. manifest.sha256 hashes those exact export-manifest bytes. The closed COMPLETE
   bundle inventory is eight files, including export-state.json. No source plan
   or private map is copied into it.

Bundle layouts and control files are the canonical
`contracts/report_inventory.py` types. Before staging, the writer checks its
ABORTED marker, manifest, LF receipt and COMPLETE marker with them, and requires
`classify_bundle` to return a bound COMPLETE result. The viewer keeps its staged
checks, which give specific error codes, and then requires `classify_bundle` to
agree (`bundle_inventory_invalid`). Legacy seven-file bundles classify only as
legacy.

The viewer checks that exact inventory, typed stage, descriptor/private-report
digest and run/case/config/raw-source bindings. Legacy v1.0.0 seven-file bundles
remain readable as explicitly unbound archives; they are not promoted to bound
provenance. Existing verify-report/evidence signatures and the four-report-file
artifacts_verified count remain stable. New results identify run_manifest_bound
and the private descriptor digest. These local verification results are sensitive;
do not copy them into provider/shareable projections.

Risk/evidence/exit logic and the cooperative deadline are unchanged. Descriptor
work occurs within that budget, and export retains the ABORTED marker until every
artifact is staged/published and the final COMPLETE state replaces it. No deadline
rejection follows that final publication. Rollback removes only invocation-owned
files; failed cleanup retains ABORTED. The reader rechecks the entire exact bundle
before returning and never opens a report-supplied input path.

Authorship, semantic execution, bytecode/source correspondence, filesystem race
isolation and independent finished-product acceptance remain external matters.
The new focused regression sources cover stage forgery, binding/digest mismatch,
privacy separation, acyclicity, deadline rollback and viewer inventory/state.
They have not run; dependency/runtime validation is deferred until authorized.
