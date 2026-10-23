# Complete-bundle and pinned evidence viewer

Source construction only under Dirty Mode; **runtime unverified**. This feature,
filesystem behavior and its regression source have not been executed.

`source_view.verify_report(bundle, original_plan=None)` checks the closed v1 bundle:
only private/shareable JSON/HTML, manifest, manifest SHA256 receipt and export state.
The export state must be exactly COMPLETE with a matching report exit. ABORTED,
missing state, `.pending`, `.export-state.pending`, partial/extra files, symlink or
junction paths, wrong versions, duplicate JSON keys, malformed hashes, traversal
catalogs, changed artifacts and identity/exit inconsistencies are refused. HTML is
hashed as bytes; it is never opened in a browser or evaluated. An optional explicitly
supplied original plan is matched to the manifest/private report SHA256.

`view_evidence(bundle, original_plan, finding_id, fact_id)` additionally selects an
opaque private finding/fact, matches its public projection and fixed v1 locator
shape, and loads only that explicitly supplied local plan. It checks the resource
index, exact address, actions, canonical pointer, role, report field and source pin.
It rebuilds the source reference with the actual `make_ref` helper, uses actual
`resolve` mask/identity/absence checks, and compares the masked safe source result
to the recorded report fact. Source and every bundle file are reopened/rechecked
before returning. Mutation aborts; no alternative source path is guessed.

Only current v1 facts are viewable: fixed metadata provider/mode/type, actions,
before/after existence and the bounded rule attributes (including canonical CIDR
indices), plus optional replace-path existence. Tags, arbitrary dictionary keys,
resource name/address as an attribute and arbitrary pointer traversal are refused.
The one exact address/pointer in `location` is deliberately private, clearly marked
sensitive, and never a shareable/provider projection. Marked values, unknown masks,
arbitrary strings and object contents are not dumped; values use the same closed
Boolean/numeric/enumerated/structural summary as report v1. The original plan is
never copied. Source path names are not output.

A shareable-only report has no private mapping and cannot enable raw-source
resolution. There is no model response, explanation selector or inferred path
parameter in these APIs. An evidence lookup cannot authorize apply, execute/fetch
anything or change a finding. The viewer proves a selected fact against pinned
bytes, not that a risk interpretation is universally correct.

Hashes detect corruption relative to the supplied local manifest; they are **not a
signature or producer authentication**. A party able to replace all artifacts and
recompute the manifest can replace the claimed bundle. The viewer still checks
the selected field against the explicitly supplied source and refuses out-of-scope
locators, but does not certify authorship or independently accept the product.

Each file uses `read_source_bytes` regular-file/no-link/stable-read checks (16 MiB
maximum), and JSON uses the shared strict decoder (depth 64, encoded strings 256
KiB, duplicate/nonfinite rejection). Manifest/state/receipt limits are 64 KiB/4 KiB/
128 bytes. A cooperative 30-second budget covers the view, with exact closed
inventory, at most 40,000 finding rows and 256 facts per finding for source views.
Larger fact rows fail with a limit error rather than a partial view. This is not OS-level filesystem race
isolation; later activation must exercise rename/link/Windows/crash behavior.

Standalone interfaces, **not commands run during construction**:

```text
python scripts/view_evidence.py verify-report REPORT_DIR --plan ORIGINAL_PLAN.json
python scripts/view_evidence.py evidence REPORT_DIR --plan ORIGINAL_PLAN.json --finding OPAQUE_FINDING_ID --fact OPAQUE_FACT_ID
```

Opaque IDs come from the local private report. Successful verification/viewing
returns 0; failure returns 3 and a fixed invariant code rather than raw exception
text. Risk/coverage outcomes remain those of the original report. Useful failures
include `bundle_layout_invalid`, `bundle_export_not_complete`,
`bundle_manifest_hash_mismatch`, `bundle_artifact_hash_mismatch`,
`evidence_source_digest_mismatch`, `evidence_field_outside_view_scope`,
`evidence_resolution_mismatch` and `evidence_value_or_mask_mismatch`.

The installed product CLI also exposes the same read-only interfaces:

```text
iac-review verify-report REPORT_DIR --plan ORIGINAL_PLAN.json
iac-review evidence REPORT_DIR --plan ORIGINAL_PLAN.json --finding OPAQUE_FINDING_ID --fact OPAQUE_FACT_ID
```

`--plan` is optional only for integrity-only `verify-report`; `evidence` always
requires it. Both use the existing whole-invocation CLI deadline and exit 3 on
input/invariant failure. The original inspect/export and offline explain paths,
including the writer's final COMPLETE boundary/deadline signature, remain intact.
The viewer regression source includes integrated CLI privacy, missing-plan/hash
errors and whole-invocation budget checks. None has been executed in Dirty Mode.
