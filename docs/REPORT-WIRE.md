# Report wire contract (seam S2)

Status: construction source, Dirty Mode. Accepted at most as *construction — runtime
unverified*. Nothing in this module or its regressions has been imported or executed yet.

`src/iac_review/contracts/report_wire.py` is the single canonical owner of the report
projection types. Producers (`report/`), the writer, the bundle viewer (`source_view.py`)
and the facade `ReviewReport` validate through it. No consumer defines duplicate models
or compatibility shims.

## Public API (frozen 2026-10-23)

All functions are pure: no file, network, environment or clock access.

| Function | Returns |
|---|---|
| `validate_projection(value, *, projection: "private" \| "shareable")` | `PrivateProjection` or `ShareableProjection` model |
| `validate_private_projection(payload)` | validated current-shape `dict` |
| `validate_shareable_projection(payload)` | validated current-shape `dict` |
| `validate_legacy_private_report(payload)` | validated legacy `dict` (unbound) |
| `projection_dict(model)` | revalidated `dict` of a canonical model, aliases applied (`C-custom`) |
| `validate_report_pair(private, shareable, *, exit_code: int)` | `(PrivateProjection, ShareableProjection)` |

`value` / `payload` is `bytes` (strict UTF-8), `str`, or any `Mapping` with string keys
(nested Mappings/tuples are copied to plain dict/list before strict JSON re-parsing).
Every rejection raises `ValueError("report_projection_invalid")`. Messages never contain
input values (`hide_input_in_errors`). Extra fields are never dropped (`extra="forbid"`,
`strict=True`) and report-level fields have no defaults. Exception: nested provenance
models (`ReportProvenance`/`RunManifest`) carry single-legal-value defaults (e.g.
`schema_version`), which direct calls of these functions accept when omitted. The
`ReviewReport` facade (`contracts._canonical_pair`) refuses such input because it compares
the input to the canonical dump; consumers needing exact-byte custody use the facade.

Models: `PrivateProjection`, `ShareableProjection`, `LegacyPrivateReport`. Fact models:
`KnownPublicFact`, `MaskedPublicFact`, `KnownPrivateFact`, `MaskedPrivateFact`.

## Versions

| Item | Value |
|---|---|
| Report `schema_version` | `1.0.0` (private, shareable, legacy) |
| `parser_version` / `policy_version` / `rule_version` | `1.0.0` |
| Current private report | requires `provenance` (typed `ReportProvenance` + `descriptor_sha256`); written in bound manifest `1.1.0` bundles |
| Legacy private report | same body, no `provenance`; only valid in legacy manifest `1.0.0` bundles |

The legacy type is never promoted: a legacy report fails `validate_private_projection`
and `validate_report_pair`, and a current report (with `provenance`) fails
`validate_legacy_private_report`. No function converts between them.

## Strict JSON ingress

Bounds: report bytes 256 MiB, 10,000 resources, 40,000 rows, 65,536 facts per row,
address 256 KiB UTF-8, pointer 4,096 characters, action lists up to `16 MiB / 4`
(the smallest legal action entry costs 4 input bytes), version strings up to 256 KiB.
They exist to stop unbounded input. Input byte limits alone do not bound producer
output; the producer's 30-second review budget (`ingest.MAX_SECONDS`, one plan re-read
per resolved fact) keeps real reports far below these caps. A report beyond them makes
`build_report` fail closed (`report_projection_invalid`); nothing is truncated.

Accepted fail-closed refusal: an address containing a lone surrogate escape (e.g.
`"\ud800"`) passes ingest and Python `json`, but the strict JSON model parser rejects it,
so no report is produced for that plan.

Consumer seam (D7, `source_view.py`): the viewer reads `private.json` with a 16 MiB cap
and the ingest 256 KiB string limit, while the writer's `ensure_ascii` + `indent=2`
output can exceed both (e.g. a non-ASCII address escapes to up to 3x its UTF-8 size).
Until the viewer cap is aligned, such a valid bundle can be refused by the viewer.

Before model validation: byte cap 256 MiB, strict UTF-8 (no UTF-16/32 sniffing, no BOM),
duplicate object keys rejected, `NaN`/`Infinity` rejected, top level must be an object,
nesting depth at most 64, mapping keys must be strings (no silent `json.dumps` key coercion).

## Invariants enforced

Per evaluation row:

- severity equals the fixed policy 1.0.0 table (R1 4, R2 3, R3 3, R4 4);
- explanation equals the fixed outcome + rule template text;
- row `limitation_ids` sorted, unique and limited to `decision_evidence_withheld`,
  `indeterminate`, `privacy_value_omitted`, `supporting_evidence_omitted`;
- `indeterminate` limitation iff outcome `indeterminate`; supported rows have an outcome;
- `decision_evidence_withheld` implies outcome `indeterminate` and no facts;
- a supported `introduced_risk` / `unchanged_risk` / `clear` has at least one decision fact;
- `unknown` / `sensitive` fact markers appear only in `indeterminate` rows;
- a `privacy_omitted` fact requires the `privacy_value_omitted` row limitation;
- masked facts carry `value: null`; known values are bool, bounded int, finite float,
  an allowlisted string, or a list of action names.

Per projection: unique finding/fact IDs and (resource, rule) pairs; no opaque ID reused
across roles (finding, resource, fact, run, case); one resource type per resource ID;
global limitations sorted and derived exactly for row-level and `unsupported_shape`
limitations; summary counts, `resource_count`, `missing_evaluation`, risk flags, exit code
(2 inconclusive > 1 threshold risk > 0) and status are consistent with the rows.

Private only: pointers are canonical RFC 6901 under `/resource_changes/<index>/` with
the correct side and field; one raw index per resource ID and no index aliasing; one
address and action list per resource ID; `incomplete_plan` / `errored_or_unknown`
match plan flags; `["unsupported"]` actions require `unsupported_input`; evidence
failures require `decision_evidence_withheld`; when conclusive, `no_changes` iff no risk
and every row is `["no-op"]`; resolution equals the mask state mapping (`unknown`,
`sensitive`, otherwise `resolved`). Current private: provenance digest matches the exact
descriptor bytes, one case, and run ID, case ID, raw plan SHA256 and `fail_on` match.

Pair: common sections are equal, `exit_code` is an `int` equal to both summaries, and the
shareable rows equal the private rows with `address`, `actions`, `reason_code`, and fact
`pointer` / `resolution` removed, in the same order.

## Import DAG

`contracts` (`Wire`) <- `contracts.manifest` <- `provenance` <- `contracts.report_wire`.
`contracts/__init__.py` imports `report_wire` lazily inside `_canonical_pair`; no cycle.
`report_wire` never imports `report/`, `source_view` or `rules`; the severity and text
tables are fixed policy data mirrored from the producer, not detector logic.

## Bundle inventory and export control (`contracts/report_inventory.py`)

Pure types; callers read the files and pass bytes, names and payload hashes. Every
rejection raises `ValueError("report_inventory_invalid")`.

| Layout | manifest `schema_version` | Hashed payloads (`artifacts`) | Files |
|---|---|---|---|
| Bound (current) | `1.1.0` | `private.json`, `private.html`, `shareable.json`, `shareable.html`, `run-manifest.json` | 8 = payloads + `manifest.json`, `manifest.sha256`, `export-state.json` |
| Legacy (unbound) | `1.0.0` | the four report files | 7 = payloads + the same three control files |

`export-state.json` is `{"state": "ABORTED", "reason": "export_not_finalized"}` from the
first write until publication, then `{"state": "COMPLETE", "exit_code": 0|1|2}`.
`manifest.sha256` is exactly the 64-hex SHA256 of the `manifest.json` bytes plus LF (the
writer has always written it this way; the canonical type does not accept a missing LF).

| Function | Returns |
|---|---|
| `expected_files(manifest_version)` | `BOUND_FILES` or `LEGACY_FILES` |
| `validate_manifest(manifest: bytes)` | `BoundManifest` or `LegacyManifest` |
| `validate_manifest_receipt(receipt: bytes, manifest: bytes)` | manifest SHA256 hex |
| `validate_export_state(state: bytes)` | `CompleteMarker` or `AbortedMarker` |
| `classify_bundle(names, *, state, manifest, receipt, artifact_hashes)` | `BundleInventory` (`kind` `bound` or `legacy`) |

`classify_bundle` is the only path to a COMPLETE classification. It refuses ABORTED or
unknown state, missing, extra, duplicate or staging (`.pending`, `.export-state.pending`)
entries, a catalog that is not exactly the version's payload set, payload hash drift and
receipt mismatch. A legacy layout never yields `kind="bound"`; `BundleInventory` itself
rejects a kind/version/catalog mismatch. Control files are capped at 64 KiB and parsed
with the same strict JSON ingress as reports. Constants reuse `provenance.REPORT_FILES` and
`DESCRIPTOR_FILE`, so there is no second payload list (`CONTROL_FILES` still mirrors the
viewer's control-file set in `source_view.py` until D7 imports it from here).

Consumer seam (D7): `source_view.py` currently accepts `exit_code` 0-3 and a receipt
without LF; the canonical types are stricter (0-2, LF required). Before adopting
`classify_bundle`, D7 decides whether to align the viewer or report a legacy-receipt need to D5.

## Deferred validation

- Regressions in `tests/contracts/test_report_wire.py` and `tests/contracts/test_report_inventory.py` are authored, not run.
- No real bundle or archive was read to confirm the inventory types against writer output.
- Pydantic strict JSON-mode behaviour for literal/union edge cases, and full producer
  compatibility of the added invariants, are unverified until tests run.
- Source fingerprint profile v2 including this module is owned by D7 (seam S3).
