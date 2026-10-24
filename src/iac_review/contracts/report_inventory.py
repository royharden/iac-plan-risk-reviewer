"""Canonical report bundle inventory and export-control types. Pure, no file I/O.

Callers read files and pass bytes/names/hashes in. Two layouts exist:

- bound manifest 1.1.0: eight files; five hashed payloads (four reports plus
  run-manifest.json) and manifest.json, manifest.sha256, export-state.json;
- legacy manifest 1.0.0: seven files; four hashed reports plus the same three
  control files. Legacy bundles stay explicitly unbound.

Unknown, partial or ABORTED exports never classify as COMPLETE, and a legacy
inventory never classifies as bound. Every rejection raises
``ValueError("report_inventory_invalid")``.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime
from hashlib import sha256
import re
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

from iac_review.contracts.manifest import Digest
from iac_review.contracts.report_wire import ReportId, ReportWire, _payload
from iac_review.provenance import DESCRIPTOR_FILE, REPORT_FILES

BOUND_MANIFEST_VERSION = "1.1.0"
LEGACY_MANIFEST_VERSION = "1.0.0"
CONTROL_FILES = frozenset({"manifest.json", "manifest.sha256", "export-state.json"})
BOUND_PAYLOADS = REPORT_FILES | {DESCRIPTOR_FILE}
LEGACY_PAYLOADS = REPORT_FILES
BOUND_FILES = BOUND_PAYLOADS | CONTROL_FILES
LEGACY_FILES = LEGACY_PAYLOADS | CONTROL_FILES
MAX_CONTROL_BYTES = 65_536
PRIVACY_TEXT = "Private files and this manifest remain local. Share only the two shareable files."
_RECEIPT = re.compile(rb"[0-9a-f]{64}\n")


def _require(ok: bool, code: str) -> None:
    if not ok:
        raise ValueError(code)


class _Manifest(ReportWire):
    run_id: ReportId
    created_at: Annotated[str, Field(min_length=1, max_length=64)]
    plan_sha256: Digest
    parser_version: Literal["1.0.0"]
    policy_version: Literal["1.0.0"]
    artifacts: dict[str, Digest] = Field(max_length=len(BOUND_PAYLOADS))
    privacy: Literal[PRIVACY_TEXT]

    @field_validator("created_at")
    @classmethod
    def aware_timestamp(cls, value: str) -> str:
        _require(datetime.fromisoformat(value).tzinfo is not None, "report_inventory_timestamp")
        return value


class BoundManifest(_Manifest):
    """manifest.json of a current bound bundle (writer schema 1.1.0)."""
    schema_version: Literal["1.1.0"]

    @model_validator(mode="after")
    def payload_catalog(self):
        _require(set(self.artifacts) == BOUND_PAYLOADS, "report_inventory_catalog")
        return self


class LegacyManifest(_Manifest):
    """manifest.json of a legacy unbound bundle (schema 1.0.0, no run-manifest.json)."""
    schema_version: Literal["1.0.0"]

    @model_validator(mode="after")
    def payload_catalog(self):
        _require(set(self.artifacts) == LEGACY_PAYLOADS, "report_inventory_catalog")
        return self


class CompleteMarker(ReportWire):
    """export-state.json after successful publication."""
    state: Literal["COMPLETE"]
    exit_code: int = Field(ge=0, le=2)  # a report exists only for exits 0-2


class AbortedMarker(ReportWire):
    """export-state.json written first; it remains until every artifact is published."""
    state: Literal["ABORTED"]
    reason: Literal["export_not_finalized"]


ExportState = Annotated[CompleteMarker | AbortedMarker, Field(discriminator="state")]


class _StateWire(ReportWire):
    marker: ExportState


class BundleInventory(ReportWire):
    """Classification of one complete bundle; the only way to obtain a COMPLETE result."""
    kind: Literal["bound", "legacy"]
    manifest_version: Literal["1.1.0", "1.0.0"]
    run_id: ReportId
    plan_sha256: Digest
    exit_code: int = Field(ge=0, le=2)
    manifest_sha256: Digest
    artifacts: dict[str, Digest] = Field(max_length=len(BOUND_PAYLOADS))

    @model_validator(mode="after")
    def kind_matches_version(self):
        bound = self.kind == "bound"
        _require(bound == (self.manifest_version == BOUND_MANIFEST_VERSION)
            and set(self.artifacts) == (BOUND_PAYLOADS if bound else LEGACY_PAYLOADS), "report_inventory_kind")
        return self


def _invalid(call):
    def wrapped(*args, **kwargs):
        try:
            return call(*args, **kwargs)
        except (ValueError, TypeError, UnicodeError, RecursionError, AttributeError, KeyError):
            raise ValueError("report_inventory_invalid") from None
    wrapped.__name__, wrapped.__doc__ = call.__name__, call.__doc__
    return wrapped


def _control_json(raw: bytes) -> bytes:
    _require(type(raw) is bytes and len(raw) <= MAX_CONTROL_BYTES, "report_inventory_control_bytes")
    return _payload(raw)  # strict UTF-8, duplicate keys, non-finite, depth


@_invalid
def expected_files(manifest_version: str) -> frozenset[str]:
    """Exact file set for a manifest version: eight bound files or seven legacy files."""
    return {BOUND_MANIFEST_VERSION: BOUND_FILES, LEGACY_MANIFEST_VERSION: LEGACY_FILES}[manifest_version]


@_invalid
def validate_manifest(manifest: bytes) -> BoundManifest | LegacyManifest:
    raw = _control_json(manifest)
    for model in (BoundManifest, LegacyManifest):
        try:
            return model.model_validate_json(raw)
        except ValueError:
            continue
    raise ValueError("report_inventory_manifest")


@_invalid
def validate_manifest_receipt(receipt: bytes, manifest: bytes) -> str:
    """manifest.sha256 is exactly the LF-terminated hex digest of manifest.json bytes."""
    _require(type(receipt) is bytes and type(manifest) is bytes and _RECEIPT.fullmatch(receipt) is not None,
             "report_inventory_receipt_format")
    digest = sha256(manifest).hexdigest()
    _require(receipt.decode("ascii")[:64] == digest, "report_inventory_receipt_mismatch")
    return digest


@_invalid
def validate_export_state(state: bytes) -> CompleteMarker | AbortedMarker:
    raw = _control_json(state)
    return _StateWire.model_validate_json(b'{"marker":' + raw + b"}").marker


@_invalid
def classify_bundle(names: Iterable[str], *, state: bytes, manifest: bytes, receipt: bytes,
                    artifact_hashes: Mapping[str, str]) -> BundleInventory:
    """Classify a fully published bundle from caller-read bytes and payload hashes.

    ``names`` are the directory entries; ``artifact_hashes`` the SHA256 of each
    payload file actually read. Refuses ABORTED/unknown state, missing/extra/pending
    files and any catalog/hash/receipt mismatch.
    """
    marker = validate_export_state(state)
    _require(type(marker) is CompleteMarker, "report_inventory_not_complete")
    parsed = validate_manifest(manifest)
    listed = list(names)
    _require(all(type(n) is str for n in listed) and len(set(listed)) == len(listed)
        and set(listed) == expected_files(parsed.schema_version), "report_inventory_layout")
    hashes = dict(artifact_hashes)
    _require(all(type(k) is str and type(v) is str for k, v in hashes.items())
        and hashes == parsed.artifacts, "report_inventory_artifact_hash")
    manifest_sha256 = validate_manifest_receipt(receipt, manifest)
    bound = type(parsed) is BoundManifest
    return BundleInventory(kind="bound" if bound else "legacy", manifest_version=parsed.schema_version,
                           run_id=parsed.run_id, plan_sha256=parsed.plan_sha256, exit_code=marker.exit_code,
                           manifest_sha256=manifest_sha256, artifacts=dict(parsed.artifacts))
