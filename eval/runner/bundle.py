"""Guarded private bundle assembly SOURCE; no discovery, unblinding or execution."""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
from time import monotonic
from typing import Literal

from pydantic import Field, model_validator

from iac_review.contracts.manifest import ArtifactRef, Digest, ManifestWire, OpaqueId, RunManifest
from eval.runner.custody import Identity, Seal, metadata_digest
from eval.runner.preflight import (
    METADATA_PATHS, PreflightPins, _constant, _object, checked_path, preflight, read_metadata,
)

PAYLOAD_PREFIXES = {
    "case_input": "private/synthetic/inputs/", "oracle": "private/synthetic/oracle/",
    "measurements": "private/synthetic/measurements/",
}


class AssemblySelection(ManifestWire):
    schema_version: Literal[1] = 1
    product: Literal["iac-plan-risk-reviewer"] = "iac-plan-risk-reviewer"
    run_id: OpaqueId
    run_manifest_sha256: Digest
    source_root_sha256: Digest
    output_root_sha256: Digest
    max_total_bytes: int = Field(default=16 * 1024 * 1024, ge=1024, le=128 * 1024 * 1024)
    max_seconds: int = Field(default=30, ge=1, le=120)


class ReleasedArtifact(ManifestWire):
    artifact_id: OpaqueId
    role: Literal["case_input", "oracle", "measurements"]
    sha256: Digest


class ReleaseAuthorization(ManifestWire):
    schema_version: Literal[1] = 1
    product: Literal["iac-plan-risk-reviewer"] = "iac-plan-risk-reviewer"
    run_manifest_sha256: Digest
    edition_id: OpaqueId
    edition_state: Literal["consumed_holdout"]
    custodian: Identity
    authorized_by: Identity
    release_record_sha256: Digest
    exposure_artifact_sha256: Digest
    purpose: Literal["private_reproducibility_only"] = "private_reproducibility_only"
    synthetic_only_attested: Literal[True]
    secret_free_attested: Literal[True]
    owned_project_attested: Literal[True]
    valid_from: datetime
    valid_until: datetime
    artifacts: tuple[ReleasedArtifact, ...] = Field(min_length=1, max_length=512)

    @model_validator(mode="after")
    def interval(self) -> ReleaseAuthorization:
        if (self.valid_from.tzinfo is None or self.valid_until.tzinfo is None
                or self.valid_until <= self.valid_from):
            raise ValueError("aware bounded release authorization interval required")
        ids = [row.artifact_id for row in self.artifacts]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate released artifact")
        if not self.authorized_by.strip() or not self.custodian.strip():
            raise ValueError("release authorizer/custodian identity required")
        return self


class CopiedArtifact(ManifestWire):
    artifact_id: OpaqueId
    path: str
    sha256: Digest
    bytes: int = Field(ge=0)


class AssemblyReceipt(ManifestWire):
    schema_version: Literal[1] = 1
    product: Literal["iac-plan-risk-reviewer"] = "iac-plan-risk-reviewer"
    run_id: OpaqueId
    mode: Literal["metadata_only", "consumed_synthetic_copy"]
    run_manifest_sha256: Digest
    selection_sha256: Digest
    release_authorization_sha256: Digest | None
    copied: tuple[CopiedArtifact, ...]
    omitted_artifact_ids: tuple[OpaqueId, ...]
    payloads_included: int = Field(ge=0)
    product_acceptance: Literal[False] = False
    authorship_authenticated: Literal[False] = False
    external_authorization_authenticated: Literal[False] = False


def root_digest(path: Path) -> str:
    """Local scope binding only, never an outward source-path projection."""
    return sha256(os.path.normcase(str(path.absolute())).encode("utf-8")).hexdigest()


def _bytes(value) -> bytes:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + "\n").encode("utf-8")


def _check_root(path: Path, *, exists: bool) -> Path:
    path = path.absolute()
    if any(p.is_symlink() or (hasattr(p, "is_junction") and p.is_junction()) for p in (path, *path.parents)):
        raise ValueError("bundle root traverses a link/junction")
    if exists and not path.is_dir():
        raise ValueError("source bundle root must be an existing directory")
    if not exists and (path.exists() or not path.parent.is_dir()):
        raise ValueError("assembly destination must be fresh under an existing parent")
    return path


def select_artifacts(manifest: RunManifest, include_consumed_payloads: bool,
                     authorization: ReleaseAuthorization | None,
                     expected_authorization_sha256: str | None, state: str) -> tuple[ArtifactRef, ...]:
    """Select metadata first; no payload is selected without explicit external release."""
    selected = [row for row in manifest.artifacts if row.role in METADATA_PATHS]
    if any(row.path != METADATA_PATHS[row.role] for row in selected):
        raise ValueError("metadata artifact path is not allowlisted")
    if any(row.artifact_id == "run-manifest" for row in manifest.artifacts):
        raise ValueError("run-manifest artifact identity is reserved")
    if not include_consumed_payloads:
        if authorization is not None or expected_authorization_sha256 is not None:
            raise ValueError("release authorization supplied without explicit payload opt-in")
        return tuple(selected)
    if (authorization is None or expected_authorization_sha256 is None
            or metadata_digest(authorization) != expected_authorization_sha256):
        raise ValueError("payload copy requires externally pinned release authorization")
    if (manifest.stage != "evaluation" or state != "consumed_holdout"
            or manifest.edition_state != "consumed_holdout"
            or authorization.edition_id != manifest.edition_id
            or authorization.run_manifest_sha256 != metadata_digest(manifest)):
        raise ValueError("only exact consumed synthetic edition may be released")
    now = datetime.now(timezone.utc)
    if not authorization.valid_from <= now <= authorization.valid_until:
        raise ValueError("release authorization expired or not yet valid")
    by_id = {row.artifact_id: row for row in manifest.artifacts}
    for allowed in authorization.artifacts:
        ref = by_id.get(allowed.artifact_id)
        if (ref is None or ref.role != allowed.role or ref.sha256 != allowed.sha256
                or ref.role not in PAYLOAD_PREFIXES or ref.visibility != "private"
                or not ref.path.startswith(PAYLOAD_PREFIXES[ref.role])):
            raise ValueError("released artifact is absent, outside synthetic allowlist or hash mismatched")
        if any(part in ref.path.casefold() for part in (
                "credential", "secret", "private-map", "private_map", "auth.json", "token")):
            raise ValueError("credential/secret/private-map path may never be copied")
        selected.append(ref)
    return tuple(selected)


def _read_verified(root: Path, ref: ArtifactRef, check) -> bytes:
    check()
    path = checked_path(root, ref)
    cap = min(ref.bytes_upper, 4 * 1024 * 1024) if ref.role in METADATA_PATHS else ref.bytes_upper
    if not path.is_file() or path.stat().st_size > cap:
        raise ValueError("selected bundle artifact absent or oversized")
    with path.open("rb") as stream:
        raw = stream.read(cap + 1)
    check()
    if len(raw) > cap or sha256(raw).hexdigest() != ref.sha256:
        raise ValueError("selected artifact bytes differ from authorized hash/bound")
    return raw


def assemble(root: Path, out: Path, manifest: RunManifest, pins: PreflightPins,
             selection: AssemblySelection, expected_selection_sha256: str, *,
             include_consumed_payloads: bool = False,
             authorization: ReleaseAuthorization | None = None,
             expected_authorization_sha256: str | None = None) -> AssemblyReceipt:
    """Copy exact bounded bytes only when invoked later under explicit authorization.

    All checks/reads precede destination creation. A final COMPLETE state is the
    sole publication boundary; no runtime acceptance or release publication follows.
    """
    root = _check_root(root, exists=True)
    out = _check_root(out, exists=False)
    if root == out or root.is_relative_to(out) or out.is_relative_to(root):
        raise ValueError("assembly source and destination may not overlap")
    if (metadata_digest(selection) != expected_selection_sha256
            or selection.run_id != manifest.run_id
            or selection.run_manifest_sha256 != pins.run_manifest_sha256
            or selection.source_root_sha256 != root_digest(root)
            or selection.output_root_sha256 != root_digest(out)):
        raise ValueError("assembly selection lacks exact externally approved roots/run pin")
    deadline = monotonic() + selection.max_seconds

    def check() -> None:
        if monotonic() > deadline:
            raise ValueError("bundle_assembly_time_limit")

    check()
    status = preflight(root, manifest, pins)  # Metadata only; never opens payloads.
    check()
    refs = select_artifacts(manifest, include_consumed_payloads, authorization,
                            expected_authorization_sha256, status["edition_state"])
    if include_consumed_payloads:
        seal_ref = next(row for row in refs if row.role == "seal")
        exposure = next((row for row in refs if row.role == "exposure"), None)
        seal = Seal.model_validate_json(json.dumps(read_metadata(root, seal_ref)))
        if (authorization.custodian != seal.custodian or exposure is None
                or authorization.exposure_artifact_sha256 != exposure.sha256):
            raise ValueError("release custody/consumption record does not match exact seal")
    data = {"metadata/run-manifest.json": _bytes(manifest)}
    copies = [CopiedArtifact(artifact_id="run-manifest", path="metadata/run-manifest.json",
                             sha256=sha256(data["metadata/run-manifest.json"]).hexdigest(),
                             bytes=len(data["metadata/run-manifest.json"]))]
    total = len(data["metadata/run-manifest.json"])
    if total > selection.max_total_bytes:
        raise ValueError("manifest exceeds assembly byte cap")
    for ref in refs:
        check()
        if ref.path in data or ref.bytes_upper > selection.max_total_bytes - total:
            raise ValueError("duplicate path or declared artifact exceeds remaining byte cap")
        if ref.role in METADATA_PATHS and ref.path != METADATA_PATHS[ref.role]:
            raise ValueError("metadata role path is not allowlisted")
        raw = _read_verified(root, ref, check)
        total += len(raw)
        if total > selection.max_total_bytes:
            raise ValueError("assembly exceeds byte cap")
        data[ref.path] = raw
        copies.append(CopiedArtifact(artifact_id=ref.artifact_id, path=ref.path,
                                     sha256=sha256(raw).hexdigest(), bytes=len(raw)))
    selected_ids = {ref.artifact_id for ref in refs}
    receipt = AssemblyReceipt(
        run_id=manifest.run_id, mode="consumed_synthetic_copy" if include_consumed_payloads else "metadata_only",
        run_manifest_sha256=pins.run_manifest_sha256, selection_sha256=expected_selection_sha256,
        release_authorization_sha256=expected_authorization_sha256,
        copied=tuple(copies), omitted_artifact_ids=tuple(
            ref.artifact_id for ref in manifest.artifacts if ref.artifact_id not in selected_ids),
        payloads_included=sum(ref.role in PAYLOAD_PREFIXES for ref in refs))
    receipt_raw = _bytes(receipt)
    data["assembly-receipt.json"] = receipt_raw
    data["assembly-receipt.sha256"] = (sha256(receipt_raw).hexdigest() + "\n").encode("ascii")
    aborted_raw = _bytes({"state": "ABORTED", "reason": "assembly_not_finalized"})
    complete_raw = _bytes({"state": "COMPLETE", "mode": receipt.mode})
    if sum(len(raw) for raw in data.values()) + len(aborted_raw) + len(complete_raw) > selection.max_total_bytes:
        raise ValueError("receipt overhead exceeds assembly byte cap")
    check()
    out.mkdir(exist_ok=False)
    created = []
    directories = []
    state_path = out / "assembly-state.json"

    def write_new(path: Path, raw: bytes) -> None:
        if (not path.is_relative_to(out)
                or any(p.is_symlink() or (hasattr(p, "is_junction") and p.is_junction())
                       for p in (path, *path.parents))):
            raise ValueError("assembly output path escaped or changed to link")
        with path.open("xb") as stream:
            created.append(path)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())

    write_new(state_path, aborted_raw)
    try:
        for name, raw in data.items():
            check()
            path = out.joinpath(*name.split("/"))
            parents = []
            parent = path.parent
            while parent != out:
                parents.append(parent)
                parent = parent.parent
            for parent in reversed(parents):
                if not parent.exists():
                    parent.mkdir(exist_ok=False)
                    directories.append(parent)
                if parent.is_symlink() or (hasattr(parent, "is_junction") and parent.is_junction()):
                    raise ValueError("assembly output changed to link")
            write_new(path, raw)
        check()
        if authorization is not None and datetime.now(timezone.utc) > authorization.valid_until:
            raise ValueError("release authorization expired during assembly")
        final_state = out / ".assembly-state.pending"
        write_new(final_state, complete_raw)
        check()
        os.replace(final_state, state_path)
    except BaseException:
        # Never recursively delete or touch paths not created by this invocation.
        for path in reversed(created):
            if path == state_path:
                continue
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
        for path in reversed(directories):
            try:
                path.rmdir()
            except OSError:
                pass
        raise
    return receipt


def read_control(root: Path, name: Literal["run-manifest.json", "assembly-selection.json", "release-authorization.json"]):
    """Only fixed bounded control metadata; cannot point CLI at a hidden payload."""
    if name not in {"run-manifest.json", "assembly-selection.json", "release-authorization.json"}:
        raise ValueError("control filename is not allowlisted")
    path = _check_root(root, exists=True) / "metadata" / name
    if any(p.is_symlink() or (hasattr(p, "is_junction") and p.is_junction()) for p in (path, *path.parents)):
        raise ValueError("control metadata path traverses link/junction")
    cap = 4 * 1024 * 1024
    if not path.is_file() or path.stat().st_size > cap:
        raise ValueError("assembly control metadata absent/oversized")
    with path.open("rb") as stream:
        raw = stream.read(cap + 1)
    if len(raw) > cap:
        raise ValueError("control metadata grew beyond cap")
    return json.loads(raw, object_pairs_hook=_object, parse_constant=_constant)
