"""Payload-free reproducibility manifest. Claims are metadata, not authentication."""
from __future__ import annotations

from decimal import Decimal, DecimalException
from pathlib import PurePosixPath
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
OpaqueId = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")]
Arm = Literal["D", "L", "P", "M", "C", "C-custom", "T"]
Split = Literal["dev", "validation", "heldout"]
Kind = Literal["unverified", "mock", "executed", "live", "replay"]
Status = Literal["ok", "invalid", "timeout", "error", "cancelled", "not_run", "pending", "unmapped"]


class ManifestWire(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")


def amount(value: str | None) -> Decimal | None:
    if value is None:
        return None
    if len(value) > 64:
        raise ValueError("amount exceeds metadata bound")
    try:
        parsed = Decimal(value)
    except DecimalException as error:
        raise ValueError("invalid decimal amount") from error
    if not parsed.is_finite() or parsed < 0:
        raise ValueError("finite nonnegative amount required")
    return parsed


def relative_path(value: str) -> str:
    if (not value or len(value) > 240 or "\\" in value or ":" in value
            or "//" in value or value.startswith("/")
            or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-/" for char in value)):
        raise ValueError("bounded portable relative artifact path required")
    parts = value.split("/")
    reserved = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)),
                *(f"lpt{i}" for i in range(1, 10))}
    if any(part in ("", ".", "..") or part.endswith((".", " "))
           or part.split(".")[0].casefold() in reserved for part in parts):
        raise ValueError("path alias, traversal or reserved device forbidden")
    if str(PurePosixPath(value)) != value:
        raise ValueError("noncanonical relative artifact path")
    return value


class ComponentVersion(ManifestWire):
    component_id: OpaqueId
    kind: Literal["source", "parser", "rules", "prompt", "model", "scanner", "config", "corpus"]
    name: OpaqueId
    version: OpaqueId
    sha256: Digest
    compatibility: Literal["unverified", "verified", "incompatible"] = "unverified"


class CaseBinding(ManifestWire):
    case_id: OpaqueId
    split: Split
    configuration_id: OpaqueId
    family_id: OpaqueId
    mutation_lineage: OpaqueId
    raw_source_sha256: Digest
    safe_projection_sha256: Digest | None = None


class ArtifactRef(ManifestWire):
    artifact_id: OpaqueId
    role: Literal["authority", "seal", "semantic_receipt", "eligibility", "exposure",
                  "utility", "producer", "schema", "report_private", "report_shareable",
                  "case_input", "oracle", "measurements", "private_map"]
    path: str = Field(min_length=1, max_length=240)
    sha256: Digest
    bytes_upper: int = Field(ge=0, le=16 * 1024 * 1024)
    visibility: Literal["private", "shareable"] = "private"

    @model_validator(mode="after")
    def safe_reference(self) -> ArtifactRef:
        relative_path(self.path)
        if self.visibility == "shareable":
            if self.role != "report_shareable" or not self.path.startswith("shareable/"):
                raise ValueError("only a shareable report may be an outward reference")
            if any(token in self.path.casefold() for token in ("private", "oracle", "map", "secret", "token")):
                raise ValueError("private-map or sensitive outward reference forbidden")
        elif self.role == "report_shareable":
            raise ValueError("shareable report requires explicit outward visibility")
        if self.role in {"oracle", "case_input", "private_map", "measurements", "report_private"}:
            if not self.path.startswith("private/"):
                raise ValueError("private payload references must stay in private/")
        return self


class AttemptMetadata(ManifestWire):
    attempt_id: OpaqueId
    invocation_id: OpaqueId
    arm: Arm
    status: Status
    kind: Kind
    raw_source_sha256: Digest
    safe_projection_sha256: Digest | None = None
    prompt_sha256: Digest | None = None
    model_version_id: OpaqueId | None = None
    price_sha256: Digest | None = None
    start_receipt_sha256: Digest | None = None
    terminal_receipt_sha256: Digest | None = None
    known_usd: str | None = Field(default=None, max_length=64)
    billing_known: bool = False
    unresolved_usd_upper: str | None = Field(default=None, max_length=64)
    elapsed_ms: int | None = Field(default=None, ge=0)
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def billing(self) -> AttemptMetadata:
        known, upper = amount(self.known_usd), amount(self.unresolved_usd_upper)
        if self.billing_known and (known is None or upper not in (None, Decimal(0))):
            raise ValueError("known billing requires amount and no unresolved liability")
        if self.status == "pending" and (self.billing_known or self.terminal_receipt_sha256 is not None):
            raise ValueError("pending attempt cannot claim terminal billing")
        return self


class InvocationMetadata(ManifestWire):
    invocation_id: OpaqueId
    arm: Arm
    status: Status
    kind: Kind
    case_ids: tuple[OpaqueId, ...] = Field(max_length=4096)
    config_component_id: OpaqueId
    version_component_id: OpaqueId
    attempt_ids: tuple[OpaqueId, ...] = Field(max_length=10000)
    all_attempts_attested: bool = False


class EvaluationEligibility(ManifestWire):
    arm: Arm
    invocation_id: OpaqueId
    measurement_ref: OpaqueId
    raw_source_sha256: Digest
    eligibility_ref: Digest | None = None
    claimed_eligible: bool = False


class RunManifest(ManifestWire):
    schema_version: Literal[1] = 1
    stage: Literal["deterministic", "evaluation"] = "evaluation"
    run_id: OpaqueId
    edition_id: OpaqueId
    edition_state: Literal["development", "sealed", "consumed_holdout"]
    split: Split
    build_sha256: Digest
    policy_sha256: Digest
    authority_sha256: Digest | None = None
    semantic_suite_sha256: Digest | None = None
    eligibility_sha256: Digest | None = None
    components: tuple[ComponentVersion, ...] = Field(min_length=1, max_length=128)
    cases: tuple[CaseBinding, ...] = Field(max_length=4096)
    invocations: tuple[InvocationMetadata, ...] = Field(max_length=4096)
    attempts: tuple[AttemptMetadata, ...] = Field(max_length=10000)
    artifacts: tuple[ArtifactRef, ...] = Field(max_length=512)
    eligibility: tuple[EvaluationEligibility, ...] = Field(max_length=100000)
    # No raw payload, credentials, free text, path discovery or execution assertion.

    @model_validator(mode="after")
    def stage_boundary(self) -> RunManifest:
        pins = (self.authority_sha256, self.semantic_suite_sha256, self.eligibility_sha256)
        if self.stage == "evaluation":
            if any(pin is None for pin in pins):
                raise ValueError("evaluation requires authority, semantic-suite and eligibility pins")
            return self
        if (any(pin is not None for pin in pins) or self.attempts or self.eligibility or self.artifacts
                or self.edition_state != "development" or self.split != "dev"
                or len(self.cases) != 1 or len(self.invocations) != 1
                or {row.kind for row in self.components} != {"source", "parser", "rules", "config"}
                or len(self.components) != 4
                or any(row.compatibility != "unverified" for row in self.components)):
            raise ValueError("deterministic stage cannot claim custody, benchmark versions, usage or eligibility")
        invocation = self.invocations[0]
        if (invocation.arm != "D" or invocation.kind != "executed" or invocation.status != "ok"
                or invocation.attempt_ids or invocation.all_attempts_attested
                or invocation.case_ids != (self.cases[0].case_id,)):
            raise ValueError("deterministic stage requires exactly one local D-only invocation")
        return self
