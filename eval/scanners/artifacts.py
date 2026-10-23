"""Import separately captured scanner results without treating agreement as oracle truth."""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Wire(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")


class Mapping(Wire):
    arm: Literal["C", "C-custom", "T"]
    scanner_name: Literal["checkov", "trivy"]
    version: str
    executable_sha256: str
    policy_sha256: str
    rule_id: Literal["R1", "R2", "R3", "R4"]
    check_ids: tuple[str, ...]
    supported_actions: tuple[tuple[str, ...], ...]
    supported_types: tuple[str, ...]
    input_kind: Literal["terraform-plan-json"] = "terraform-plan-json"
    source_enrichment: Literal[False] = False
    compatibility: Literal["unverified", "verified", "incompatible"]
    compatibility_evidence_sha256: str | None = None
    int_disposition: str | None = None

    @model_validator(mode="after")
    def validate_mapping(self) -> Mapping:
        if (self.arm in {"C", "C-custom"}) != (self.scanner_name == "checkov"):
            raise ValueError("scanner arm/name mismatch")
        if not self.version or not self.executable_sha256 or not self.policy_sha256:
            raise ValueError("exact scanner, binary and policy pins required")
        if self.compatibility != "unverified" and not self.compatibility_evidence_sha256:
            raise ValueError("compatibility decision needs concrete evidence")
        if self.compatibility == "incompatible" and not self.int_disposition:
            raise ValueError("incompatible arm requires delivery INT disposition")
        if self.compatibility == "verified" and not self.check_ids:
            raise ValueError("verified overlap must identify checks")
        return self


class Capture(Wire):
    arm: Literal["C", "C-custom", "T"]
    plan_sha256: str
    scanner_version: str
    executable_sha256: str
    config_sha256: str
    enabled_check_ids: tuple[str, ...]
    status: Literal["ok", "timeout", "error", "not_run"]
    raw_exit_code: int | None = None
    stdout_sha256: str | None = None
    stderr_sha256: str | None = None
    elapsed_seconds: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    output_truncated: bool = False
    source_enrichment: Literal[False] = False
    reason: str | None = None


def verify_capture(capture: Capture, mapping: Mapping, plan_path: Path) -> None:
    if plan_path.is_symlink() or not plan_path.is_file():
        raise ValueError("scanner input must be the same regular saved JSON plan")
    if plan_path.stat().st_size > 16 * 1024 * 1024:
        raise ValueError("scanner plan exceeds byte cap")
    if hashlib.sha256(plan_path.read_bytes()).hexdigest() != capture.plan_sha256:
        raise ValueError("scanner did not receive identical frozen plan bytes")
    if capture.arm != mapping.arm or capture.scanner_version != mapping.version \
            or capture.executable_sha256 != mapping.executable_sha256:
        raise ValueError("scanner capture differs from declared mapping pins")
    if not set(mapping.check_ids).issubset(capture.enabled_check_ids):
        raise ValueError("mapped checks were not all enabled")
    if capture.status == "ok":
        if mapping.compatibility != "verified":
            raise ValueError("unverified compatibility cannot yield scored scanner evidence")
        if capture.raw_exit_code is None or not capture.stdout_sha256 \
                or capture.elapsed_seconds is None or capture.output_truncated:
            raise ValueError("successful scanner capture lacks complete bounded raw evidence")


def overlap_status(mapping: Mapping, action: tuple[str, ...], resource_type: str) -> str:
    if mapping.compatibility != "verified":
        return "unverified"
    if action not in mapping.supported_actions or resource_type not in mapping.supported_types:
        return "unmapped"
    return "eligible"
