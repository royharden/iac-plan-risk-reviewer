"""Private untrusted P text and manual assessment wires; no truth/eligibility grant."""
from __future__ import annotations

from hashlib import sha256
import json
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
OpaqueId = Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]
LimitId = Literal[
    "incomplete_plan", "errored_or_unknown", "unsupported_input", "unsupported_shape",
    "coverage_gap", "indeterminate", "decision_evidence_withheld", "supporting_evidence_omitted",
    "privacy_value_omitted", "missing_evaluation",
]
Label = Literal["supported", "contradicted", "unsupported", "unknown"]


class Wire(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")


def digest(value: Wire) -> str:
    """Canonical wire hash; private integrity metadata, never authentication."""
    raw = json.dumps(value.model_dump(mode="json"), sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True, allow_nan=False).encode("ascii")
    return sha256(raw).hexdigest()


def text_digest(text: str) -> str:
    return sha256(text.encode("utf-8")).hexdigest()


def _unique(values) -> None:
    if len(values) != len(set(values)):
        raise ValueError("duplicate catalog or actor identity")


def bounded_text(text: str) -> str:
    if len(text.encode("utf-8")) > 65_536:
        raise ValueError("private prose byte limit")
    if any((ord(char) < 32 and char not in "\n\t") or 127 <= ord(char) <= 159
           or 0x202A <= ord(char) <= 0x202E or 0x2066 <= ord(char) <= 0x2069 for char in text):
        raise ValueError("terminal or directional controls forbidden")
    return text


class DecisionReference(Wire):
    rule_id: Literal["R1", "R2", "R3", "R4"]
    outcome: Literal["introduced_risk", "unchanged_risk", "clear", "indeterminate"]
    immutable_outcome_sha256: Digest


class ExplanationArtifact(Wire):
    schema_version: Literal[1] = 1
    artifact_id: OpaqueId
    case_id: OpaqueId
    finding_id: OpaqueId
    attempt_id: OpaqueId
    generator_actor_ids: tuple[OpaqueId, ...] = Field(min_length=1, max_length=16)
    decision: DecisionReference
    source_arm: Literal["P"] = "P"
    origin: Literal["mock", "live", "replay", "unverified"] = "unverified"
    # Admission belongs to the independent provenance/scoring owner, not capture.
    live_eligible: Literal[False] = False
    raw_input_sha256: Digest
    projection_sha256: Digest
    prompt_sha256: Digest
    build_sha256: Digest
    response_sha256: Digest
    attempt_record_sha256: Digest | None = None
    price_sha256: Digest | None = None
    usage_sha256: Digest | None = None
    explanation_withheld: bool = False
    prose: str = Field(max_length=32_768)
    prose_sha256: Digest
    fact_ids: tuple[OpaqueId, ...] = Field(max_length=256)
    limitation_ids: tuple[LimitId, ...] = Field(max_length=32)

    @model_validator(mode="after")
    def pinned_text(self):
        bounded_text(self.prose)
        if text_digest(self.prose) != self.prose_sha256:
            raise ValueError("prose hash mismatch")
        for values in (self.generator_actor_ids, self.fact_ids, self.limitation_ids):
            _unique(values)
        return self


class SpanSpec(Wire):
    start: int = Field(ge=0, le=32_768)
    end: int = Field(ge=1, le=32_768)
    kind: Literal["claim", "context"]
    withheld: bool = False


class ExplicitSpans(Wire):
    spans: tuple[SpanSpec, ...] = Field(max_length=1024)


class TextSpan(SpanSpec):
    span_id: OpaqueId
    text: str = Field(min_length=1, max_length=32_768)


class ClaimInventory(Wire):
    artifact_sha256: Digest
    prose_sha256: Digest
    curator_actor_id: OpaqueId
    # External receipt is a declared pin, never an authenticated identity proof.
    curation_receipt_sha256: Digest | None = None
    spans: tuple[TextSpan, ...] = Field(max_length=1024)


class Rubric(Wire):
    schema_version: Literal[1] = 1
    rubric_id: OpaqueId
    rubric_text: str = Field(min_length=1, max_length=16_384)
    rubric_text_sha256: Digest
    required_fact_ids: tuple[OpaqueId, ...] = Field(max_length=256)
    required_limitation_ids: tuple[LimitId, ...] = Field(max_length=32)
    independent_rubric_receipt_sha256: Digest | None = None

    @model_validator(mode="after")
    def unique_requirements(self):
        bounded_text(self.rubric_text)
        if text_digest(self.rubric_text) != self.rubric_text_sha256:
            raise ValueError("rubric text hash mismatch")
        _unique(self.required_fact_ids)
        _unique(self.required_limitation_ids)
        return self


class AnnotationRow(Wire):
    claim_id: OpaqueId
    label: Label | None = None  # Blank is not the semantic label "unknown".
    withheld: bool
    critical_false: bool | None = None  # Explicit assessor input, never inferred.
    necessary_fact_ids: tuple[OpaqueId, ...] = Field(default=(), max_length=256)
    limitation_ids: tuple[LimitId, ...] = Field(default=(), max_length=32)

    @model_validator(mode="after")
    def annotation_shape(self):
        _unique(self.necessary_fact_ids)
        _unique(self.limitation_ids)
        if self.label is None:
            if self.critical_false is not None or self.necessary_fact_ids or self.limitation_ids:
                raise ValueError("blank label cannot contain a semantic annotation")
        elif self.critical_false is None:
            raise ValueError("completed label requires an explicit critical-false answer")
        elif self.critical_false and self.label not in ("contradicted", "unsupported"):
            raise ValueError("critical false requires a contradicted or unsupported claim")
        return self


class AssessorSheet(Wire):
    artifact_sha256: Digest
    inventory_sha256: Digest
    rubric_sha256: Digest
    assessor_id: OpaqueId
    review_receipt_sha256: Digest | None = None
    rows: tuple[AnnotationRow, ...] = Field(max_length=1024)


class AdjudicationSheet(Wire):
    artifact_sha256: Digest
    inventory_sha256: Digest
    rubric_sha256: Digest
    first_sheet_sha256: Digest
    second_sheet_sha256: Digest
    adjudicator_id: OpaqueId
    review_receipt_sha256: Digest | None = None
    rows: tuple[AnnotationRow, ...] = Field(max_length=1024)


def span_id(artifact: ExplanationArtifact, spec: SpanSpec) -> str:
    material = f"{digest(artifact)}:{spec.start}:{spec.end}:{spec.kind}:{text_digest(artifact.prose[spec.start:spec.end])}"
    return sha256(material.encode("ascii")).hexdigest()[:32]


def validate_inventory(artifact: ExplanationArtifact, inventory: ClaimInventory) -> None:
    if inventory.artifact_sha256 != digest(artifact) or inventory.prose_sha256 != artifact.prose_sha256:
        raise ValueError("inventory artifact/text pin mismatch")
    if inventory.curator_actor_id in artifact.generator_actor_ids:
        raise ValueError("curator must be declared nonauthoring")
    cursor = 0
    ids = []
    for span in inventory.spans:
        if (span.start != cursor or not span.start < span.end <= len(artifact.prose)
                or span.text != artifact.prose[span.start:span.end]
                or span.span_id != span_id(artifact, span)
                or (artifact.explanation_withheld and span.kind == "claim" and not span.withheld)
                or (span.kind == "context" and span.withheld)):
            raise ValueError("inventory must partition exact text with stable IDs, including withheld claims")
        cursor = span.end
        ids.append(span.span_id)
    _unique(ids)
    if cursor != len(artifact.prose):
        raise ValueError("inventory dropped generated text")


def make_inventory(artifact: ExplanationArtifact, specs: tuple[SpanSpec, ...], curator_actor_id: str,
                   *, curation_receipt_sha256: str | None = None) -> ClaimInventory:
    """Apply HUMAN supplied spans only; no automatic claim extraction or labels."""
    inventory = ClaimInventory(
        artifact_sha256=digest(artifact), prose_sha256=artifact.prose_sha256,
        curator_actor_id=curator_actor_id, curation_receipt_sha256=curation_receipt_sha256,
        spans=tuple(TextSpan(**spec.model_dump(), span_id=span_id(artifact, spec),
                             text=artifact.prose[spec.start:spec.end]) for spec in specs),
    )
    validate_inventory(artifact, inventory)
    return inventory
