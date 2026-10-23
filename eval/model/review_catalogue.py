"""Safe assessor facts, separate from private locations and independent expectations."""
from __future__ import annotations

from hashlib import sha256
from html import escape
import json

from pydantic import Field, model_validator

from iac_review.explain import ExplanationCapsule, SafeFact, _validate_fact
from eval.model.explanation_artifacts import (
    Digest, ExplanationArtifact, LimitId, Wire, digest, text_digest,
)


def facts_digest(facts: tuple[SafeFact, ...]) -> str:
    raw = json.dumps([fact.model_dump(mode="json") for fact in facts], sort_keys=True,
                     separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    return sha256(raw.encode("ascii")).hexdigest()


class ReviewCatalogue(Wire):
    artifact_sha256: Digest
    prose_sha256: Digest
    capsule_sha256: Digest
    facts_sha256: Digest
    facts: tuple[SafeFact, ...] = Field(max_length=256)
    limitation_ids: tuple[LimitId, ...] = Field(max_length=32)

    @model_validator(mode="after")
    def safe_facts(self):
        # Reuse the actual product schema/value allowlist, not a parallel policy.
        for fact in self.facts:
            _validate_fact(fact.model_dump(mode="python"))
        if (len({fact.fact_id for fact in self.facts}) != len(self.facts)
                or len(set(self.limitation_ids)) != len(self.limitation_ids)
                or facts_digest(self.facts) != self.facts_sha256):
            raise ValueError("duplicate or changed safe catalogue facts")
        return self


def validate_catalogue(artifact: ExplanationArtifact, catalogue: ReviewCatalogue) -> None:
    # Revalidate on consumption: existing SafeFact.Any list values are not deeply
    # frozen; the pinned content hash detects mutation after model construction.
    ReviewCatalogue.model_validate_json(catalogue.model_dump_json())
    if (catalogue.artifact_sha256 != digest(artifact)
            or catalogue.prose_sha256 != artifact.prose_sha256
            or catalogue.capsule_sha256 != artifact.projection_sha256
            or {fact.fact_id for fact in catalogue.facts} != set(artifact.fact_ids)
            or set(catalogue.limitation_ids) != set(artifact.limitation_ids)):
        raise ValueError("catalogue artifact/capsule/text/ID binding mismatch")


def build_catalogue(artifact: ExplanationArtifact, projection_json: str) -> ReviewCatalogue:
    """Consume the EXACT captured capsule JSON, never rebuild or fetch a source."""
    if len(projection_json.encode("utf-8")) > 65_536 or text_digest(projection_json) != artifact.projection_sha256:
        raise ValueError("exact bounded projection bytes required")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate capsule JSON key")
            result[key] = value
        return result
    json.loads(projection_json, object_pairs_hook=pairs)
    capsule = ExplanationCapsule.model_validate_json(projection_json)
    if (capsule.finding_id != artifact.finding_id or capsule.rule_id != artifact.decision.rule_id
            or capsule.outcome != artifact.decision.outcome
            or not set(capsule.required_fact_ids) <= {fact.fact_id for fact in capsule.facts}):
        raise ValueError("capsule decision/identity mismatch")
    result = ReviewCatalogue(
        artifact_sha256=digest(artifact), prose_sha256=artifact.prose_sha256,
        capsule_sha256=text_digest(projection_json), facts_sha256=facts_digest(capsule.facts),
        facts=capsule.facts, limitation_ids=capsule.required_limitation_ids,
    )
    validate_catalogue(artifact, result)
    return result


def render_catalogue(artifact: ExplanationArtifact, catalogue: ReviewCatalogue) -> str:
    """Standalone escaped reference table; no private map, prose or raw source."""
    validate_catalogue(artifact, catalogue)
    rows = "".join("<tr>" + "".join(f"<td>{escape(str(value))}</td>" for value in (
        fact.fact_id, fact.side, fact.field, fact.role, fact.state,
        json.dumps(fact.value, ensure_ascii=True, allow_nan=False),
    )) + "</tr>" for fact in catalogue.facts)
    limits = "".join(f"<li>{escape(value)}</li>" for value in catalogue.limitation_ids)
    return ('<!doctype html><html><head><meta charset="utf-8">'
            '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; base-uri \'none\'; form-action \'none\'">'
            '<title>Safe review catalogue</title></head><body><h1>Safe fact reference; not semantic truth</h1>'
            f'<p>Artifact {escape(catalogue.artifact_sha256)}; capsule {escape(catalogue.capsule_sha256)}</p>'
            f'<table>{rows}</table><ul>{limits}</ul></body></html>')
