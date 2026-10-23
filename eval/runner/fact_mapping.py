"""Private independently supplied fact LOCATIONS -> per-run opaque fact IDs.

No detector/oracle import, labels or inference. Caller must already have authority
to supply these locations and original private bundle/source. Hashes do not prove it.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
from time import monotonic
from typing import Literal

from pydantic import Field, model_validator

from eval.model.explanation_artifacts import Digest, ExplanationArtifact, OpaqueId, Wire, digest
from eval.model.review_catalogue import ReviewCatalogue, validate_catalogue
from eval.runner.custody import Identity
from iac_review.evidence import make_ref, resolve, verify_unchanged
from iac_review.ingest import MAX_RESOURCES, MAX_SECONDS, decode_source, load_plan, read_source_bytes
from iac_review.source_view import verify_report, view_evidence


class ExpectedLocation(Wire):
    expected_fact_id: Identity
    resource_index: int = Field(ge=0, le=MAX_RESOURCES - 1)
    side: Literal["before", "after", "actions", "metadata"]
    tokens: tuple[str | int, ...] = Field(max_length=16)

    @model_validator(mode="after")
    def bounded_tokens(self):
        if any(type(token) is int and token < 0 or isinstance(token, str) and len(token) > 256 for token in self.tokens):
            raise ValueError("bounded nonnegative location tokens required")
        return self


class FactCorrespondence(Wire):
    expected_fact_id: Identity
    report_fact_id: OpaqueId | None = None
    status: Literal["mapped", "missing", "masked", "withheld", "foreign", "ambiguous", "unresolved"]

    @model_validator(mode="after")
    def mapped_identity(self):
        if (self.status == "mapped") != (self.report_fact_id is not None):
            raise ValueError("only mapped correspondence can supply an opaque fact ID")
        return self


class FactMapping(Wire):
    private: Literal[True] = True
    artifact_sha256: Digest
    catalogue_sha256: Digest
    case_id: OpaqueId
    resource_id: Identity  # Independent evaluator's ID, never inferred from D.
    source_sha256: Digest
    private_report_sha256: Digest
    locations_sha256: Digest
    rows: tuple[FactCorrespondence, ...] = Field(max_length=512)
    identity_authenticated: Literal[False] = False

    @model_validator(mode="after")
    def unique_correspondence(self):
        expected = [row.expected_fact_id for row in self.rows]
        actual = [row.report_fact_id for row in self.rows if row.report_fact_id is not None]
        if len(set(expected)) != len(expected) or len(set(actual)) != len(actual):
            raise ValueError("expected or run fact identities cannot collapse")
        return self


def locations_digest(locations: tuple[ExpectedLocation, ...]) -> str:
    return sha256(json.dumps([row.model_dump(mode="json") for row in locations], sort_keys=True,
                 separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")).hexdigest()


def map_facts(artifact: ExplanationArtifact, expected_resource_id: str,
              locations: tuple[ExpectedLocation, ...], *, bundle: Path, original_plan: Path,
              expected_locations_sha256: str, private_report_sha256: str,
              catalogue: ReviewCatalogue) -> FactMapping:
    """Validate exact displayed fact correspondence. Preserve EVERY expectation."""
    if (not locations or len(locations) > 512 or locations_digest(locations) != expected_locations_sha256
            or len({row.expected_fact_id for row in locations}) != len(locations)):
        raise ValueError("bounded unique independently pinned locations required")
    validate_catalogue(artifact, catalogue)
    safe_facts = {fact.fact_id: fact for fact in catalogue.facts}
    deadline = monotonic() + MAX_SECONDS
    verify_report(bundle, original_plan, deadline=deadline)
    private_bytes = read_source_bytes(Path(bundle) / "private.json")
    if sha256(private_bytes).hexdigest() != private_report_sha256:
        raise ValueError("private report differs from caller pin")
    private = decode_source(private_bytes)
    plan = load_plan(original_plan)
    if plan.identity.sha256 != artifact.raw_input_sha256:
        raise ValueError("artifact raw source pin mismatch")
    matches = [row for row in private.get("evaluations", ()) if row.get("finding_id") == artifact.finding_id]
    if len(matches) != 1 or matches[0].get("rule_id") != artifact.decision.rule_id:
        raise ValueError("exact private finding required; outcomes are not gold inputs")
    finding = matches[0]
    results = []
    for expected in locations:
        if monotonic() > deadline:
            raise ValueError("fact correspondence time limit")
        status, report_id = "missing", None
        if expected.resource_index >= len(plan.resources):
            status = "foreign"
        else:
            resource = plan.resources[expected.resource_index]
            if resource.address != finding.get("address"):
                status = "foreign"
            else:
                ref = make_ref(plan, resource, expected.side, expected.tokens)
                checked = resolve(plan, ref)
                if checked.status in ("sensitive", "unknown"):
                    status = "masked"
                elif checked.status != "resolved":
                    status = "unresolved"
                elif checked.value.state == "absent":
                    status = "missing"
                else:
                    facts = [fact for fact in finding.get("facts", ()) if fact.get("pointer") == ref.pointer]
                    if len(facts) > 1:
                        status = "ambiguous"
                    elif facts:
                        fact = facts[0]
                        report_id = fact.get("fact_id")
                        if report_id not in artifact.fact_ids:
                            status, report_id = "foreign", None
                        elif fact.get("state") in ("unknown", "sensitive", "privacy_omitted", "absent"):
                            status, report_id = "withheld", None
                        else:
                            # Existing viewer independently checks exact source/index/masks/value.
                            viewed = view_evidence(bundle, original_plan, artifact.finding_id, report_id, deadline=deadline)
                            keys = ("field", "side", "role", "state", "value")
                            safe = safe_facts[report_id].model_dump(mode="json")
                            actual = {key: viewed["fact"][key] for key in keys}
                            declared = {key: safe[key] for key in keys}
                            encoded = lambda value: json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False)
                            if encoded(actual) != encoded(declared):
                                status, report_id = "unresolved", None
                            else:
                                status = "mapped"
        results.append(FactCorrespondence(expected_fact_id=expected.expected_fact_id,
                                           report_fact_id=report_id, status=status))
    # Multiple independent expected facts must not silently collapse to one fact ID.
    counts = {}
    for row in results:
        if row.report_fact_id:
            counts[row.report_fact_id] = counts.get(row.report_fact_id, 0) + 1
    results = [row.model_copy(update={"report_fact_id": None, "status": "ambiguous"})
               if row.report_fact_id and counts[row.report_fact_id] > 1 else row for row in results]
    verify_unchanged(plan)
    verify_report(bundle, original_plan, deadline=deadline)
    if sha256(read_source_bytes(Path(bundle) / "private.json")).hexdigest() != private_report_sha256:
        raise ValueError("private report changed during correspondence")
    return FactMapping(artifact_sha256=digest(artifact), catalogue_sha256=digest(catalogue), case_id=artifact.case_id,
                       resource_id=expected_resource_id, source_sha256=plan.identity.sha256,
                       private_report_sha256=private_report_sha256, locations_sha256=expected_locations_sha256,
                       rows=tuple(results))
