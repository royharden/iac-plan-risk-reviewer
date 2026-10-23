"""Privacy-preserving M inputs and independent P annotation scoring, offline only."""
from __future__ import annotations

from collections import Counter
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict

from iac_review.contracts import AWS_PROVIDER, PlanDocument
from iac_review.evidence import read_value


class Wire(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")


class SafeFact(Wire):
    fact_id: str
    side: Literal["before", "after"]
    field: Literal["type", "protocol", "from_port", "to_port", "cidr_blocks", "ipv6_cidr_blocks",
                   "publicly_accessible", "storage_encrypted", "encrypted", "prior_exists"]
    state: Literal["known", "null", "absent", "unknown", "withheld"]
    value: bool | int | float | str | list[str] | None = None


class SafeResource(Wire):
    resource_id: str
    type: Literal["aws_security_group_rule", "aws_db_instance", "aws_ebs_volume", "unsupported"]
    mode: Literal["managed", "data", "unsupported"]
    canonical_provider: bool
    actions: tuple[str, ...]
    facts: tuple[SafeFact, ...]


class ModelOnlyRequest(Wire):
    case_id: str
    policy_version: Literal["1.0.0"] = "1.0.0"
    resources: tuple[SafeResource, ...]
    policy: tuple[str, ...] = (
        "R1: new world IPv4/IPv6 ingress TCP or all-protocol exposure on 22/3389 only.",
        "R2: create known publicly accessible or known false-to-true RDS public flag.",
        "R3: known true-to-false RDS/EBS encryption removal on update/replacement.",
        "R4: existing RDS/EBS delete or either ordered replacement; never suppress by tags.",
        "Unknown/sensitive necessary facts are indeterminate. Unsupported shapes are not negatives.",
    )


class Prediction(Wire):
    resource_id: str
    rule_id: Literal["R1", "R2", "R3", "R4"]
    outcome: Literal["introduced_risk", "unchanged_risk", "clear", "indeterminate"]
    fact_ids: tuple[str, ...]


def model_only_input(plan: PlanDocument) -> tuple[ModelOnlyRequest, dict]:
    """No D finding, gold label, split, scanner output, address or pointer enters M.

    Mapping is a separate private return; never send or serialize it with the request.
    Unknown/sensitive sources retain explicit coverage loss rather than false values.
    """
    private_map = {}
    resources = []
    fields = ("type", "protocol", "from_port", "to_port", "cidr_blocks", "ipv6_cidr_blocks",
              "publicly_accessible", "storage_encrypted", "encrypted")
    allowed_actions = {("no-op",), ("create",), ("read",), ("update",), ("delete",),
                       ("delete", "create"), ("create", "delete")}
    for resource in plan.resources:
        opaque = uuid4().hex
        private_map[opaque] = resource.key
        facts = []
        for side in ("before", "after"):
            for field in fields:
                value = read_value(resource, side, (field,))
                projected = None
                state = "withheld" if value.sensitive else value.state
                if state == "known":
                    raw = value.value
                    if field in {"publicly_accessible", "storage_encrypted", "encrypted"}:
                        safe = type(raw) is bool
                    elif field in {"from_port", "to_port"}:
                        safe = type(raw) is int and -1 <= raw <= 65535
                    elif field == "type":
                        safe = raw in ("ingress", "egress") if type(raw) is str else False
                    elif field == "protocol":
                        safe = raw in ("tcp", "6", "-1", "udp", "17", "icmp", "icmpv6") \
                            if type(raw) is str else False
                    else:
                        # Only policy-bearing world CIDRs are exported; private CIDRs are omitted.
                        # This is disclosed coverage loss, never an invented empty/non-world list.
                        safe = type(raw) is list and all(
                            type(item) is str and item in ("0.0.0.0/0", "::/0") for item in raw)
                    if safe:
                        projected = raw
                    else:
                        state = "withheld"
                fact_id = uuid4().hex
                facts.append(SafeFact(fact_id=fact_id, side=side, field=field,
                                      state=state, value=projected))
                private_map[fact_id] = (resource.key, side, field)
        prior = read_value(resource, "before", ())
        prior_state = "withheld" if prior.sensitive else prior.state
        prior_id = uuid4().hex
        facts.append(SafeFact(fact_id=prior_id, side="before", field="prior_exists",
                              state=prior_state,
                              value=(prior.state == "known")
                              if prior_state in ("known", "null", "absent") else None))
        private_map[prior_id] = (resource.key, "before", ())
        resources.append(SafeResource(
            resource_id=opaque,
            type=resource.type if resource.type in (
                "aws_security_group_rule", "aws_db_instance", "aws_ebs_volume") else "unsupported",
            mode=resource.mode if resource.mode in ("managed", "data") else "unsupported",
            canonical_provider=resource.provider_name == AWS_PROVIDER,
            actions=resource.actions if resource.actions in allowed_actions else ("unsupported",),
            facts=tuple(facts)))
    return ModelOnlyRequest(case_id=uuid4().hex, resources=tuple(resources)), private_map


def validate_predictions(request: ModelOnlyRequest, predictions: tuple[Prediction, ...]) -> None:
    allowed = {row.resource_id: {fact.fact_id for fact in row.facts} for row in request.resources}
    seen = set()
    for prediction in predictions:
        key = prediction.resource_id, prediction.rule_id
        if key in seen or prediction.resource_id not in allowed:
            raise ValueError("duplicate or foreign model-only prediction")
        seen.add(key)
        if not set(prediction.fact_ids).issubset(allowed[prediction.resource_id]):
            raise ValueError("foreign model-only fact id")
    # Missing rows are deliberately not filled in: scorer counts abstention/misses.


class ClaimAssessment(Wire):
    claim_id: str
    assessor_id: str
    label: Literal["supported", "contradicted", "unsupported", "unknown"]
    withheld: bool = False
    necessary_fact_ids: tuple[str, ...] = ()
    limitation_ids: tuple[str, ...] = ()


def prose_metrics(claim_ids: tuple[str, ...], first: tuple[ClaimAssessment, ...],
                  second: tuple[ClaimAssessment, ...], expected_facts: set[str],
                  expected_limits: set[str], generator_authors: set[str],
                  adjudicated: dict[str, ClaimAssessment] | None = None) -> dict:
    """Both independent assessors score ALL generated claims, including withheld ones."""
    if len(set(claim_ids)) != len(claim_ids):
        raise ValueError("duplicate generated claim id")
    records = []
    assessors = []
    for assessment in (first, second):
        mapping = {row.claim_id: row for row in assessment}
        if len(mapping) != len(assessment) or set(mapping) != set(claim_ids):
            raise ValueError("each assessor must annotate every generated claim")
        identities = {row.assessor_id for row in assessment}
        if claim_ids and (len(identities) != 1 or identities & generator_authors):
            raise ValueError("assessor must be independent and consistent")
        assessors.append(identities)
        records.append(mapping)
    if claim_ids and assessors[0] == assessors[1]:
        raise ValueError("two different rubric assessors required")
    counts = Counter()
    facts = set()
    limits = set()
    disagreements = []
    for claim in claim_ids:
        a, b = records[0][claim], records[1][claim]
        same = (a.label, a.withheld, set(a.necessary_fact_ids), set(a.limitation_ids)) == (
            b.label, b.withheld, set(b.necessary_fact_ids), set(b.limitation_ids))
        selected = a
        if not same:
            disagreements.append(claim)
            selected = (adjudicated or {}).get(claim)
            if selected is None:
                continue
            if selected.claim_id != claim or selected.assessor_id in (
                generator_authors | assessors[0] | assessors[1]):
                raise ValueError("adjudicator must be a third independent actor")
        counts[selected.label] += 1
        counts["withheld"] += selected.withheld
        if selected.label == "supported":
            facts.update(selected.necessary_fact_ids)
            limits.update(selected.limitation_ids)
    generated = len(claim_ids)
    unresolved = [claim for claim in disagreements if claim not in (adjudicated or {})]
    return {"generated": generated, "counts": dict(counts),
            "support_rate": counts["supported"] / generated if generated else None,
            "agreement": (generated - len(disagreements)) / generated if generated else None,
            "necessary_fact_recall": len(facts & expected_facts) / len(expected_facts)
            if expected_facts else None,
            "limitation_recall": len(limits & expected_limits) / len(expected_limits)
            if expected_limits else None,
            "unresolved_disagreements": unresolved,
            "complete": bool(generated) and not unresolved,
            "product_prose_enabled": False}
