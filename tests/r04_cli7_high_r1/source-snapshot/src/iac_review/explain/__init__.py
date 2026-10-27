"""Finite explanation selection, never free prose or a detector.

The default path is deterministic. This module contains no live provider SDK,
network call, tool API or retry. FakeSelector is explicitly plumbing-only.
"""
from __future__ import annotations

import json
from typing import Any, Literal, Protocol
from iac_review.contracts import Wire

_OUTCOMES = {
    "introduced_risk": "This supported change introduces the declared risk.",
    "unchanged_risk": "The declared risk remains present; new introduction is not claimed.",
    "clear": "This named predicate is clear within its supported facts only.",
    "indeterminate": "This predicate cannot be decided from the available safe facts.",
}
_FIELDS = {
    "type", "protocol", "from_port", "to_port", "cidr_blocks", "ipv6_cidr_blocks",
    "publicly_accessible", "storage_encrypted", "encrypted", "actions", "mode",
    "provider_name", "before", "after", "replace_paths", "prefix_list_ids",
    "source_security_group_id", "self", "source_fact",
}
_STATES = {"known", "null", "absent", "unknown", "sensitive", "present_container", "privacy_omitted"}
_SAFE_STRINGS = {
    "0.0.0.0/0", "::/0", "ingress", "egress", "tcp", "6", "-1", "udp", "17",
    "icmp", "1", "icmpv6", "58", "managed", "data", "registry.terraform.io/hashicorp/aws",
    "aws_security_group_rule", "aws_security_group", "aws_vpc_security_group_ingress_rule",
    "aws_db_instance", "aws_ebs_volume", "aws_rds_cluster", "aws_dynamodb_table",
    "aws_s3_bucket", "aws_efs_file_system", "aws_elasticache_replication_group", "aws_instance",
    "no-op", "create", "read", "update", "delete",
}
_LIMITATIONS = {
    "incomplete_plan", "errored_or_unknown", "unsupported_input", "unsupported_shape",
    "coverage_gap", "indeterminate", "decision_evidence_withheld",
    "supporting_evidence_omitted", "privacy_value_omitted", "missing_evaluation",
}
_ACTIONS = {"no-op", "create", "read", "update", "delete"}


class SafeFact(Wire):
    fact_id: str
    field: str
    side: Literal["before", "after", "actions", "metadata"]
    role: Literal["decision", "supporting"]
    state: str
    value: Any = None


class ExplanationCapsule(Wire):
    finding_id: str
    rule_id: Literal["R1", "R2", "R3", "R4"]
    outcome: Literal["introduced_risk", "unchanged_risk", "clear", "indeterminate"]
    facts: tuple[SafeFact, ...]
    required_fact_ids: tuple[str, ...]
    required_limitation_ids: tuple[str, ...]
    baseline: str


class ClauseSelection(Wire):
    template_id: Literal["outcome", "fact", "boolean_transition"]
    fact_ids: tuple[str, ...] = ()


class ExplanationResponse(Wire):
    clauses: tuple[ClauseSelection, ...]
    limitation_ids: tuple[str, ...]


class SelectionResult(Wire):
    accepted: bool
    text: str
    source: Literal["validated_selection", "deterministic_fallback"]
    reason_code: str
    selected_fact_ids: tuple[str, ...] = ()
    limitation_ids: tuple[str, ...] = ()


class SelectorPort(Protocol):
    """Future fixed-provider adapter boundary; no tools and no execution here."""

    def select(self, capsule: ExplanationCapsule) -> ExplanationResponse: ...


def _safe_opaque(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 32 and all(c in "0123456789abcdef" for c in value)


def _validate_fact(value: dict[str, Any]) -> SafeFact:
    fact = SafeFact.model_validate(value)
    if not _safe_opaque(fact.fact_id) or fact.field not in _FIELDS or fact.state not in _STATES:
        raise ValueError("capsule fact is outside the fixed safe schema")
    scalar = fact.value
    if scalar is not None and not (
        type(scalar) in {bool, int, float} or
        isinstance(scalar, str) and scalar in _SAFE_STRINGS or
        isinstance(scalar, list) and all(isinstance(v, str) and v in _ACTIONS for v in scalar)
    ):
        raise ValueError("capsule fact contains a forbidden value")
    if type(scalar) is float:
        import math
        if not math.isfinite(scalar):
            raise ValueError("non-finite capsule value")
    if fact.state != "known" and scalar is not None:
        raise ValueError("nonknown fact contains a value")
    return fact


def build_capsule(shareable: dict[str, Any], finding_id: str) -> ExplanationCapsule:
    """Construct only from the narrow report projection, never from raw input."""
    if shareable.get("projection") != "shareable":
        raise ValueError("only a shareable projection may form a provider capsule")
    if not _safe_opaque(finding_id):
        raise ValueError("finding ID is not opaque")
    matches = [row for row in shareable.get("evaluations", []) if row.get("finding_id") == finding_id]
    if len(matches) != 1:
        raise ValueError("finding is missing or ambiguous")
    row = matches[0]
    outcome = row.get("outcome")
    if outcome not in _OUTCOMES:
        raise ValueError("only supported outcomes have explanation capsules")
    facts = tuple(_validate_fact(value) for value in row.get("facts", []))
    if len(facts) > 256 or len({fact.fact_id for fact in facts}) != len(facts):
        raise ValueError("capsule fact limit or identity failure")
    limitations = set(row.get("limitation_ids", [])) | {
        value["id"] for value in shareable.get("limitations", [])
    }
    if not limitations <= _LIMITATIONS:
        raise ValueError("foreign limitation ID")
    # The baseline itself is assembled from the finite facts, not trusted prose.
    baseline = _OUTCOMES[outcome]
    baseline += " " + " ".join(_render_fact(fact) for fact in facts)
    if limitations:
        baseline += " Limitations: " + ", ".join(sorted(limitations)) + "."
    return ExplanationCapsule(
        finding_id=finding_id, rule_id=row["rule_id"], outcome=outcome,
        facts=facts, required_fact_ids=tuple(f.fact_id for f in facts if f.role == "decision"),
        required_limitation_ids=tuple(sorted(limitations)), baseline=baseline.strip(),
    )


def _render_fact(fact: SafeFact) -> str:
    label = f"{fact.side} {fact.field}"
    if fact.state == "present_container":
        return f"{label}: a container exists; its contents are not exported."
    if fact.state != "known":
        return f"{label}: {fact.state}."
    return f"{label}: {json.dumps(fact.value, ensure_ascii=True, allow_nan=False)}."


def _render_clause(
    capsule: ExplanationCapsule, clause: ClauseSelection, facts: dict[str, SafeFact],
) -> str:
    if len(set(clause.fact_ids)) != len(clause.fact_ids) or any(key not in facts for key in clause.fact_ids):
        raise ValueError("duplicate or foreign fact ID")
    selected = [facts[key] for key in clause.fact_ids]
    if clause.template_id == "outcome":
        if selected:
            raise ValueError("outcome template has no fact slots")
        return _OUTCOMES[capsule.outcome]
    if clause.template_id == "fact":
        if len(selected) != 1:
            raise ValueError("fact template requires exactly one fact")
        return _render_fact(selected[0])
    if len(selected) != 2:
        raise ValueError("boolean transition needs ordered before and after facts")
    before, after = selected
    if not (
        before.side == "before" and after.side == "after" and
        before.field == after.field and before.state == after.state == "known" and
        type(before.value) is bool and type(after.value) is bool
    ):
        raise ValueError("before/after relation is not established")
    permitted = (
        capsule.rule_id == "R2" and before.field == "publicly_accessible" and
        before.value is False and after.value is True and capsule.outcome == "introduced_risk"
    ) or (
        capsule.rule_id == "R3" and before.field in {"storage_encrypted", "encrypted"} and
        before.value is True and after.value is False and capsule.outcome == "introduced_risk"
    )
    if not permitted:
        raise ValueError("transition template predicate does not match the fixed rule result")
    return f"{before.field} changes from {str(before.value).lower()} to {str(after.value).lower()}."


def validate_selection(
    capsule: ExplanationCapsule, response: str | dict[str, Any] | ExplanationResponse,
) -> SelectionResult:
    """Return D fallback for invalid selections; never mutate a rule outcome."""
    try:
        if isinstance(response, str):
            if len(response.encode("utf-8")) > 16_384:
                raise ValueError("selector response exceeds limit")
            selected = ExplanationResponse.model_validate_json(response)
        elif isinstance(response, ExplanationResponse):
            selected = response
        else:
            # JSON decoding preserves strict wire semantics for arrays -> tuples.
            encoded = json.dumps(response, allow_nan=False)
            if len(encoded.encode("utf-8")) > 16_384:
                raise ValueError("selector response exceeds limit")
            selected = ExplanationResponse.model_validate_json(encoded)
        if not selected.clauses or len(selected.clauses) > 257:
            raise ValueError("selector clause count is invalid")
        if sum(clause.template_id == "outcome" for clause in selected.clauses) != 1:
            raise ValueError("exactly one outcome clause is mandatory")
        if set(selected.limitation_ids) != set(capsule.required_limitation_ids):
            raise ValueError("required limitations were changed or omitted")
        if len(set(selected.limitation_ids)) != len(selected.limitation_ids):
            raise ValueError("duplicate limitation")
        facts = {fact.fact_id: fact for fact in capsule.facts}
        fact_ids = tuple(key for clause in selected.clauses for key in clause.fact_ids)
        if len(set(fact_ids)) != len(fact_ids):
            raise ValueError("duplicate fact selection")
        if not set(capsule.required_fact_ids) <= set(fact_ids):
            raise ValueError("required decision facts were omitted")
        text = " ".join(_render_clause(capsule, clause, facts) for clause in selected.clauses)
        if selected.limitation_ids:
            text += " Limitations: " + ", ".join(selected.limitation_ids) + "."
        return SelectionResult(
            accepted=True, text=text, source="validated_selection", reason_code="valid_finite_selection",
            selected_fact_ids=fact_ids, limitation_ids=selected.limitation_ids,
        )
    except (ValueError, TypeError, KeyError):
        return SelectionResult(
            accepted=False, text=capsule.baseline, source="deterministic_fallback",
            reason_code="invalid_selection", selected_fact_ids=capsule.required_fact_ids,
            limitation_ids=capsule.required_limitation_ids,
        )


class FakeSelector:
    """Returns every finite fact; not a model measurement or quality claim."""

    def select(self, capsule: ExplanationCapsule) -> ExplanationResponse:
        return ExplanationResponse(
            clauses=(ClauseSelection(template_id="outcome"),) + tuple(
                ClauseSelection(template_id="fact", fact_ids=(fact.fact_id,)) for fact in capsule.facts
            ), limitation_ids=capsule.required_limitation_ids,
        )
