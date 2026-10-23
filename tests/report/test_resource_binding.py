"""F1: a valid locator for B must never support a finding displayed under A.

Regression source only; not executed during Dirty Mode.
"""
import pytest

from iac_review import report as reporting
from iac_review.contracts import (
    EvidenceRef, PlanDocument, PlanIdentity, ResolvedEvidence, ResourceChange,
    RuleEvaluation, ValueState,
)


@pytest.mark.parametrize("foreign_field", ["key", "index", "both"])
@pytest.mark.parametrize("role", ["decision", "supporting"])
def test_foreign_reference_is_not_resolved_or_displayed(monkeypatch, foreign_field, role):
    resources = tuple(ResourceChange(
        key=f"resource-{index}", index=index, address=f"aws_db_instance.synthetic{index}",
        provider_name="registry.terraform.io/hashicorp/aws", mode="managed",
        type="aws_db_instance", name=f"synthetic{index}", actions=("update",),
    ) for index in range(2))
    plan = PlanDocument(
        identity=PlanIdentity(sha256="a" * 64, format_version="1.2", complete=True, errored=False),
        source_path="not-opened.json", raw={}, resources=resources,
    )

    def ref(resource, fact_id):
        return EvidenceRef(
            fact_id=fact_id, plan_sha256=plan.identity.sha256,
            resource_key=resource.key, resource_index=resource.index, side="metadata",
            pointer=f"/resource_changes/{resource.index}/mode",
            expected=ValueState(state="known", value="managed"), role="decision",
        )

    own = ref(resources[0], "own")
    updates = {}
    if foreign_field in {"key", "both"}:
        updates["resource_key"] = resources[1].key
    if foreign_field in {"index", "both"}:
        updates["resource_index"] = 1
        updates["pointer"] = "/resource_changes/1/mode"
    foreign = own.model_copy(update={**updates, "fact_id": "foreign", "role": role})
    rows = []
    for resource in resources:
        for rule in ("R1", "R2", "R3", "R4"):
            decision = (ref(resource, f"{resource.index}-{rule}"),)
            supporting = ()
            if resource.index == 0 and rule == "R2":
                if role == "decision":
                    decision = (foreign,)
                else:
                    supporting = (foreign,)
            rows.append(RuleEvaluation(
                evaluation_id=f"evaluation-{resource.index}-{rule}", resource_key=resource.key,
                rule_id=rule, severity=3, applicability="supported", outcome="clear",
                reason_code="synthetic_clear", decision_refs=decision, supporting_refs=supporting,
            ))
    resolved_ids = []

    def resolve(_plan, evidence):
        resolved_ids.append(evidence.fact_id)
        return ResolvedEvidence(ref=evidence, status="resolved", value=evidence.expected)

    monkeypatch.setattr(reporting, "verify_unchanged", lambda _plan: None)
    monkeypatch.setattr(reporting, "resolve", resolve)
    result = reporting.build_report(plan, tuple(rows))
    target = next(row for row in result.private["evaluations"]
                  if row["address"] == resources[0].address and row["rule_id"] == "R2")
    assert "foreign" not in resolved_ids
    if role == "decision":
        assert target["facts"] == []
        assert target["outcome"] == "indeterminate"
        assert result.exit_code == 2
        assert result.private["evidence_failures"][0]["status"] == "mismatch"
    else:
        assert len(target["facts"]) == 1
        assert target["outcome"] == "clear"
        assert "supporting_evidence_omitted" in target["limitation_ids"]
        assert result.exit_code == 0
