"""Small developer regressions derived from the frozen public R1–R4 policy.

These expected outcomes are not independent/hidden gold. Source only in Dirty Mode.
"""
import pytest

from iac_review.ingest import load_plan
from iac_review.rules import evaluate


def one_rule(core_plan_file, entry, rule):
    return next(row for row in evaluate(load_plan(core_plan_file([entry]))) if row.rule_id == rule)


def sg(**overrides):
    facts = {"type": "ingress", "protocol": "tcp", "from_port": 22, "to_port": 22,
             "cidr_blocks": ["0.0.0.0/0"], "ipv6_cidr_blocks": []}
    facts.update(overrides)
    return facts


@pytest.mark.parametrize(("before", "after", "actions", "masks", "outcome"), [
    (None, sg(), ("create",), {}, "introduced_risk"),
    (sg(), sg(to_port=3389), ("update",), {}, "introduced_risk"),
    (sg(cidr_blocks=["0.0.0.0/0", "10.0.0.0/8"]),
     sg(cidr_blocks=["10.0.0.0/8", "0.0.0.0/0", "0.0.0.0/0"]), ("update",), {}, "unchanged_risk"),
    (sg(cidr_blocks=[], ipv6_cidr_blocks=[]), sg(cidr_blocks=[], ipv6_cidr_blocks=["::/0"]),
     ("update",), {}, "introduced_risk"),
    (sg(), sg(from_port=443, to_port=443), ("update",), {}, "clear"),
    (sg(), sg(type="egress"), ("update",), {}, None),
    (sg(), sg(), ("update",), {"after_unknown": {"from_port": True}}, "indeterminate"),
    (sg(), sg(), ("update",), {"before_sensitive": True}, "indeterminate"),
    (None, sg(cidr_blocks=["10.0.0.0/8"]), ("create",),
     {"after_unknown": {"protocol": True, "from_port": True, "to_port": True}}, "clear"),
    (None, sg(protocol="-1", from_port=None, to_port=None), ("create",), {}, "introduced_risk"),
])
def test_r1_sets_short_circuits_and_unknowns(core_change, core_plan_file, before, after, actions, masks, outcome):
    result = one_rule(core_plan_file, core_change(
        "aws_security_group_rule", actions=actions, before=before, after=after, change_fields=masks,
    ), "R1")
    assert result.outcome == outcome
    if outcome is None:
        assert result.applicability == "not_applicable"


def test_r1_supported_risk_keeps_prefix_list_coverage_gap(core_change, core_plan_file):
    result = one_rule(core_plan_file, core_change(
        "aws_security_group_rule", actions=("create",), after=sg(prefix_list_ids=["synthetic-prefix"]),
    ), "R1")
    assert result.outcome == "introduced_risk"
    assert "r1_prefix_list_source_unsupported" in result.coverage


@pytest.mark.parametrize(("actions", "before", "after", "mask", "expected"), [
    (("create",), None, True, {}, "introduced_risk"),
    (("update",), False, True, {}, "introduced_risk"),
    (("no-op",), True, True, {}, "unchanged_risk"),
    (("update",), True, False, {}, "clear"),
    (("update",), None, True, {}, "indeterminate"),
    (("update",), False, True, {"after_unknown": {"publicly_accessible": True}}, "indeterminate"),
])
def test_r2_boolean_transitions(core_change, core_plan_file, actions, before, after, mask, expected):
    result = one_rule(core_plan_file, core_change(
        actions=actions, before={"publicly_accessible": before}, after={"publicly_accessible": after},
        change_fields=mask,
    ), "R2")
    assert result.outcome == expected


@pytest.mark.parametrize(("kind", "actions", "before", "after", "unknown", "expected"), [
    ("aws_db_instance", ("create",), None, False, False, "clear"),
    ("aws_db_instance", ("update",), True, False, False, "introduced_risk"),
    ("aws_ebs_volume", ("delete", "create"), True, False, False, "introduced_risk"),
    ("aws_ebs_volume", ("update",), False, True, False, "clear"),
    ("aws_db_instance", ("no-op",), True, True, False, "clear"),
    ("aws_db_instance", ("update",), None, False, False, "indeterminate"),
    ("aws_db_instance", ("update",), True, False, True, "indeterminate"),
])
def test_r3_removal_only(core_change, core_plan_file, kind, actions, before, after, unknown, expected):
    attribute = "storage_encrypted" if kind == "aws_db_instance" else "encrypted"
    result = one_rule(core_plan_file, core_change(
        kind, actions=actions, before={attribute: before}, after={attribute: after},
        change_fields={"after_unknown": {attribute: unknown}},
    ), "R3")
    assert result.outcome == expected


@pytest.mark.parametrize("actions", [("delete",), ("delete", "create"), ("create", "delete")])
def test_r4_both_orders_and_disposable_tags_do_not_suppress(core_change, core_plan_file, actions):
    result = one_rule(core_plan_file, core_change(
        actions=actions, before={"tags": {"disposable": "true"}},
        change_fields={"before_sensitive": {"tags": True}, "replace_paths": None},
    ), "R4")
    assert result.outcome == "introduced_risk"
    assert result.reason_code == "stateful_destructive_intent"


@pytest.mark.parametrize("absent", [False, True])
def test_r4_null_or_absent_prior_is_contradictory(core_change, core_plan_file, absent):
    entry = core_change(actions=("delete",), before=None)
    if absent:
        entry["change"].pop("before")
    result = one_rule(core_plan_file, entry, "R4")
    assert result.outcome == "indeterminate"
    assert result.reason_code == "contradictory_prior_existence"


@pytest.mark.parametrize(("fields", "rule", "applicability"), [
    ({"mode": "data"}, "R2", "not_applicable"),
    ({"provider_name": "registry.terraform.io/example/aws"}, "R2", "unsupported_shape"),
    ({"type": "aws_security_group"}, "R1", "unsupported_shape"),
])
def test_domain_boundary_is_not_a_negative(core_change, core_plan_file, fields, rule, applicability):
    result = one_rule(core_plan_file, core_change(**fields), rule)
    assert result.applicability == applicability and result.outcome is None
