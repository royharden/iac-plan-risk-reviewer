"""RV1's public policy examples, independently specified from selected-plan v1.

These are development regressions, never a sealed oracle or fresh holdout score.
Each parameter row captures a failure of a particular frozen semantic boundary.
"""
from itertools import product

import pytest

from iac_review.ingest import load_plan
from iac_review.rules import evaluate


def result_for(core_change, core_plan_file, rule, resource_type, **kwargs):
    plan = load_plan(core_plan_file([core_change(resource_type, **kwargs)]))
    return next(row for row in evaluate(plan) if row.rule_id == rule)


def ingress(**changes):
    value = {
        "type": "ingress", "protocol": "tcp", "from_port": 22, "to_port": 22,
        "cidr_blocks": ["0.0.0.0/0"], "ipv6_cidr_blocks": [],
    }
    value.update(changes)
    return value


@pytest.mark.parametrize("protocol", ["tcp", "6", "-1"])
@pytest.mark.parametrize("family", [4, 6])
def test_r1_protocol_and_ip_family_are_both_decision_dimensions(
    core_change, core_plan_file, protocol, family,
):
    # Catches treating numeric TCP or IPv6 as a negative/unsupported example.
    after = ingress(protocol=protocol)
    if family == 6:
        after.update(cidr_blocks=[], ipv6_cidr_blocks=["::/0"])
    row = result_for(core_change, core_plan_file, "R1", "aws_security_group_rule",
                     actions=("create",), after=after)
    assert (row.applicability, row.outcome, row.severity) == ("supported", "introduced_risk", 4)


@pytest.mark.parametrize("port", [443, 3306, 5432, 1433, 6379, 27017, 9200])
def test_r1_does_not_expand_the_frozen_admin_port_set(core_change, core_plan_file, port):
    # Catches accidental policy expansion: world-open database ports are outside R1.
    row = result_for(core_change, core_plan_file, "R1", "aws_security_group_rule",
                     actions=("create",), after=ingress(from_port=port, to_port=port))
    assert row.outcome == "clear"


@pytest.mark.parametrize("start,end", [(23, 3388), (0, 21), (3390, 65535)])
def test_r1_interval_excludes_both_boundary_ports(core_change, core_plan_file, start, end):
    row = result_for(core_change, core_plan_file, "R1", "aws_security_group_rule",
                     actions=("create",), after=ingress(from_port=start, to_port=end))
    assert row.outcome == "clear"


@pytest.mark.parametrize("start,end", [(23, 22), (-1, 22), (22, 65536), (True, 22), (22, "22")])
def test_r1_invalid_intervals_never_become_clean_negatives(core_change, core_plan_file, start, end):
    row = result_for(core_change, core_plan_file, "R1", "aws_security_group_rule",
                     actions=("create",), after=ingress(from_port=start, to_port=end))
    assert row.outcome == "indeterminate"


@pytest.mark.parametrize("actions", [("update",), ("delete", "create"), ("create", "delete")])
def test_r1_new_family_is_new_exposure_even_when_the_port_is_unchanged(
    core_change, core_plan_file, actions,
):
    # Catches set comparison that drops IP family and only compares port numbers.
    row = result_for(core_change, core_plan_file, "R1", "aws_security_group_rule",
                     actions=actions, before=ingress(), after=ingress(ipv6_cidr_blocks=["::/0"]))
    assert row.outcome == "introduced_risk"


@pytest.mark.parametrize("rule,resource_type,attribute", [
    ("R2", "aws_db_instance", "publicly_accessible"),
    ("R3", "aws_db_instance", "storage_encrypted"),
    ("R3", "aws_ebs_volume", "encrypted"),
])
@pytest.mark.parametrize("before,after", list(product([False, True], repeat=2)))
@pytest.mark.parametrize("actions", [("update",), ("delete", "create"), ("create", "delete")])
def test_exact_boolean_transition_table(core_change, core_plan_file, rule, resource_type,
                                        attribute, before, after, actions):
    # Expectations come directly from frozen R2/R3 truth boundaries, not detector output.
    if rule == "R2":
        expected = "clear" if not after else "unchanged_risk" if before else "introduced_risk"
    else:
        expected = "introduced_risk" if before and not after else "clear"
    row = result_for(core_change, core_plan_file, rule, resource_type, actions=actions,
                     before={attribute: before}, after={attribute: after})
    assert row.outcome == expected
    assert row.severity == 3


@pytest.mark.parametrize("attribute,rule", [("publicly_accessible", "R2"), ("storage_encrypted", "R3")])
@pytest.mark.parametrize("bad_value", [0, 1, "false", "true", None])
def test_boolean_attributes_do_not_coerce_numbers_strings_or_null(
    core_change, core_plan_file, attribute, rule, bad_value,
):
    row = result_for(core_change, core_plan_file, rule, "aws_db_instance",
                     actions=("create",), after={attribute: bad_value})
    assert row.outcome == "indeterminate"


@pytest.mark.parametrize("resource_type", ["aws_db_instance", "aws_ebs_volume"])
@pytest.mark.parametrize("actions", [("delete",), ("delete", "create"), ("create", "delete")])
@pytest.mark.parametrize("optional_paths", [None, [], [["unavailable"]]])
def test_r4_destruction_never_depends_on_optional_after_or_replacement_paths(
    core_change, core_plan_file, resource_type, actions, optional_paths,
):
    # Catches gating known destructive actions on an unknown after tree/replace_paths.
    row = result_for(core_change, core_plan_file, "R4", resource_type, actions=actions,
                     before={"tags": {"disposable": "true"}}, after=None,
                     change_fields={"after_unknown": True, "replace_paths": optional_paths})
    assert (row.outcome, row.reason_code, row.severity) == (
        "introduced_risk", "stateful_destructive_intent", 4,
    )


@pytest.mark.parametrize("resource_type", [
    "aws_instance", "aws_rds_cluster", "aws_dynamodb_table", "aws_s3_bucket",
    "aws_efs_file_system", "aws_elasticache_replication_group",
])
def test_named_unsupported_stateful_types_are_never_true_negatives(core_change, core_plan_file,
                                                                 resource_type):
    row = result_for(core_change, core_plan_file, "R4", resource_type,
                     actions=("delete",), before={"id": "synthetic"})
    assert (row.applicability, row.outcome) == ("unsupported_shape", None)
