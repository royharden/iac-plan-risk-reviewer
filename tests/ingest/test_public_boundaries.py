"""Readable parser regressions against frozen public policy; not an oracle.

Source only, not executed during Dirty Mode.
"""
from copy import deepcopy

import pytest

from iac_review.ingest import InputError, load_plan


def test_replacement_order_and_deposed_identity_are_preserved(core_change, core_plan_file):
    first = core_change(actions=("delete", "create"), deposed="old-a")
    second = core_change(actions=("create", "delete"), deposed="old-b")
    plan = load_plan(core_plan_file([first, second]))
    assert [resource.actions for resource in plan.resources] == [("delete", "create"), ("create", "delete")]
    assert [resource.deposed for resource in plan.resources] == ["old-a", "old-b"]
    assert plan.resources[0].key != plan.resources[1].key


def test_same_address_and_deposed_is_duplicate_even_at_another_index(core_change, core_plan_file):
    entry = core_change(deposed="old-a")
    with pytest.raises(InputError, match="duplicate_resource_identity"):
        load_plan(core_plan_file([entry, deepcopy(entry)]))


@pytest.mark.parametrize(("payload", "error"), [
    (b'{"format_version":"1.2","format_version":"1.2"}', "duplicate_json_key"),
    (b'\xff', "malformed_json"),
    (b'{"format_version":"1.2","ignored":NaN}', "nonfinite_json_number"),
    (b'{"format_version":"1.2","ignored":Infinity}', "nonfinite_json_number"),
    (b'{"format_version":"1.2","ignored":1e999}', "nonfinite_json_number"),
    (b'{} {}', "malformed_json"),
    (b'{"ignored":' + b'[' * 64 + b'0' + b']' * 64 + b'}', "json_depth_limit"),
])
def test_invalid_bytes_are_rejected_without_echoing_payload(tmp_path, payload, error):
    path = tmp_path / "invalid.json"
    path.write_bytes(payload)
    with pytest.raises(InputError, match=error) as caught:
        load_plan(path)
    assert str(caught.value) == error


@pytest.mark.parametrize("actions", [[], [None], "update", [""]])
def test_malformed_actions_reject_input(core_change, core_plan_file, actions):
    entry = core_change()
    entry["change"]["actions"] = actions
    with pytest.raises(InputError, match="actions_malformed"):
        load_plan(core_plan_file([entry]))


def test_unknown_action_is_coverage_loss_not_reordered_or_invented(core_change, core_plan_file):
    plan = load_plan(core_plan_file([core_change(actions=("update", "create"))]))
    assert plan.resources[0].actions == ("update", "create")
    assert plan.resources[0].action_supported is False
    assert "action_sequence_unsupported" in plan.coverage


def test_major_rejects_minor_is_unsupported_and_missing_flags_stay_missing(core_plan_file):
    with pytest.raises(InputError, match="format_major_unsupported"):
        load_plan(core_plan_file(format_version="2.0"))
    plan = load_plan(core_plan_file(format_version="1.99", omit=("complete", "errored")))
    assert plan.identity.complete is None and plan.identity.errored is None
    assert {"format_minor_unsupported", "plan_completeness_missing", "plan_error_flag_missing"} <= set(plan.coverage)
