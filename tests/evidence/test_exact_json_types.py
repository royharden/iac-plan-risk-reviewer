"""Exact evidence preserves JSON types recursively, including Python-equal values."""

import pytest

from iac_review.contracts import ValueState
from iac_review.evidence import make_ref, resolve
from iac_review.ingest import load_plan


@pytest.mark.parametrize("actual,corrupt", [
    pytest.param(False, 0, id="false-is-not-zero"),
    pytest.param(True, 1, id="true-is-not-one"),
    pytest.param(1, True, id="one-is-not-true"),
    pytest.param(1, 1.0, id="integer-is-not-float"),
    pytest.param(1.0, 1, id="float-is-not-integer"),
    pytest.param([1], [True], id="array-element-type"),
    pytest.param({"flag": False}, {"flag": 0}, id="object-summary-rejects-arbitrary-values"),
    pytest.param({"nested": [{"ports": [1]}]}, {"nested": [{"ports": [True]}]},
                 id="deeply-nested-element-type"),
    pytest.param({"n": 1.0}, {"n": 1}, id="nested-float-type"),
    pytest.param([1, 2], [2, 1], id="array-order"),
    pytest.param({"a": 1}, {"b": 1}, id="object-key"),
])
def test_python_equal_or_rearranged_reference_is_not_exact_source_evidence(
    core_change, core_plan_file, actual, corrupt,
):
    # Catches Pydantic/Python equality accepting another JSON type as source evidence.
    plan = load_plan(core_plan_file([core_change(after={"value": actual})]))
    ref = make_ref(plan, plan.resources[0], "after", ("value",))
    control = resolve(plan, ref)
    assert control.status == "resolved"
    assert type(control.value.value) is type(actual)
    altered = ref.model_copy(update={"expected": ValueState(state="known", value=corrupt)})
    assert resolve(plan, altered).status == "mismatch"


@pytest.mark.parametrize("value", [False, True, 0, 1, 1.0, "1", [], {},
                                   [False, 0, 0.0], {"a": [True, 1, 1.0]}])
def test_exact_same_typed_json_value_remains_resolvable(core_change, core_plan_file, value):
    plan = load_plan(core_plan_file([core_change(after={"value": value})]))
    ref = make_ref(plan, plan.resources[0], "after", ("value",))
    same = ref.model_copy(update={"expected": ref.expected.model_copy(deep=True)})
    assert resolve(plan, same).status == "resolved"


@pytest.mark.parametrize("actual,corrupt", [(False, 0), (1, True), (1, 1.0), ([1], [True])])
def test_exact_type_check_reaches_leaves_inside_nested_shapes(core_change, core_plan_file,
                                                            actual, corrupt):
    plan = load_plan(core_plan_file([core_change(after={"outer": [{"leaf": actual}]})]))
    ref = make_ref(plan, plan.resources[0], "after", ("outer", 0, "leaf"))
    assert resolve(plan, ref).status == "resolved"
    altered = ref.model_copy(update={"expected": ValueState(state="known", value=corrupt)})
    assert resolve(plan, altered).status == "mismatch"
