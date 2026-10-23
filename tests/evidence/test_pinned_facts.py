"""Public evidence boundary regressions; source only during Dirty Mode."""
import pytest

from iac_review.contracts import ValueState
from iac_review.evidence import make_ref, read_value, resolve, verify_unchanged
from iac_review.ingest import SourceChangedError, load_plan


@pytest.mark.parametrize(("after", "masks", "state", "status", "sensitive"), [
    ({"nested": {"value": 7}}, {}, "known", "resolved", False),
    ({"nested": {"value": None}}, {}, "null", "resolved", False),
    ({"nested": {}}, {}, "absent", "resolved", False),
    ({"nested": {"value": 7}}, {"after_unknown": {"nested": True}}, "unknown", "unknown", False),
    ({"nested": {"value": "MASKED_CANARY"}}, {"after_sensitive": True}, "unknown", "sensitive", True),
    ({"nested": {"value": "MASKED_CANARY"}}, {"after_sensitive": {"nested": True}}, "unknown", "sensitive", True),
])
def test_parent_masks_dominate_and_absent_differs_from_null(
    core_change, core_plan_file, after, masks, state, status, sensitive,
):
    plan = load_plan(core_plan_file([core_change(after=after, change_fields=masks)]))
    resource = plan.resources[0]
    fact = read_value(resource, "after", ("nested", "value"))
    assert fact.state == state and fact.sensitive is sensitive
    result = resolve(plan, make_ref(plan, resource, "after", ("nested", "value")))
    assert result.status == status
    if sensitive or state == "unknown":
        assert result.value.value is None


def test_absence_requires_existing_parent(core_change, core_plan_file):
    plan = load_plan(core_plan_file([core_change(after={})]))
    result = resolve(plan, make_ref(plan, plan.resources[0], "after", ("missing_parent", "leaf")))
    assert result.status == "missing"


def test_rfc6901_escaping_and_corrupt_reference_rejection(core_change, core_plan_file):
    plan = load_plan(core_plan_file([core_change(after={"a/b~c": False})]))
    ref = make_ref(plan, plan.resources[0], "after", ("a/b~c",))
    assert ref.pointer.endswith("/a~1b~0c")
    assert resolve(plan, ref).value.value is False
    mutations = [
        {"plan_sha256": "0" * 64}, {"resource_key": "foreign"},
        {"pointer": ref.pointer.replace("/after/", "/before/")},
        {"expected": ValueState(state="known", value=True)},
    ]
    for mutation in mutations:
        assert resolve(plan, ref.model_copy(update=mutation)).status == "mismatch"


def test_even_whitespace_mutation_aborts_pinned_evidence(core_change, core_plan_file):
    path = core_plan_file([core_change(after={"value": False})])
    plan = load_plan(path)
    ref = make_ref(plan, plan.resources[0], "after", ("value",))
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(SourceChangedError, match="source_digest_changed"):
        verify_unchanged(plan)
    with pytest.raises(SourceChangedError, match="source_digest_changed"):
        resolve(plan, ref)
