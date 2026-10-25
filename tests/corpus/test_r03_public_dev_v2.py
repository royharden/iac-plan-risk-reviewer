"""Independent integrity controls for the approved synthetic public dev amendment."""

import json
import shutil
from copy import deepcopy
from pathlib import Path

import pytest
from evals.scanners import public_dev_v2 as v2


def plan(after, *, unknown=None, sensitive=None, actions=None, deposed=None):
    resource = {
        "address": "aws_ebs_volume.public",
        "mode": "managed",
        "type": "aws_ebs_volume",
        "name": "public",
        "provider_name": "registry.terraform.io/hashicorp/aws",
        "change": {
            "actions": actions or ["update"],
            "before": {"encrypted": True},
            "after": after,
            "after_unknown": {} if unknown is None else unknown,
            "after_sensitive": {} if sensitive is None else sensitive,
        },
    }
    if deposed is not None:
        resource["deposed"] = deposed
    return {
        "format_version": "1.2",
        "complete": True,
        "errored": False,
        "resource_changes": [resource],
        "unrelated_public_metadata": {"flag": False, "n": 0},
    }


def projected(source):
    result, notes = v2.project_plan(source)
    assert v2.canonical(
        {k: value for k, value in result.items() if k != "planned_values"}
    ) == v2.canonical(source)
    assert "configuration" not in result
    return result["planned_values"]["root_module"]["resources"], notes


def test_unknown_attributes_omitted_known_null_preserved_and_source_unchanged():
    """what_bug_this_catches: after_unknown is ignored and contradictory values enter scanner input."""
    source = plan(
        {"known_null": None, "hidden": "contradiction", "nested": {"hide": 1, "keep": True}},
        unknown={"hidden": True, "nested": {"hide": True}},
    )
    before = deepcopy(source)
    rows, _ = projected(source)
    assert rows[0]["values"] == {"known_null": None, "nested": {"keep": True}}
    assert source == before


def test_unknown_array_positions_become_null_without_collapsing_known_null():
    """what_bug_this_catches: dropping unknown list elements shifts later source positions."""
    source = plan(
        {"items": [0, "unknown", None, {"hide": 1, "keep": 2}]},
        unknown={"items": [False, True, False, {"hide": True}]},
    )
    rows, _ = projected(source)
    assert rows[0]["values"]["items"] == [0, None, None, {"keep": 2}]
    assert source["resource_changes"][0]["change"]["after"]["items"][1:3] == ["unknown", None]
    assert source["resource_changes"][0]["change"]["after_unknown"]["items"][1:3] == [True, False]


@pytest.mark.parametrize("mask", [True, {"encrypted": True}, {"nested": {"token": True}}])
def test_sensitivity_metadata_is_faithful(mask):
    """what_bug_this_catches: v2 resets masks while copying known sensitive values."""
    rows, _ = projected(plan({"encrypted": False}, sensitive=mask))
    assert rows[0]["sensitive_values"] == mask
    assert rows[0]["schema_version"] == 0


def test_whole_after_unknown_has_no_contradictory_known_fields():
    rows, notes = projected(plan({"encrypted": False}, unknown=True))
    assert rows[0]["values"] == {}
    assert notes[0]["reason"] == "unknown_after_root_withheld"


@pytest.mark.parametrize(
    ("after", "actions", "deposed", "reason"),
    [
        (None, ["delete"], None, "delete_only_has_no_planned_resource"),
        ({"encrypted": False}, ["delete"], None, "delete_only_has_no_planned_resource"),
        (None, ["update"], None, "null_after_has_no_planned_resource"),
        ({"encrypted": False}, ["update"], "public-old", "deposed_identity_not_projected"),
    ],
)
def test_absent_future_resources_never_get_callback_placeholders(after, actions, deposed, reason):
    """what_bug_this_catches: prior/deleted/deposed state invented as planned state to make a scanner run."""
    rows, notes = projected(plan(after, actions=actions, deposed=deposed))
    assert rows == [] and notes[0]["reason"] == reason


@pytest.mark.parametrize("mask", [1, "true", {"encrypted": {"wrong": True}}])
def test_invalid_unknown_masks_refuse_instead_of_becoming_known(mask):
    with pytest.raises(ValueError, match="unknown mask"):
        v2.project_plan(plan({"encrypted": False}, unknown=mask))


def test_generator_preserves_all_original_bytes_lineage_and_policy_labels(tmp_path):
    """what_bug_this_catches: the new edition overwrites originals or silently derives new labels."""
    root = Path(__file__).resolve().parents[2]
    for relative in ("fixtures/scenarios/dev", "fixtures/expected/dev"):
        shutil.copytree(root / relative, tmp_path / relative)
    old = json.loads((tmp_path / v2.OLD_MANIFEST).read_bytes())
    before = {row["path"]: (tmp_path / row["path"]).read_bytes() for row in old["cases"]}
    result = v2.generate(tmp_path)
    assert result["scenario_count"] == 24 and result["additional_independent_scenarios"] == 0
    assert result["producer_provider_compatibility_tested"] is False
    assert v2.generate(tmp_path) == result
    labels = {
        row["case_id"]: row
        for row in json.loads((tmp_path / v2.RELATIVE / "expected.json").read_bytes())["cases"]
    }
    for original, new in zip(old["cases"], result["cases"], strict=True):
        old_bytes = (tmp_path / original["path"]).read_bytes()
        assert old_bytes == before[original["path"]]
        assert new["original_sha256"] == v2.sha(old_bytes) == original["sha256"]
        raw = (tmp_path / new["path"]).read_bytes()
        assert v2.sha(raw) == new["sha256"] == labels[new["case_id"]]["sha256"]
        assert b"\n" not in raw and b"\r" not in raw
        changed = json.loads(raw)
        assert v2.canonical(
            {k: value for k, value in changed.items() if k != "planned_values"}
        ) == v2.canonical(json.loads(old_bytes))
        for key in ("rule_id", "applicability", "outcome"):
            assert labels[new["case_id"]][key] == original[key]
        assert "outcome" not in new and "rule_id" not in new
    path = tmp_path / result["cases"][0]["path"]
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(ValueError, match="immutable"):
        v2.generate(tmp_path)


def test_new_output_cannot_publish_through_a_linked_ancestor(tmp_path):
    """what_bug_this_catches: a nonexistent output file bypasses a linked-parent refusal."""
    root = Path(__file__).resolve().parents[2]
    for relative in ("fixtures/scenarios/dev", "fixtures/expected/dev"):
        shutil.copytree(root / relative, tmp_path / relative)
    edition = tmp_path / v2.RELATIVE
    edition.mkdir(parents=True)
    outside = tmp_path / "outside-edition"
    outside.mkdir()
    (edition / "plans").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="linked"):
        v2.generate(tmp_path)
    assert list(outside.iterdir()) == []
