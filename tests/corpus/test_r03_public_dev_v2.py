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


def copied_edition(tmp_path):
    root = Path(__file__).resolve().parents[2]
    for relative in (v2.RELATIVE, Path("fixtures/expected/dev")):
        shutil.copytree(root / relative, tmp_path / relative)
    inventory = json.loads((tmp_path / v2.RELATIVE / "inventory.json").read_bytes())
    expected = json.loads((tmp_path / v2.RELATIVE / "expected.json").read_bytes())
    return inventory, expected


def write_edition(root, inventory, expected):
    for name, value in (("inventory", inventory), ("expected", expected)):
        (root / v2.RELATIVE / f"{name}.json").write_bytes(v2.canonical(value))


def refuse_plan_reads(monkeypatch):
    original = v2.read

    def guarded(path):
        assert path.parent.name != "plans", "plan read before complete metadata admission"
        return original(path)

    monkeypatch.setattr(v2, "read", guarded)


@pytest.mark.parametrize("location", ["inventory", "expected"])
@pytest.mark.parametrize("mutation", ["duplicate", "missing", "extra", "replacement"])
def test_all_case_membership_is_admitted_before_any_plan_read(
    tmp_path, monkeypatch, location, mutation
):
    """what_bug_this_catches: repeated valid IDs inflate24 successes or partial corpora run."""
    inventory, expected = copied_edition(tmp_path)
    rows = {"inventory": inventory, "expected": expected}[location]["cases"]
    if mutation == "duplicate":
        rows[:] = [deepcopy(rows[7]) for _ in range(24)]
    elif mutation == "missing":
        rows.pop()
    elif mutation == "extra":
        rows.append({**rows[-1], "case_id": "extra-valid-id"})
    else:
        rows[-1]["case_id"] = "replacement-valid-id"
    write_edition(tmp_path, inventory, expected)
    refuse_plan_reads(monkeypatch)
    with pytest.raises(ValueError):
        v2.evaluate(tmp_path)


@pytest.mark.parametrize("location", ["inventory", "expected"])
@pytest.mark.parametrize("field,value", [("edition_id", "wrong-edition"), ("split", "heldout")])
def test_wrong_edition_is_rejected_before_any_plan_read(
    tmp_path, monkeypatch, location, field, value
):
    """what_bug_this_catches: metadata can silently relabel a corpus accepted as the fixed edition."""
    inventory, expected = copied_edition(tmp_path)
    {"inventory": inventory, "expected": expected}[location][field] = value
    write_edition(tmp_path, inventory, expected)
    refuse_plan_reads(monkeypatch)
    with pytest.raises(ValueError):
        v2.evaluate(tmp_path)


def test_wrong_declared_count_is_rejected_before_any_plan_read(tmp_path, monkeypatch):
    """what_bug_this_catches: a complete row list bypasses the fixed edition's declared count."""
    inventory, expected = copied_edition(tmp_path)
    inventory["scenario_count"] = 23
    write_edition(tmp_path, inventory, expected)
    refuse_plan_reads(monkeypatch)
    with pytest.raises(ValueError):
        v2.evaluate(tmp_path)


def test_traversal_is_refused_before_reading_existing_outside_file(tmp_path, monkeypatch):
    """what_bug_this_catches: a lexically matching traversal opens an actual outside plan."""
    root = tmp_path / "sandbox" / "corpus"
    inventory, expected = copied_edition(root)
    row = inventory["cases"][0]
    original = root / row["path"]
    row["case_id"] = "../../../../../../outside"
    row["path"] = (v2.RELATIVE / "plans" / f"{row['case_id']}.json").as_posix()
    outside = root / row["path"]
    outside.write_bytes(original.read_bytes())
    expected["cases"][0]["case_id"] = row["case_id"]
    write_edition(root, inventory, expected)
    original_read = v2.read

    def guarded(path):
        assert path.resolve().is_relative_to(root.resolve()), "outside plan read attempted"
        return original_read(path)

    monkeypatch.setattr(v2, "read", guarded)
    with pytest.raises(ValueError):
        v2.evaluate(root)


@pytest.mark.parametrize("case_id", ["../../../../../../outside", "Upper", "a/b", "a\\b", "", None])
def test_invalid_ids_cannot_read_even_an_existing_outside_plan(tmp_path, monkeypatch, case_id):
    """what_bug_this_catches: lexical path equality admits traversal and opens an outside file."""
    root = tmp_path / "sandbox" / "corpus"
    inventory, expected = copied_edition(root)
    row = inventory["cases"][-1]
    row["case_id"] = case_id
    row["path"] = (v2.RELATIVE / "plans" / f"{case_id}.json").as_posix()
    expected["cases"][-1]["case_id"] = case_id
    outside = root / row["path"]
    if case_id == "../../../../../../outside":
        outside.parent.mkdir(parents=True, exist_ok=True)
        outside.write_bytes((root / inventory["cases"][0]["path"]).read_bytes())
    write_edition(root, inventory, expected)
    refuse_plan_reads(monkeypatch)
    with pytest.raises(ValueError):
        v2.evaluate(root)


@pytest.mark.parametrize(
    "location,field,value",
    [
        ("inventory", "sha256", "0" * 64),
        ("expected", "sha256", "0" * 64),
        ("inventory", "original_sha256", "0" * 64),
        ("inventory", "original_path", "fixtures/scenarios/dev/other.json"),
        ("inventory", "scenario_ancestor", "other"),
        ("inventory", "split", "heldout"),
        ("inventory", "path", "../outside.json"),
        ("expected", "outcome", "clear"),
        ("expected", "rule_id", "R1"),
        ("expected", "applicability", "supported"),
    ],
)
def test_late_row_joins_and_labels_precede_plan_reads(
    tmp_path, monkeypatch, location, field, value
):
    """what_bug_this_catches: early cases run before late row provenance/label mismatches are refused."""
    inventory, expected = copied_edition(tmp_path)
    {"inventory": inventory, "expected": expected}[location]["cases"][-1][field] = value
    write_edition(tmp_path, inventory, expected)
    refuse_plan_reads(monkeypatch)
    with pytest.raises(ValueError):
        v2.evaluate(tmp_path)


def test_rewritten_original_manifest_cannot_authorize_new_labels(tmp_path, monkeypatch):
    """what_bug_this_catches: caller supplied original policy makes its own altered labels trusted."""
    inventory, expected = copied_edition(tmp_path)
    original_path = tmp_path / v2.OLD_MANIFEST
    original = json.loads(original_path.read_bytes())
    original["cases"][-1]["outcome"] = "clear"
    original_path.write_bytes(v2.canonical(original))
    inventory["original_inventory_sha256"] = v2.sha(original_path.read_bytes())
    expected["cases"][-1]["outcome"] = "clear"
    write_edition(tmp_path, inventory, expected)
    refuse_plan_reads(monkeypatch)
    with pytest.raises(ValueError):
        v2.evaluate(tmp_path)


def test_rehashed_replacement_cannot_authorize_itself(tmp_path, monkeypatch):
    """what_bug_this_catches: consistently rehashed replacement bytes self-authorize a new edition."""
    inventory, expected = copied_edition(tmp_path)
    row = inventory["cases"][-1]
    path = tmp_path / row["path"]
    path.write_bytes(path.read_bytes() + b" ")
    row["sha256"] = v2.sha(path.read_bytes())
    expected["cases"][-1]["sha256"] = row["sha256"]
    write_edition(tmp_path, inventory, expected)
    refuse_plan_reads(monkeypatch)
    with pytest.raises(ValueError):
        v2.evaluate(tmp_path)


def test_all_raw_hashes_are_checked_before_first_core_evaluation(tmp_path, monkeypatch):
    """what_bug_this_catches: early cases are evaluated before a late raw-byte digest mismatch."""
    import iac_review.ingest

    inventory, _ = copied_edition(tmp_path)
    path = tmp_path / inventory["cases"][-1]["path"]
    path.write_bytes(path.read_bytes() + b" ")

    def forbidden(_):
        pytest.fail("core loaded a plan before all input hashes passed")

    monkeypatch.setattr(iac_review.ingest, "load_plan", forbidden)
    with pytest.raises(ValueError, match="hash"):
        v2.evaluate(tmp_path)


def test_evaluator_refuses_linked_plan_ancestor_before_reading_plans(tmp_path, monkeypatch):
    """what_bug_this_catches: symlink/junction can redirect the admitted paths outside the corpus."""
    root = tmp_path / "corpus"
    inventory, expected = copied_edition(root)
    directory = root / v2.RELATIVE / "plans"
    outside = tmp_path / "outside-plans"
    directory.rename(outside)
    directory.symlink_to(outside, target_is_directory=True)
    write_edition(root, inventory, expected)
    refuse_plan_reads(monkeypatch)
    with pytest.raises(ValueError, match="linked"):
        v2.evaluate(root)


def test_fixed_edition_keeps24_ids_with23_unique_raw_hashes():
    """what_bug_this_catches: deduplicating raw hashes drops a legitimate case with a distinct rule."""
    result = v2.evaluate()
    assert result["total"] == result["passed"] == 24
    assert result["failed"] == 0
    assert len({row["case_id"] for row in result["cases"]}) == 24
    assert len({row["input_sha256"] for row in result["cases"]}) == 23
