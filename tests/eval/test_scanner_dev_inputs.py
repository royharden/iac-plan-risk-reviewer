"""Public development recipe regression SOURCE, not run during construction."""
from __future__ import annotations

import hashlib
import json

import pytest

from eval.scanners.dev_inputs import (MAX_BUNDLE_BYTES, MAX_CASE_BYTES, MAX_CASES,
                                     build_inputs, write_bundle)


def test_recipe_bytes_ids_and_lineage_are_deterministic() -> None:
    """what_bug_this_catches: clock/random/source-path drift changes supposedly frozen public inputs."""
    first, second = build_inputs(), build_inputs()
    assert first == second
    assert len({case.case_id for case in first}) == len(first)
    assert len({case.filename for case in first}) == len(first)
    assert all(case.mutation_ancestors == ("mut_public_recipe_base_v1",) for case in first)


def test_recipe_enforces_small_fixed_resource_bounds() -> None:
    """what_bug_this_catches: variant multiplication silently creates an oversized local corpus."""
    cases = build_inputs()
    assert 0 < len(cases) <= MAX_CASES
    assert all(0 < len(case.payload) <= MAX_CASE_BYTES for case in cases)
    assert sum(len(case.payload) for case in cases) <= MAX_BUNDLE_BYTES


def test_every_input_stays_public_development_not_oracle_or_holdout() -> None:
    """what_bug_this_catches: implementation-authored mutations later presented as independent gold."""
    for case in build_inputs():
        metadata = case.metadata()
        assert metadata["development_only"] is True
        assert metadata["independent_gold"] is False and metadata["heldout_eligible"] is False
        assert metadata["synthetic"] is True
        assert "not_terraform_output" in metadata["provenance"]
        assert metadata["raw_json_sha256"] == hashlib.sha256(case.payload).hexdigest()


def test_replacement_ordering_is_preserved_without_outcome_labels() -> None:
    """what_bug_this_catches: replacement order normalized away before scanner compatibility work."""
    cases = [case for case in build_inputs() if "ordered_actions" in case.dimensions]
    actions = {tuple(json.loads(case.payload)["resource_changes"][0]["change"]["actions"])
               for case in cases}
    assert ("delete", "create") in actions and ("create", "delete") in actions
    assert ("delete",) in actions and ("read",) in actions
    assert all("expected_outcome" not in case.metadata() for case in cases)


def test_ipv6_masks_absence_and_null_are_distinct_input_facts() -> None:
    """what_bug_this_catches: input generation erases a required mask/absence distinction."""
    cases = build_inputs()
    by_dimension = {dimension: case for case in cases for dimension in case.dimensions}
    ipv6 = json.loads(by_dimension["ipv6_world"].payload)["resource_changes"][0]
    assert ipv6["change"]["after"]["ipv6_cidr_blocks"] == ["::/0"]
    ancestor = json.loads(by_dimension["unknown_ancestor"].payload)["resource_changes"][0]
    assert ancestor["change"]["after_unknown"] is True
    sensitive = json.loads(by_dimension["sensitive_leaf"].payload)
    assert sensitive["resource_changes"][0]["change"]["after_sensitive"] == {"cidr_blocks": True}
    assert sensitive["planned_values"]["root_module"]["resources"][0]["sensitive_values"] == {"cidr_blocks": True}
    absent = json.loads(by_dimension["absent"].payload)["resource_changes"][0]
    null = json.loads(by_dimension["null_cidr"].payload)["resource_changes"][0]
    assert "ipv6_cidr_blocks" not in absent["change"]["after"]
    assert null["change"]["after"]["cidr_blocks"] is None


def test_delete_does_not_invent_a_planned_values_callback() -> None:
    """what_bug_this_catches: generator manufactures after-resources to make delete coverage look complete."""
    case = next(case for case in build_inputs()
                if case.configuration_lineage == "cfg_aws_db_instance_v1"
                and case.mutation_lineage == "mut_action_delete_v1")
    plan = json.loads(case.payload)
    assert plan["resource_changes"][0]["change"]["before"] is not None
    assert plan["resource_changes"][0]["change"]["after"] is None
    assert plan["planned_values"]["root_module"]["resources"] == []


def test_written_bundle_hashes_and_driver_usage_do_not_mix_probes(tmp_path) -> None:
    """what_bug_this_catches: malformed probes invalidate the whole ordinary scanner comparison batch."""
    target = tmp_path / "new-development-bundle"
    metadata = write_bundle(target, build_sha256="a" * 64)
    assert metadata["generated_by_terraform"] is False
    assert metadata["tested_terraform_version"] is None and metadata["tested_aws_provider_version"] is None
    driver = json.loads((target / "driver-manifest.json").read_text(encoding="utf-8"))
    assert driver["arms"] == {} and driver["heldout_eligible"] is False
    ordinary = {row["case_id"] for row in driver["cases"]}
    for row in metadata["cases"]:
        raw = (target / row["relative_path"]).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == row["raw_json_sha256"]
        assert (row["case_id"] in ordinary) == (row["usage"] == "scanner_input_candidate")
    assert (target / "STARTED").is_file() and (target / "COMPLETE").is_file()


def test_existing_bundle_is_preserved_without_overwrite(tmp_path) -> None:
    """what_bug_this_catches: generator overwrites an earlier frozen development bundle."""
    target = tmp_path / "existing"
    target.mkdir()
    original = target / "keep.txt"
    original.write_text("preserve", encoding="utf-8")
    with pytest.raises(ValueError, match="new nonsymlink"):
        write_bundle(target, build_sha256="a" * 64)
    assert original.read_text(encoding="utf-8") == "preserve"


def test_invalid_build_pin_creates_nothing(tmp_path) -> None:
    """what_bug_this_catches: missing build identity still creates apparently frozen input evidence."""
    target = tmp_path / "not-created"
    with pytest.raises(ValueError, match="build SHA256"):
        write_bundle(target, build_sha256="not-a-pin")
    assert not target.exists()


def test_raw_payloads_and_metadata_contain_no_expected_labels() -> None:
    """what_bug_this_catches: a convenience generator quietly becomes a detector-derived oracle."""
    prohibited = {"expected_risk", "expected_outcome", "gold_label", "oracle_label", "risk_label", "outcome"}

    def inspect(value):
        if isinstance(value, dict):
            assert not prohibited.intersection(value)
            for child in value.values():
                inspect(child)
        elif isinstance(value, list):
            for child in value:
                inspect(child)

    for case in build_inputs():
        inspect(case.metadata())
        if case.usage == "scanner_input_candidate":
            inspect(json.loads(case.payload))
