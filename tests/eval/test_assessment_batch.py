"""Regression source for distinct raw-scenario and all-attempt batch intake."""
from types import SimpleNamespace

import pytest

from eval.runner.assessment_batch import (
    BatchD5Export,
    cost_scope_record, reconcile_attempt_ids, reconstruct_export_bundle, resolve_private_reference,
    validate_coordinator_wire, validate_export_pins, validate_scenario_inventory,
    validate_execution_mode, validate_span_partition,
)
from eval.model.capture_index import export_digest
from eval.model.experiment import canonical, digest
from eval.model.provenance import ExportBundle
from eval.runner.model_bridge import links_for_bundle
from scripts.import_assessment_batch import _parse_strict_json_bytes
from eval.runner.utility import ExplanationCase, _inventory
import hashlib
import json


def test_findings_from_one_raw_plan_count_as_one_scenario():
    """The batch contract is explicit that duplicate raw hashes are rejected."""
    scenarios = tuple(SimpleNamespace(scenario_id=f"s{i}", raw_plan_sha256=f"{i:064x}")
                      for i in range(24))
    assert validate_scenario_inventory(scenarios) == 24
    duplicate_raw = (*scenarios[:-1], SimpleNamespace(scenario_id="s23",
                                                       raw_plan_sha256=scenarios[0].raw_plan_sha256))
    with pytest.raises(ValueError, match="distinct raw plan"):
        validate_scenario_inventory(duplicate_raw)
    with pytest.raises(ValueError, match="fewer than 24"):
        validate_scenario_inventory(scenarios[:-1])
    raw = "f" * 64
    findings = tuple(ExplanationCase(case_id="same-plan", resource_id=f"resource-{rule}",
        rule_id=rule, input_sha256=raw, action="create", knowledge="known",
        required_fact_ids=("fact",), required_limitation_ids=(),
        allowed_fact_ids=("fact",), allowed_limitation_ids=())
        for rule in ("R1", "R2"))
    inventory = _inventory(findings)
    assert inventory["eligible_scenarios"] == 1
    assert inventory["eligible_findings"] == 2


def test_duplicate_attempt_across_plan_exports_is_rejected():
    """Attempt identities are unique across invocation exports and global journal."""
    validate_span_partition([{"case_id": "a", "start_index": 0, "stop_index": 1},
                             {"case_id": "b", "start_index": 1, "stop_index": 1}], 1)
    with pytest.raises(ValueError, match="contiguous"):
        validate_span_partition([{"case_id": "a", "start_index": 0, "stop_index": 1},
                                 {"case_id": "b", "start_index": 2, "stop_index": 2}], 2)
    with pytest.raises(ValueError, match="duplicate attempt"):
        reconcile_attempt_ids((("a1",), ("a1",)), ("a1", "a2"))


def test_missing_exports_remain_incomplete_and_costs_are_not_zeroed():
    """Withheld invocations and unmatched journal attempts remain explicit liabilities."""
    assert reconcile_attempt_ids((("a1",),), ("a1", "failed", "unmatched")) == (
        "failed", "unmatched")
    with pytest.raises(ValueError, match="absent from global journal"):
        reconcile_attempt_ids((("a1",),), ("different",))


def test_d4_nested_wire_reconstructs_zero_row_export_without_fabricating_rows():
    wire = {"rows": [], "attempts": [], "accounting": {"requests": 0},
            "provenance": {"source_sha256": "a" * 64}, "observations": []}
    bundle = reconstruct_export_bundle(wire)
    assert bundle.rows == ()
    assert json.loads(bundle.attempts_json) == []
    assert json.loads(bundle.observations_json) == []
    prov_pin = digest(canonical(wire["provenance"]))
    bundle_pin = export_digest(bundle)
    assert prov_pin != bundle_pin
    validate_export_pins(bundle, prov_pin, bundle_pin)
    with pytest.raises(ValueError, match="provenance pin"):
        validate_export_pins(bundle, "0" * 64, bundle_pin)
    with pytest.raises(ValueError, match="whole ExportBundle pin"):
        validate_export_pins(bundle, prov_pin, "0" * 64)


def test_coordinator_outer_pin_is_separate_and_exact():
    raw = json.dumps({"schema_version": "m4-seven-arm-benchmark-provenance-v1",
                      "live_eligible": False}, sort_keys=True, separators=(",", ":"))
    assert validate_coordinator_wire(raw, hashlib.sha256(raw.encode()).hexdigest())[
        "schema_version"] == "m4-seven-arm-benchmark-provenance-v1"
    with pytest.raises(ValueError, match="pin/schema"):
        validate_coordinator_wire(raw, "0" * 64)


def test_private_references_cannot_escape_or_follow_symlinks(tmp_path):
    root = tmp_path.resolve()
    (root / "inbox").mkdir()
    assert resolve_private_reference(root, "inbox") == root / "inbox"
    with pytest.raises(ValueError, match="normalized"):
        resolve_private_reference(root, "../outside")
    (root / "alias").symlink_to(root / "inbox", target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        resolve_private_reference(root, "alias")


def test_invocation_accounting_is_never_added_to_global_cumulative_cost():
    record = cost_scope_record({"known_usd": "7"}, [{"known_usd": "2"},
                                                        {"known_usd": "5"}])
    assert record["global_journal"]["known_usd"] == "7"
    assert len(record["invocation_accounting"]) == 2
    assert record["invocation_totals_added_to_global"] is False


def test_global_journal_links_are_partitioned_to_each_bundle():
    bundle = ExportBundle((), '[{"attempt_id":"local"}]', "{}", "{}", "[]")
    links = (SimpleNamespace(attempt_id="local"), SimpleNamespace(attempt_id="other"))
    assert [row.attempt_id for row in links_for_bundle(bundle, links)] == ["local"]


def test_execution_mode_metadata_never_promotes_rows():
    assert validate_execution_mode({"live_eligible": False}, None) == "development_fake_only"
    approved = {"execution_mode": "approved_synthetic_unverified",
               "execution_authority_sha256": "a" * 64}
    assert validate_execution_mode(approved, "a" * 64) == "approved_synthetic_unverified"
    with pytest.raises(ValueError, match="authority pin"):
        validate_execution_mode(approved, "b" * 64)
    with pytest.raises(ValueError, match="unsupported coordinator execution mode"):
        validate_execution_mode({"execution_mode": "live"}, None)


def test_pinned_batch_json_mode_accepts_arrays_and_rejects_bad_wire_shapes():
    valid = b'{"rows":[],"attempts":[],"accounting":{},"provenance":{},"observations":[]}'
    parsed = _parse_strict_json_bytes(valid)
    assert BatchD5Export.model_validate_json(valid).rows == ()
    assert parsed["rows"] == []
    with pytest.raises(ValueError, match="duplicate JSON key"):
        _parse_strict_json_bytes(b'{"rows":[],"rows":[],"attempts":[],"accounting":{},"provenance":{},"observations":[]}')
    with pytest.raises(ValueError):
        BatchD5Export.model_validate_json(
            b'{"rows":"not-an-array","attempts":[],"accounting":{},"provenance":{},"observations":[]}')
    with pytest.raises(ValueError):
        BatchD5Export.model_validate_json(
            b'{"rows":[],"attempts":[],"accounting":{},"provenance":{},"observations":[],"extra":true}')
