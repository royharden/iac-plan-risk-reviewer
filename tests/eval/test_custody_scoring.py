"""Unexecuted regression SOURCE using public synthetic metadata, never hidden gold.

The fictional executed/live markers below are adversarial wire inputs to the
validator, not evidence of actual model calls, semantic tests or corpus results.
"""
from datetime import datetime, timedelta, timezone
import ast
import hashlib
import json
from types import SimpleNamespace
from pathlib import Path

import pytest

from eval.runner.custody import (
    Actor, CustodyAuthority, ExposureReceipt, InventoryRow, SEMANTIC_CELLS, Seal,
    SemanticReceipt, metadata_digest, validate_exposure, validate_independence,
    validate_seal, validate_semantics,
)
from eval.runner.model_bridge import ProducerExport, UtilityRequest, bridge_bundle, utility_summaries
from eval.runner.scoring import (
    ArmRow, Edition, EligibleMeasurement, EligibilityManifest, OracleRow,
    measurement_eligible, record_digest, score,
)
from eval.runner.utility import (
    Attempt, ExplanationCase, LObservation, MeasurementPin, attempt_summary,
    explanation_inventory_digest, l_utility,
)

H = "a" * 64
B = "b" * 64
C = "c" * 64
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def custody_metadata():
    """Inventory claims only, deliberately no Terraform inputs or oracle outcomes."""
    rows = []
    actions = ("create", "update", "delete", "no-op", "delete/create", "create/delete")
    for i in range(28):
        hidden = i >= 4
        rows.append(InventoryRow(
            case_id=f"public-meta-{i}", family_id=f"family-{i}",
            configuration_lineage=f"configuration-{i}", mutation_lineage=f"mutation-{i}",
            split="heldout" if hidden else "dev", rule_id=f"R{(i - 4) // 6 + 1}" if hidden else f"R{i + 1}",
            action=actions[(i - 4) % 6], knowledge=("known", "unknown", "sensitive")[i % 3],
            semantic_cells=SEMANTIC_CELLS, explanation_eligible=hidden,
            input_sha256=f"{100 + i:064x}"))
    inventory_hash = digest(canonical([row.model_dump(mode="json") for row in rows]))
    authority = CustodyAuthority(
        edition_id="public-metadata-test-only", policy_sha256=H, frozen_build_sha256=B,
        prompt_sha256=H, rubric_sha256=H, oracle_sha256=H, inventory_sha256=inventory_hash,
        actors=tuple(Actor(actor_id=f"test-registry/{name}", session_id=f"test-{name}")
                     for name in ("implementation", "author", "checker", "custodian")),
        implementation_actors=("test-registry/implementation",),
        oracle_author="test-registry/author", oracle_checker="test-registry/checker",
        custodian="test-registry/custodian", frozen_at=NOW)
    edition = Edition(
        edition_id=authority.edition_id, state="sealed", oracle_author=authority.oracle_author,
        oracle_checker=authority.oracle_checker, detector_authors=authority.implementation_actors,
        policy_sha256=H, oracle_sha256=H, frozen_build_sha256=B,
        lineage_inventory_sha256=inventory_hash, inference_exclusion_attested=True,
        independent_custody_attested=True, eligible_heldout_explanations=24)
    seal = Seal(edition=edition, authority_sha256=metadata_digest(authority), inventory=tuple(rows),
                sealed_at=NOW + timedelta(seconds=1), custodian=authority.custodian,
                inference_exclusion_attested=True, no_detector_or_scanner_gold_attested=True,
                independent_source_review_attested=True)
    return authority, seal


def test_fork_persona_cannot_check_implementation():
    authority, _ = custody_metadata()
    actors = tuple(row.model_copy(update={"forked_from": "test-registry/implementation"})
                   if row.actor_id == authority.oracle_checker else row for row in authority.actors)
    with pytest.raises(ValueError, match="overlaps implementation"):
        validate_independence(authority.model_copy(update={"actors": actors}))


def test_missing_registry_edge_and_cycles_reject():
    authority, _ = custody_metadata()
    checker = authority.actors[2]
    for edge in ("missing/actor", checker.actor_id):
        actors = authority.actors[:2] + (checker.model_copy(update={"parent_id": edge}),) + authority.actors[3:]
        with pytest.raises(ValueError):
            validate_independence(authority.model_copy(update={"actors": actors}))


def test_seal_pins_and_split_ancestry_do_not_authenticate_authorship():
    authority, seal = custody_metadata()
    result = validate_seal(authority, seal, metadata_digest(authority))
    assert result["structurally_eligible"] is True
    assert result["authorship_authenticated"] is False
    with pytest.raises(ValueError, match="authority"):
        validate_seal(authority, seal, C)
    # Re-pin a deliberately broken inventory so the partition check, not just hashing, rejects.
    rows = list(seal.inventory)
    rows[4] = rows[4].model_copy(update={"mutation_lineage": rows[0].mutation_lineage})
    inv_hash = digest(canonical([row.model_dump(mode="json") for row in rows]))
    altered = authority.model_copy(update={"inventory_sha256": inv_hash})
    broken = seal.model_copy(update={"inventory": tuple(rows), "authority_sha256": metadata_digest(altered),
                                    "edition": seal.edition.model_copy(update={"lineage_inventory_sha256": inv_hash})})
    with pytest.raises(ValueError, match="crosses splits"):
        validate_seal(altered, broken, metadata_digest(altered))


def test_mock_or_skipped_semantics_never_eligible():
    authority, _ = custody_metadata()
    receipt = SemanticReceipt(
        authority_sha256=metadata_digest(authority), build_sha256=B, suite_sha256=H,
        actor_id=authority.oracle_checker, origin="executed", cells=SEMANTIC_CELLS,
        discovered=len(SEMANTIC_CELLS), passed=len(SEMANTIC_CELLS), failed=0, skipped=0,
        exact_mismatches=0, certainty_errors=0, invalid_displayed_facts=0,
        rule_mutations=0, prohibited_effects=0, canary_leaks=0)
    for change in ({"origin": "mock"}, {"skipped": 1}, {"exact_mismatches": 1}, {"discovered": 0}):
        with pytest.raises(ValueError):
            validate_semantics(authority, receipt.model_copy(update=change), metadata_digest(authority), H)


def test_exposure_is_consumed_even_if_scoring_later_fails():
    authority, seal = custody_metadata()
    receipt = ExposureReceipt(
        edition_id=authority.edition_id, authority_sha256=metadata_digest(authority),
        seal_sha256=metadata_digest(seal), build_sha256=B, oracle_sha256=H,
        measurements_sha256=C, arm="D", custodian=authority.custodian,
        exposed_at=NOW + timedelta(seconds=2), durable_receipt_id="external-receipt-test",
        durable_before_access_attested=True)
    assert validate_exposure(authority, seal, (receipt,), metadata_digest(authority))["fresh_holdout"] is False
    with pytest.raises(ValueError, match="consumes"):
        validate_exposure(authority, seal, (receipt,), metadata_digest(authority), requested_fresh=True)
    with pytest.raises(ValueError):
        validate_exposure(authority, seal, (), metadata_digest(authority))


def baseline(**updates):
    row = ArmRow(case_id="public-case", resource_id="resource", rule_id="R1", arm="D",
                 status="ok", applicability="supported", outcome="introduced_risk",
                 reason_code="public_wire_example", decision_fact_ids=("fact",),
                 source_sha256=H, build_sha256=B, measurement_ref="sha256:" + C)
    return row.model_copy(update=updates)


def test_legacy_mock_and_missing_arm_never_become_live_or_true_negative():
    # Public scorer arithmetic fixture, not an independently authored detector oracle.
    oracle = OracleRow(case_id="public-case", resource_id="resource", rule_id="R1",
                       family_id="public", configuration_lineage="public-config",
                       mutation_lineage="public-mutation", split="dev", applicability="supported",
                       outcome="introduced_risk", reason_code="public_wire_example", decision_fact_ids=("fact",))
    row = baseline()
    assert not measurement_eligible(row, None)
    result = score([oracle], [row], "dev")
    assert result["arms"]["D"]["measurement_status"] == "INCOMPLETE"
    assert result["arms"]["D"]["per_rule"]["R1"]["fn"] == 1
    assert result["arms"]["M"]["per_rule"]["R1"]["tn"] == 0
    meta = EligibleMeasurement(arm="L", measurement_ref=row.measurement_ref,
                               source_sha256=H, build_sha256=B, kind="mock",
                               provenance_sha256=C, actual_execution_attested=True)
    manifest = EligibilityManifest(edition_id="public", rows=(meta,))
    mock = row.model_copy(update={"schema_version": 2, "arm": "L", "measurement_kind": "mock",
                                  "eligibility_ref": record_digest(meta)})
    assert not measurement_eligible(mock, manifest)
    with pytest.raises(ValueError, match="pinned"):
        score([oracle], [mock], "dev", eligibility=manifest)


def l_inputs():
    actions = ("create", "update", "delete", "no-op", "delete/create", "create/delete")
    cases = tuple(ExplanationCase(
        case_id=f"public-{i}", resource_id=f"resource-{i}", rule_id=f"R{i // 6 + 1}",
        input_sha256=f"{i + 200:064x}", action=actions[i % 6],
        knowledge=("known", "unknown", "sensitive")[i % 3], required_fact_ids=(f"fact-{i}",),
        required_limitation_ids=(), allowed_fact_ids=(f"fact-{i}",), allowed_limitation_ids=())
        for i in range(24))
    pin = MeasurementPin(
        edition_id="public", build_sha256=B, corpus_sha256=C,
        explanation_inventory_sha256=explanation_inventory_digest(cases),
        prompt_sha256=H, rubric_sha256=H, model_version="fictional-wire-only",
        price_identity="fictional-2026-01-01", attempt_ids=tuple(f"attempt-{i}" for i in range(24)),
        all_attempts_attested=True)
    attempts = tuple(Attempt(
        attempt_id=f"attempt-{i}", arm="L", pin_sha256=metadata_digest(pin), origin="live",
        input_sha256=C, source_sha256=case.input_sha256, response_sha256=H,
        start_record_sha256=H, terminal_record_sha256=H, status="ok",
        known_usd=.001, billing_known=True) for i, case in enumerate(cases))
    observations = []
    for i, case in enumerate(cases):
        d = baseline(case_id=case.case_id, resource_id=case.resource_id, rule_id=case.rule_id,
                     source_sha256=case.input_sha256, decision_fact_ids=case.required_fact_ids)
        observations.append(LObservation(
            baseline=d, selector=d.model_copy(update={"arm": "L"}), attempt_id=f"attempt-{i}",
            baseline_words=100, selector_words=80, selected_fact_ids=case.required_fact_ids,
            selected_limitation_ids=(), rendered_clauses=1, irrelevant_clauses=0,
            unsupported_clauses=0, predicates_verified=True, withheld=False))
    return cases, tuple(observations), pin, attempts


def test_exact_twenty_percent_boundary_and_missing_denominator():
    cases, observations, pin, attempts = l_inputs()
    result = l_utility(cases, observations, pin, attempts, metadata_digest(pin), .01)
    assert result["enablement_criterion"] == "MET"
    assert result["median_paired_word_reduction"] == .2
    missing = l_utility(cases, observations[:-1], pin, attempts, metadata_digest(pin), .01)
    assert missing["expected_denominator"] == 24
    assert missing["median_paired_word_reduction"] is None
    assert missing["enable_selector_by_default"] is False
    mock = tuple(row.model_copy(update={"origin": "mock"}) for row in attempts)
    assert l_utility(cases, observations, pin, mock, metadata_digest(pin), .01)["measurement_status"] == "INCOMPLETE"


def test_all_failed_spending_and_unknown_liability_survive_zero_success():
    _, _, pin, attempts = l_inputs()
    failed = attempts[0].model_copy(update={"status": "timeout", "known_usd": None,
                                           "billing_known": False, "unresolved_usd_upper": .5})
    rows = (failed,) + attempts[1:]
    result = attempt_summary(pin, rows, metadata_digest(pin), "L", 0)
    assert result["cost_per_success_usd"] is None
    assert result["billing_fully_known"] is False
    assert result["unresolved_usd_upper"] == .5
    assert result["attempts_observed"] == 24


def test_bridge_keeps_unconverted_unknown_cost_without_fake_journal_hashes():
    snapshot = {"attempt_id": "fake-attempt", "arm": "P", "status": "timeout", "duration_ms": 1,
                "input_tokens": None, "output_tokens": None, "known_usd": None,
                "unresolved_usd_upper": "0.25", "billing_known": False,
                "requires_reconciliation": True, "hashes": {"input": C},
                "response_sha256": None, "price_sha256": H, "usage_sha256": H,
                "live_eligible": False}
    attempts = canonical([snapshot])
    accounting = canonical({
        "scope": "all attempts started by this invocation; cumulative journal separately bound",
        "requests": 1, "known_usd": "0", "unresolved_usd_upper": "0.25",
        "billing_fully_known": False, "total_usd": None, "input_tokens_reported": 0,
        "output_tokens_reported": 0, "usage_complete": False,
        "pending_attempt_ids": ["fake-attempt"], "duration_ms_all_attempts": 1,
        "valid_shape_attempts": 0, "live_successes": 0,
        "cost_per_live_success_usd": None, "live_eligible": False})
    observations = "[]"
    provenance = canonical({"schema": 1, "live_eligible": False, "build_sha256": B,
                            "corpus_sha256": C, "source_sha256": H,
                            "attempts_sha256": digest(attempts), "accounting_sha256": digest(accounting),
                            "observations_sha256": digest(observations)})
    bundle = SimpleNamespace(live_eligible=False, rows=(), attempts_json=attempts,
                             accounting_json=accounting, observations_json=observations,
                             provenance_json=provenance)
    result = bridge_bundle(bundle, ())
    assert result.attempts == ()
    assert result.unconverted_attempt_ids == ("fake-attempt",)
    assert result.unresolved_usd_upper_decimal == "0.25"
    assert result.live_evidence_eligible is False
    assert result.authoritative_accounting.total_usd is None
    exported = ProducerExport(rows=(), attempts_json=attempts, accounting_json=accounting,
                              observations_json=observations, provenance_json=provenance)
    summaries = utility_summaries(UtilityRequest(producer_exports=(exported,)))
    assert summaries["P"]["producer_all_attempt_cost"]["unresolved_usd_upper_decimal"] == "0.25"
    assert summaries["P"]["producer_all_attempt_cost"]["total_usd_decimal"] is None
    assert summaries["P"]["measurement_status"] == "INCOMPLETE"
    tampered = json.loads(accounting)
    tampered["requests"] = 0
    changed = canonical(tampered)
    changed_provenance = json.loads(provenance)
    changed_provenance["accounting_sha256"] = digest(changed)
    bad = exported.model_copy(update={"accounting_json": changed,
                                      "provenance_json": canonical(changed_provenance)})
    with pytest.raises(ValueError, match="accounting"):
        bridge_bundle(bad, ())


def test_cli_persists_exposure_before_opening_hidden_payloads():
    source = Path(__file__).resolve().parents[2] / "scripts" / "eval.py"
    tree = ast.parse(source.read_bytes())
    main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "main")
    calls = [node for node in ast.walk(main) if isinstance(node, ast.Call)]
    exposure = next(node.lineno for node in calls if isinstance(node.func, ast.Name)
                    and node.func.id == "durable_json" and "exposure.json" in ast.unparse(node))
    hidden = [node.lineno for node in calls if isinstance(node.func, ast.Name)
              and node.func.id in {"read_bytes", "model"} and node.args
              and ast.unparse(node.args[0]) in {"args.oracle", "args.measurements", "args.utility"}]
    assert len(hidden) == 3 and all(line > exposure for line in hidden)


def binary_example(outcome, prediction, *, status="ok", arm="C", kind="executed"):
    """Fictional public scoring arithmetic; no detector/oracle generation."""
    gold = OracleRow(case_id="public-case", resource_id="resource", rule_id="R1",
                     family_id="family", configuration_lineage="config", mutation_lineage="mutation",
                     split="dev", applicability="supported", outcome=outcome,
                     reason_code="public_wire_example", decision_fact_ids=("fact",))
    meta = EligibleMeasurement(arm=arm, measurement_ref="sha256:" + C, source_sha256=H,
                               build_sha256=B, kind=kind, provenance_sha256=C,
                               actual_execution_attested=True)
    row = baseline(arm=arm, status=status, outcome=None, prediction_target="introduced_risk",
                   introduced_prediction=prediction, schema_version=2, measurement_kind=kind,
                   eligibility_ref=record_digest(meta))
    manifest = EligibilityManifest(edition_id="public", rows=(meta,))
    return gold, row, manifest


@pytest.mark.parametrize("outcome,prediction,expected", (
    ("introduced_risk", True, "tp"), ("introduced_risk", False, "fn"),
    ("clear", False, "tn"), ("unchanged_risk", False, "tn"), ("clear", True, "fp"),
))
def test_binary_predictions_target_introduction_without_inventing_outcome(outcome, prediction, expected):
    gold, row, manifest = binary_example(outcome, prediction)
    result = score([gold], [row], "dev", eligibility=manifest,
                   expected_eligibility_sha256=record_digest(manifest))
    counts = result["arms"]["C"]["per_rule"]["R1"]
    assert counts[expected] == 1
    assert row.outcome is None
    assert result["arms"]["C"]["measurement_status"] == "RECORDED"


@pytest.mark.parametrize("prediction", (True, False))
def test_definite_binary_prediction_on_unknown_gold_is_certainty_error(prediction):
    gold, row, manifest = binary_example("indeterminate", prediction)
    result = score([gold], [row], "dev", eligibility=manifest,
                   expected_eligibility_sha256=record_digest(manifest))
    counts = result["arms"]["C"]["per_rule"]["R1"]
    assert counts["certainty_errors"] == 1
    assert counts["tn"] == 0


@pytest.mark.parametrize("status,kind,prediction", (
    ("ok", "executed", None), ("unmapped", "executed", False), ("ok", "mock", False),
))
def test_null_unmapped_or_mock_binary_is_not_a_true_negative(status, kind, prediction):
    gold, row, manifest = binary_example("clear", prediction, status=status, kind=kind)
    result = score([gold], [row], "dev", eligibility=manifest,
                   expected_eligibility_sha256=record_digest(manifest))
    counts = result["arms"]["C"]["per_rule"]["R1"]
    assert counts["tn"] == 0
    assert counts["abstentions"] == 1


def test_binary_d_cannot_close_full_exact_gate_and_partial_model_cost_is_not_total():
    gold, row, manifest = binary_example("introduced_risk", True, arm="D")
    result = score([gold], [row], "dev", eligibility=manifest,
                   expected_eligibility_sha256=record_digest(manifest))
    assert result["deterministic_exact_gate"] is False
    assert result["arms"]["L"]["known_usd"] is None
    assert result["arms"]["L"]["row_known_usd_subtotal"] == 0
    assert result["arms"]["L"]["cost_completeness"] == "MISSING_ALL_ATTEMPT_ACCOUNTING"
