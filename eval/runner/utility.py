"""Offline L/P summaries over pinned receipts; never executes inference or reads gold.

All receipts remain untrusted attestations. Mock records are explicitly ineligible
for live evidence; source availability alone does not establish measurements.
"""
from __future__ import annotations

from collections import Counter
from fractions import Fraction
import hashlib
import json
from math import ceil, fsum
from statistics import median
from typing import Literal

from pydantic import Field

from eval.model.protocol import ClaimAssessment, prose_metrics
from eval.runner.custody import Digest, Identity, metadata_digest
from eval.runner.scoring import ArmRow, Record


class MeasurementPin(Record):
    edition_id: Identity
    build_sha256: Digest
    corpus_sha256: Digest
    explanation_inventory_sha256: Digest
    prompt_sha256: Digest
    rubric_sha256: Digest
    model_version: Identity
    price_identity: Identity
    # External controller pins this inventory before results are imported.
    attempt_ids: tuple[Identity, ...] = Field(max_length=10000)
    all_attempts_attested: bool


class Attempt(Record):
    attempt_id: Identity
    arm: Literal["L", "P", "M"]
    pin_sha256: Digest
    origin: Literal["live", "mock", "replay", "not_run"]
    # Replay is eligible only when it identifies an original pinned live attempt.
    original_live_receipt_sha256: Digest | None = None
    input_sha256: Digest
    source_sha256: Digest
    response_sha256: Digest | None = None
    # For P: hash of the complete ordered generated claim-ID list, including withheld.
    generated_claim_inventory_sha256: Digest | None = None
    start_record_sha256: Digest
    terminal_record_sha256: Digest | None = None
    status: Literal["pending", "ok", "invalid", "timeout", "error", "cancelled", "rejected"]
    elapsed_seconds: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    known_usd: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    billing_known: bool = False
    unresolved_usd_upper: float | None = Field(default=None, ge=0, allow_inf_nan=False)


def _unique(values: tuple, label: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"duplicate {label}")


def attempt_summary(pin: MeasurementPin, attempts: tuple[Attempt, ...],
                    expected_pin_sha256: str, arm: Literal["L", "P", "M"],
                    successful_explanations: int) -> dict:
    """Do not aggregate ArmRow costs: one call may produce multiple finding rows."""
    if metadata_digest(pin) != expected_pin_sha256:
        raise ValueError("measurement authority pin mismatch")
    if len(attempts) > 10000 or successful_explanations < 0:
        raise ValueError("attempt or success bound exceeded")
    _unique(pin.attempt_ids, "expected attempts")
    _unique(tuple(row.attempt_id for row in attempts), "attempt ids")
    if any(row.arm != arm or row.pin_sha256 != expected_pin_sha256 for row in attempts):
        raise ValueError("foreign arm/attempt provenance")
    actual = {row.attempt_id for row in attempts}
    expected = set(pin.attempt_ids)
    if actual - expected:
        raise ValueError("unlisted attempt")
    missing = sorted(expected - actual)
    live = all(row.origin == "live" or (
        row.origin == "replay" and row.original_live_receipt_sha256 is not None)
        for row in attempts)
    for row in attempts:
        if row.origin == "replay" and row.original_live_receipt_sha256 is None:
            raise ValueError("replay missing original live receipt")
        if row.status == "pending" and row.terminal_record_sha256 is not None:
            raise ValueError("pending attempt has terminal record")
        if row.status == "pending" and row.billing_known:
            raise ValueError("pending attempt cannot establish final billing")
        if row.status != "pending" and row.terminal_record_sha256 is None:
            raise ValueError("terminal outcome missing journal record")
        if row.status == "ok" and row.response_sha256 is None:
            raise ValueError("successful attempt missing response provenance")
        if row.billing_known and row.known_usd is None:
            raise ValueError("known billing missing amount")
        if row.billing_known and row.unresolved_usd_upper not in (None, 0):
            raise ValueError("known billing contradicts unresolved liability")
    complete = bool(expected) and not missing and pin.all_attempts_attested
    known = fsum(row.known_usd or 0 for row in attempts)
    fully_known = complete and all(row.billing_known and row.status != "pending" for row in attempts)
    unresolved = [row for row in attempts if not row.billing_known or row.status == "pending"]
    bounds_known = complete and all(row.unresolved_usd_upper is not None for row in unresolved)
    durations = [row.elapsed_seconds for row in attempts if row.elapsed_seconds is not None]
    ordered = sorted(durations)
    return {
        "attempts_expected": len(expected), "attempts_observed": len(attempts),
        "missing_attempt_ids": missing, "statuses": dict(Counter(row.status for row in attempts)),
        "all_attempts_complete": complete, "live_evidence_eligible": complete and live
        and all(row.status != "pending" for row in attempts),
        "known_usd": known, "billing_fully_known": fully_known,
        "unresolved_upper_bounds_known": bounds_known,
        "unresolved_usd_upper": fsum(row.unresolved_usd_upper or 0 for row in unresolved)
        if bounds_known else None,
        "cost_per_success_usd": known / successful_explanations
        if fully_known and successful_explanations else None,
        "successful_explanations": successful_explanations,
        "all_attempt_seconds": fsum(durations) if len(durations) == len(attempts) and complete else None,
        "p50_attempt_seconds": median(durations) if durations else None,
        "p95_attempt_seconds": ordered[ceil(.95 * len(ordered)) - 1] if ordered else None,
        "latency_denominator": len(durations), "pending_liabilities": len(unresolved),
        "input_tokens": sum(row.input_tokens or 0 for row in attempts)
        if complete and all(row.input_tokens is not None for row in attempts) else None,
        "output_tokens": sum(row.output_tokens or 0 for row in attempts)
        if complete and all(row.output_tokens is not None for row in attempts) else None,
        "product_acceptance": False,
    }


class ExplanationCase(Record):
    """Custodian-supplied expected inventory; no labels or raw source facts."""
    case_id: Identity
    resource_id: Identity
    rule_id: Literal["R1", "R2", "R3", "R4"]
    input_sha256: Digest
    action: Literal["create", "update", "delete", "no-op", "delete/create", "create/delete"]
    knowledge: Literal["known", "unknown", "sensitive"]
    required_fact_ids: tuple[Identity, ...] = Field(min_length=1, max_length=256)
    required_limitation_ids: tuple[Identity, ...] = Field(max_length=256)
    allowed_fact_ids: tuple[Identity, ...] = Field(min_length=1, max_length=512)
    allowed_limitation_ids: tuple[Identity, ...] = Field(max_length=512)


def _key(row: ExplanationCase | ArmRow) -> tuple[str, str, str]:
    return row.case_id, row.resource_id, row.rule_id


def _list_digest(values: list) -> str:
    raw = json.dumps(values, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True, allow_nan=False)
    return hashlib.sha256(raw.encode("ascii")).hexdigest()


def explanation_inventory_digest(cases: tuple[ExplanationCase, ...]) -> str:
    """Canonical order-sensitive hash to bind the full independent denominator."""
    return _list_digest([row.model_dump(mode="json") for row in cases])


def _inventory(cases: tuple[ExplanationCase, ...]) -> dict:
    if not cases or len(cases) > 4096:
        raise ValueError("bounded nonempty independent denominator inventory required")
    _unique(tuple(_key(row) for row in cases), "scenario keys")
    _unique(tuple(row.case_id for row in cases), "eligible scenario ids")
    _unique(tuple(row.input_sha256 for row in cases), "eligible input digests")
    for row in cases:
        for name in ("required_fact_ids", "required_limitation_ids", "allowed_fact_ids",
                     "allowed_limitation_ids"):
            _unique(getattr(row, name), name)
        if (not set(row.required_fact_ids) <= set(row.allowed_fact_ids)
                or not set(row.required_limitation_ids) <= set(row.allowed_limitation_ids)):
            raise ValueError("required identifiers outside approved capsule")
    rules = Counter(row.rule_id for row in cases)
    balanced = (len(cases) >= 24 and all(rules[rule] >= 6 for rule in ("R1", "R2", "R3", "R4"))
                and {row.action for row in cases} == {
                    "create", "update", "delete", "no-op", "delete/create", "create/delete"}
                and {row.knowledge for row in cases} == {"known", "unknown", "sensitive"})
    return {"eligible_scenarios": len(cases), "rule_counts": dict(rules),
            "action_counts": dict(Counter(row.action for row in cases)),
            "knowledge_counts": dict(Counter(row.knowledge for row in cases)),
            "minimum_24_balanced": balanced}


class LObservation(Record):
    baseline: ArmRow
    selector: ArmRow
    attempt_id: Identity
    baseline_words: int = Field(ge=0)
    selector_words: int = Field(ge=0)
    selected_fact_ids: tuple[Identity, ...] = Field(max_length=512)
    selected_limitation_ids: tuple[Identity, ...] = Field(max_length=512)
    rendered_clauses: int = Field(ge=0)
    irrelevant_clauses: int = Field(ge=0)
    unsupported_clauses: int = Field(ge=0)
    predicates_verified: bool
    withheld: bool


def l_utility(cases: tuple[ExplanationCase, ...], observations: tuple[LObservation, ...],
              pin: MeasurementPin, attempts: tuple[Attempt, ...], expected_pin_sha256: str,
              approved_cost_per_success_usd: float | None) -> dict:
    inventory = _inventory(cases)
    if explanation_inventory_digest(cases) != pin.explanation_inventory_sha256:
        raise ValueError("independent explanation denominator pin mismatch")
    if len(observations) > 4096:
        raise ValueError("too many L observations")
    if approved_cost_per_success_usd is not None and (
            not 0 <= approved_cost_per_success_usd < float("inf")):
        raise ValueError("finite nonnegative approved cost limit required")
    by_key = {_key(row.selector): row for row in observations}
    if len(by_key) != len(observations) or not set(by_key) <= {_key(row) for row in cases}:
        raise ValueError("duplicate or foreign L observation")
    attempt_map = {row.attempt_id: row for row in attempts}
    facts_total = sum(len(row.required_fact_ids) for row in cases)
    limits_total = sum(len(row.required_limitation_ids) for row in cases)
    facts_kept = limits_kept = clauses = irrelevant = unsupported = successes = 0
    failures = []
    reductions = []
    for case in cases:
        row = by_key.get(_key(case))
        reasons = []
        if row is None:
            failures.append({"case_id": case.case_id, "reasons": ["missing_observation"]})
            continue
        d, l = row.baseline, row.selector
        if _key(d) != _key(l) or d.arm != "D" or l.arm != "L":
            raise ValueError("L observation must pair the same D finding")
        if any(r.build_sha256 != pin.build_sha256 or r.source_sha256 != case.input_sha256
               for r in (d, l)):
            raise ValueError("L build/input pin mismatch")
        attempt = attempt_map.get(row.attempt_id)
        if attempt is None or attempt.arm != "L" or attempt.source_sha256 != case.input_sha256:
            reasons.append("missing_or_foreign_attempt")
        elif attempt.status != "ok":
            reasons.append("attempt_not_successful")
        for field in ("applicability", "outcome", "reason_code", "decision_fact_ids",
                      "required_limitation_ids"):
            if getattr(d, field) != getattr(l, field):
                reasons.append("D_invariance_failure")
                break
        if d.status != "ok" or l.status != "ok" or row.withheld:
            reasons.append("invalid_or_withheld")
        if d.applicability is None or d.outcome is None or not d.reason_code:
            reasons.append("incomplete_D_baseline")
        if not row.predicates_verified or row.unsupported_clauses:
            reasons.append("unsupported_clause")
        if any(r.invalid_displayed_refs or r.canary_leaks or r.prohibited_effects
               or r.rule_mutations or r.certainty_errors for r in (d, l)):
            reasons.append("critical_error")
        _unique(row.selected_fact_ids, "selected facts")
        _unique(row.selected_limitation_ids, "selected limitations")
        if (not set(row.selected_fact_ids) <= set(case.allowed_fact_ids)
                or not set(row.selected_limitation_ids) <= set(case.allowed_limitation_ids)):
            reasons.append("foreign_selection")
        covered_facts = len(set(row.selected_fact_ids) & set(case.required_fact_ids))
        covered_limits = len(set(row.selected_limitation_ids) & set(case.required_limitation_ids))
        if covered_facts != len(case.required_fact_ids) or covered_limits != len(case.required_limitation_ids):
            reasons.append("essential_facts_omitted")
        if row.baseline_words <= 0 or row.selector_words <= 0 or not row.rendered_clauses:
            reasons.append("empty_explanation_or_word_denominator")
        if row.irrelevant_clauses > row.rendered_clauses or row.unsupported_clauses > row.rendered_clauses:
            raise ValueError("clause count exceeds rendered denominator")
        clauses += row.rendered_clauses
        irrelevant += row.irrelevant_clauses
        unsupported += row.unsupported_clauses
        if reasons:
            failures.append({"case_id": case.case_id, "reasons": reasons})
        else:
            successes += 1
            facts_kept += covered_facts
            limits_kept += covered_limits
            reductions.append(Fraction(row.baseline_words - row.selector_words, row.baseline_words))
    cost = attempt_summary(pin, attempts, expected_pin_sha256, "L", successes)
    reduction = median(reductions) if len(reductions) == len(cases) else None
    full = successes == len(cases)
    cost_ok = (cost["cost_per_success_usd"] is not None
               and approved_cost_per_success_usd is not None
               and cost["cost_per_success_usd"] <= approved_cost_per_success_usd)
    measured = cost["live_evidence_eligible"] and inventory["minimum_24_balanced"]
    enabled = bool(measured and full and reduction is not None
                   and reduction >= Fraction(1, 5) and cost_ok)
    return {"arm": "L", "inventory": inventory, "failures": failures,
            "successful_explanations": successes, "expected_denominator": len(cases),
            "necessary_fact_recall": facts_kept / facts_total if facts_total else None,
            "limitation_recall": limits_kept / limits_total if limits_total else None,
            "irrelevant_clause_fraction": irrelevant / clauses if clauses else None,
            "unsupported_rendered_clauses": unsupported,
            "invalid_or_withheld_rate": (len(cases) - successes) / len(cases),
            "median_paired_word_reduction": float(reduction) if reduction is not None else None,
            "word_reduction_range": [float(min(reductions)), float(max(reductions))]
            if reductions else None,
            "word_range_is_confidence_interval": False,
            "word_pair_denominator": len(reductions),
            "criterion": "full essential coverage, >=24 balanced cases, >=20% median paired word reduction, zero critical errors, approved cost limit",
            "measurement_status": "RECORDED" if measured else "INCOMPLETE",
            "enablement_criterion": "MET" if enabled else (
                "NOT_MET" if measured and approved_cost_per_success_usd is not None
                and cost["billing_fully_known"] else "INCONCLUSIVE"),
            "enable_selector_by_default": enabled, "default_arm": "L" if enabled else "D",
            "cost": cost, "product_acceptance": False}


class PObservation(Record):
    case_id: Identity
    resource_id: Identity
    rule_id: Literal["R1", "R2", "R3", "R4"]
    attempt_id: Identity
    claim_ids: tuple[Identity, ...] = Field(max_length=1024)
    first: tuple[ClaimAssessment, ...] = Field(max_length=1024)
    second: tuple[ClaimAssessment, ...] = Field(max_length=1024)
    adjudicated: tuple[ClaimAssessment, ...] = Field(max_length=1024)
    critical_false_claim_ids: tuple[Identity, ...] = Field(max_length=1024)
    withheld: bool


def p_utility(cases: tuple[ExplanationCase, ...], observations: tuple[PObservation, ...],
              pin: MeasurementPin, attempts: tuple[Attempt, ...], expected_pin_sha256: str,
              generator_authors: set[str], appointed_assessors: tuple[str, str],
              appointed_adjudicator: str) -> dict:
    inventory = _inventory(cases)
    if explanation_inventory_digest(cases) != pin.explanation_inventory_sha256:
        raise ValueError("independent explanation denominator pin mismatch")
    if len(observations) > 4096:
        raise ValueError("too many P observations")
    first_id, second_id = appointed_assessors
    if (not all(name.strip() for name in (*appointed_assessors, appointed_adjudicator))
            or len({first_id, second_id, appointed_adjudicator}) != 3
            or {first_id, second_id, appointed_adjudicator} & generator_authors):
        raise ValueError("two independent assessors and third-party adjudicator required")
    by_key = {(row.case_id, row.resource_id, row.rule_id): row for row in observations}
    if len(by_key) != len(observations) or not set(by_key) <= {_key(row) for row in cases}:
        raise ValueError("duplicate or foreign P observation")
    attempt_map = {row.attempt_id: row for row in attempts}
    counts: Counter = Counter({name: 0 for name in (
        "generated", "supported", "contradicted", "unsupported", "unknown", "withheld",
        "missing_explanations", "withheld_explanations", "critical_false_claims",
        "unresolved_claims", "agreed_claims", "adjudicated_claims")})
    reports = []
    successes = facts_kept = limits_kept = 0
    provenance_complete = True
    for case in cases:
        row = by_key.get(_key(case))
        if row is None:
            reports.append({"case_id": case.case_id, "complete": False, "reason": "missing_observation"})
            counts["missing_explanations"] += 1
            continue
        _unique(row.claim_ids, "P claims")
        _unique(tuple(a.claim_id for a in row.adjudicated), "adjudicated claims")
        _unique(row.critical_false_claim_ids, "critical false claims")
        if not set(row.critical_false_claim_ids) <= set(row.claim_ids):
            raise ValueError("foreign critical false claim")
        for annotations, actor in ((row.first, first_id), (row.second, second_id),
                                   (row.adjudicated, appointed_adjudicator)):
            for a in annotations:
                if (a.assessor_id != actor or a.claim_id not in row.claim_ids
                        or not set(a.necessary_fact_ids) <= set(case.allowed_fact_ids)
                        or not set(a.limitation_ids) <= set(case.allowed_limitation_ids)):
                    raise ValueError("foreign rubric actor, claim or fact")
        adjudicated = {a.claim_id: a for a in row.adjudicated}
        metrics = prose_metrics(row.claim_ids, row.first, row.second,
                                set(case.required_fact_ids), set(case.required_limitation_ids),
                                generator_authors, adjudicated)
        resolved = []
        for a, b in zip(sorted(row.first, key=lambda a: a.claim_id),
                        sorted(row.second, key=lambda a: a.claim_id)):
            same = (a.label, a.withheld, set(a.necessary_fact_ids), set(a.limitation_ids)) == (
                b.label, b.withheld, set(b.necessary_fact_ids), set(b.limitation_ids))
            if same and a.claim_id in adjudicated:
                raise ValueError("adjudication supplied for an agreed claim")
            selected = a if same else adjudicated.get(a.claim_id)
            if selected is not None:
                resolved.append(selected)
        visible = [a for a in resolved if a.label == "supported" and not a.withheld and not row.withheld]
        kept_facts = set().union(*(set(a.necessary_fact_ids) for a in visible)) if visible else set()
        kept_limits = set().union(*(set(a.limitation_ids) for a in visible)) if visible else set()
        facts_kept += len(kept_facts & set(case.required_fact_ids))
        limits_kept += len(kept_limits & set(case.required_limitation_ids))
        attempt = attempt_map.get(row.attempt_id)
        provenance_ok = (attempt is not None and attempt.arm == "P"
                         and attempt.source_sha256 == case.input_sha256
                         and attempt.status != "pending"
                         and attempt.generated_claim_inventory_sha256 == _list_digest(list(row.claim_ids)))
        provenance_complete = provenance_complete and provenance_ok
        success = (metrics["complete"] and not row.withheld and not row.critical_false_claim_ids
                   and all(a.label == "supported" and not a.withheld for a in resolved)
                   and set(case.required_fact_ids) <= kept_facts
                   and set(case.required_limitation_ids) <= kept_limits
                   and provenance_ok and attempt.status == "ok")
        successes += bool(success)
        counts.update(metrics["counts"])
        counts["generated"] += len(row.claim_ids)
        counts["withheld_explanations"] += bool(row.withheld)
        counts["critical_false_claims"] += len(row.critical_false_claim_ids)
        counts["unresolved_claims"] += len(metrics["unresolved_disagreements"])
        counts["agreed_claims"] += sum(
            (a.label, a.withheld, set(a.necessary_fact_ids), set(a.limitation_ids)) ==
            (b.label, b.withheld, set(b.necessary_fact_ids), set(b.limitation_ids))
            for a, b in zip(sorted(row.first, key=lambda a: a.claim_id),
                            sorted(row.second, key=lambda a: a.claim_id)))
        counts["adjudicated_claims"] += len(row.adjudicated)
        reports.append({"case_id": case.case_id, "complete": not metrics["unresolved_disagreements"],
                        "successful": bool(success), "rubric": metrics})
    cost = attempt_summary(pin, attempts, expected_pin_sha256, "P", successes)
    generated = counts["generated"]
    facts_total = sum(len(row.required_fact_ids) for row in cases)
    limits_total = sum(len(row.required_limitation_ids) for row in cases)
    complete = len(observations) == len(cases) and all(r["complete"] for r in reports)
    return {"arm": "P", "inventory": inventory, "counts": dict(counts),
            "expected_explanations": len(cases), "successful_explanations": successes,
            "support_rate_all_generated": counts["supported"] / generated if generated else None,
            "assessor_agreement": counts["agreed_claims"] / generated if generated else None,
            "withheld_explanation_rate": counts["withheld_explanations"] / len(cases),
            "failed_explanation_rate": (len(cases) - successes) / len(cases),
            "necessary_fact_recall": facts_kept / facts_total if facts_total else None,
            "limitation_recall": limits_kept / limits_total if limits_total else None,
            "measurement_status": "RECORDED" if complete and provenance_complete and cost["live_evidence_eligible"]
            and inventory["minimum_24_balanced"] else "INCOMPLETE",
            "cases": reports, "cost": cost, "product_prose_enabled": False,
            "product_acceptance": False,
            "limitations": ["Appointment and annotation truth require independent custody verification.",
                            "Missing generations prevent a complete support denominator.",
                            "Latency measures attempts, not human reviewer productivity."]}
