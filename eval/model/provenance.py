"""Immutable, payload-free receipts and a deliberately live-ineligible ArmRow bridge.

Only this allowlisted export should be serialized, never dataclasses.asdict(Result):
Result observations may hold untrusted P claims for future independent assessment.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
import json
import re

from eval.model.experiment import Attempt, Observation, Result, canonical, digest
from eval.runner.scoring import ArmRow


@dataclass(frozen=True)
class ExportBundle:
    """All mutable dictionaries are serialized into immutable canonical JSON strings."""

    rows: tuple[ArmRow, ...]
    attempts_json: str
    provenance_json: str
    accounting_json: str
    observations_json: str
    live_eligible: bool = field(default=False, init=False)


def _attempt(row: Attempt) -> dict:
    return {
        "attempt_id": row.attempt_id, "arm": row.arm, "status": row.status,
        "duration_ms": row.duration_ms, "input_tokens": row.input_tokens,
        "output_tokens": row.output_tokens, "known_usd": row.known_usd,
        "unresolved_usd_upper": row.unresolved_usd_upper, "billing_known": row.billing_known,
        "requires_reconciliation": row.requires_reconciliation,
        "hashes": dict(row.hashes), "response_sha256": row.response_sha256,
        "price_sha256": row.price_sha256, "usage_sha256": row.usage_sha256,
        "live_eligible": False,
    }


def export_bundle(result: Result) -> ExportBundle:
    """Bind local model records to scorer identities without exposing payloads.

    Every L/P/M row is conservatively not_run even when its plumbing status is ok,
    independently of scorer eligibility defaults. D rows retain the
    supplied decision exactly; D is a baseline input, not executed by this harness.
    All attempts/failed spending are retained separately, including zero-row calls.
    Existing score() excludes not_run rows from costs: use accounting_json, never
    its model cost totals, for this ineligible bundle. No inference consumes this.
    """
    baseline_hash = digest(canonical([json.loads(row.model_dump_json()) for row in result.baseline]))
    if baseline_hash != result.baseline_sha256:
        raise ValueError("baseline invariance proof failed")
    context = result.context
    if result.live_eligible:
        raise ValueError("this exporter cannot accept live measurements")
    # Case/resource IDs are trusted local corpus metadata, not plan addresses.
    # Reject paths/pointers and unconstrained prose in emitted join fields.
    for row in result.baseline:
        if any(not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value)
               for value in (row.case_id, row.resource_id)):
            raise ValueError("scoring joins require safe opaque/local case identities")
        if row.reason_code is not None and not re.fullmatch(r"[a-z][a-z0-9_]{0,127}", row.reason_code):
            raise ValueError("baseline reason must be a fixed code")
        if not re.fullmatch(r"(?:sha256:)?[0-9a-f]{64}", row.measurement_ref):
            raise ValueError("baseline measurement_ref must be a receipt hash, never a path")
    attempts = tuple(obs.attempt for obs in result.observations if obs.attempt is not None)
    if len({row.attempt_id for row in attempts}) != len(attempts):
        raise ValueError("duplicate attempt receipt")
    receipts = [_attempt(row) for row in attempts]
    attempts_json = canonical(receipts)
    known = sum((Decimal(row.known_usd) for row in attempts if row.known_usd is not None), Decimal(0))
    unresolved = sum((Decimal(row.unresolved_usd_upper) for row in attempts), Decimal(0))
    fully_known = all(row.billing_known for row in attempts)
    accounting_json = canonical({
        "scope": "all attempts started by this invocation; cumulative journal separately bound",
        "requests": len(attempts), "known_usd": str(known),
        "unresolved_usd_upper": str(unresolved), "billing_fully_known": fully_known,
        "total_usd": str(known) if fully_known else None,
        "input_tokens_reported": sum(row.input_tokens or 0 for row in attempts),
        "output_tokens_reported": sum(row.output_tokens or 0 for row in attempts),
        "usage_complete": all(row.input_tokens is not None and row.output_tokens is not None
                              for row in attempts),
        "pending_attempt_ids": [row.attempt_id for row in attempts if row.requires_reconciliation],
        "duration_ms_all_attempts": sum(row.duration_ms for row in attempts),
        "valid_shape_attempts": sum(row.status == "ok" for row in attempts),
        "live_successes": 0, "cost_per_live_success_usd": None,
        "live_eligible": False,
    })
    finding_links = {link.finding_id: link for link in result.links}
    baseline_rows = {(r.case_id, r.resource_id, r.rule_id): r for r in result.baseline}
    summaries = []
    for obs in result.observations:
        link = finding_links.get(obs.finding_id)
        base = baseline_rows.get((link.case_id, link.resource_id, link.rule_id)) if link else None
        summaries.append({
            "arm": obs.arm, "finding_id": obs.finding_id, "status": obs.status,
            "case_id": link.case_id if link else None,
            "resource_id": link.resource_id if link else None,
            "rule_id": link.rule_id if link else None,
            "D_row_sha256": digest(canonical(base.model_dump(mode="json"))) if base else None,
            "fact_ids": list(obs.fact_ids),
            "reason": obs.reason, "attempt_id": obs.attempt.attempt_id if obs.attempt else None,
            "claim_count": len(obs.claims), "prediction_count": len(obs.predictions),
            "claims_withheld_from_product": obs.arm == "P",
            "selection_accepted": obs.selection.accepted if obs.selection is not None else False,
            "selected_fact_ids": list(obs.selection.selected_fact_ids) if obs.selection else [],
            "limitation_ids": list(obs.selection.limitation_ids) if obs.selection else [],
            "required_limitation_ids": list(obs.required_limitation_ids),
            "baseline_words": obs.baseline_words, "rendered_words": obs.rendered_words,
            "word_count_definition": "Unicode non-whitespace runs" if obs.arm == "L" else None,
            "render_source": obs.selection.source if obs.selection is not None else None,
            "word_counts_available": obs.baseline_words is not None and obs.rendered_words is not None,
            "live_eligible": False, "product_prose_enabled": False,
        })
    observations_json = canonical(summaries)
    provenance_json = canonical({
        "schema": 1, "build_sha256": context.build_sha256,
        "source_sha256": context.source_sha256, "corpus_sha256": context.corpus_sha256,
        "config_sha256": context.config_sha256,
        "baseline_sha256": result.baseline_sha256,
        "attempts_sha256": digest(attempts_json), "accounting_sha256": digest(accounting_json),
        "observations_sha256": digest(observations_json),
        "cumulative_journal_summary_sha256": digest(result.journal_summary_json),
        "live_eligible": False, "measurement_status": "NOT MEASURED",
        "D_role": "supplied immutable baseline; not executed by model orchestration",
        "P_role": "transient unreviewed assessor input; never product text",
        "inference_exclusions": ["gold", "split", "scanner outputs", "private source map",
                                  "addresses", "pointers", "build/corpus provenance"],
    })
    bundle_hash = digest(provenance_json)
    by_finding = {(obs.arm, obs.finding_id): obs for obs in result.observations if obs.arm != "M"}
    links = {(link.case_id, link.resource_id, link.rule_id): link for link in result.links}
    model_obs = [obs for obs in result.observations if obs.arm == "M"]
    if len(model_obs) > 1:
        raise ValueError("multiple M observations violate single-pass contract")
    model = model_obs[0] if model_obs else None
    model_map = dict(result.model_resource_map)
    model_predictions = {}
    if model is not None:
        for prediction in model.predictions:
            resource_id = model_map.get(prediction.resource_id)
            if resource_id is None:
                raise ValueError("foreign M identity in result")
            key = resource_id, prediction.rule_id
            if key in model_predictions:
                raise ValueError("ambiguous M prediction join")
            model_predictions[key] = prediction
    # Charge each attempt on at most one row. One M response can cover many
    # resources/rules; copying its cost to every row would multiply total spending.
    charged: set[str] = set()
    rows = list(result.baseline)

    def costs(obs: Observation | None) -> dict:
        if obs is None or obs.attempt is None:
            return {"known_usd": None, "unresolved_usd_upper": None,
                    "billing_known": False, "elapsed_seconds": None}
        receipt = obs.attempt
        owner = receipt.attempt_id not in charged
        charged.add(receipt.attempt_id)
        return {
            "known_usd": float(Decimal(receipt.known_usd)) if owner and receipt.known_usd is not None
                         else (0.0 if receipt.billing_known or receipt.known_usd is not None else None),
            "unresolved_usd_upper": float(Decimal(receipt.unresolved_usd_upper)) if owner else 0.0,
            "billing_known": receipt.billing_known,
            "elapsed_seconds": receipt.duration_ms / 1000 if owner else 0.0,
        }

    for base in result.baseline:
        link = links.get((base.case_id, base.resource_id, base.rule_id))
        for arm in ("L", "P", "M"):
            obs = model if arm == "M" else (
                by_finding.get((arm, link.finding_id)) if link else None)
            prediction = model_predictions.get((base.resource_id, base.rule_id)) if arm == "M" else None
            # L always falls back to D, including invalid/timeouts. P never writes
            # any risk outcome. M gets only its own predictions, never D labels.
            applicability = base.applicability if arm == "L" else (
                "supported" if prediction is not None else None)
            outcome = base.outcome if arm == "L" else (
                prediction.outcome if prediction is not None else None)
            fact_ids = base.decision_fact_ids if arm == "L" else (
                prediction.fact_ids if prediction is not None else ())
            rows.append(ArmRow(
                case_id=base.case_id, resource_id=base.resource_id, rule_id=base.rule_id,
                arm=arm, status="not_run", applicability=applicability, outcome=outcome,
                reason_code="mock_or_protocol_ineligible", decision_fact_ids=fact_ids,
                required_limitation_ids=base.required_limitation_ids if arm == "L" else (),
                source_sha256=context.source_sha256, build_sha256=context.build_sha256,
                measurement_ref="sha256:" + bundle_hash, **costs(obs)))
    # Any attempt without an ArmRow join is still present/counted in receipts and
    # accounting_json; no attempt may vanish merely because it produced no prediction.
    if tuple(rows[:len(result.baseline)]) != result.baseline:
        raise ValueError("D rows changed during export")
    return ExportBundle(tuple(rows), attempts_json, provenance_json,
                        accounting_json, observations_json)
