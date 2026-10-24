"""Explicit bridge from D5's preserved ineligible export; never promotes mocks.

No result payload, claims, provider call, journal execution or hidden label access.
Missing journal links/word counts/rubric annotations stay missing, never synthesized.
"""
from __future__ import annotations

from decimal import Decimal, DecimalException
import hashlib
import json
from typing import TYPE_CHECKING, Literal

from pydantic import Field

from eval.runner.custody import Digest, Identity, metadata_digest
from eval.runner.scoring import ArmRow, Record
from eval.runner.utility import (
    Attempt, ExplanationCase, LObservation, MeasurementPin, PObservation,
    attempt_summary, l_utility, p_utility,
)

if TYPE_CHECKING:
    from eval.model.provenance import ExportBundle


class AttemptSnapshot(Record):
    """D5 provenance._attempt's exact public projection, schema v1."""
    attempt_id: Identity
    arm: Literal["L", "P", "M"]
    status: Literal["ok", "invalid", "timeout", "error", "cancelled"]
    duration_ms: int = Field(ge=0)
    input_tokens: int | None = Field(ge=0)
    output_tokens: int | None = Field(ge=0)
    known_usd: str | None
    unresolved_usd_upper: str
    billing_known: bool
    requires_reconciliation: bool
    hashes: dict[str, Digest] = Field(max_length=16)
    response_sha256: Digest | None
    price_sha256: Digest
    usage_sha256: Digest
    live_eligible: Literal[False]


class JournalLink(Record):
    attempt_id: Identity
    start_record_sha256: Digest
    terminal_record_sha256: Digest


class ProducerAccounting(Record):
    """Exact D5 accounting_json v1 wire; authoritative invocation cost scope."""
    scope: Literal["all attempts started by this invocation; cumulative journal separately bound"]
    requests: int = Field(ge=0, le=10000)
    known_usd: str = Field(max_length=128)
    unresolved_usd_upper: str = Field(max_length=128)
    billing_fully_known: bool
    total_usd: str | None = Field(max_length=128)
    input_tokens_reported: int = Field(ge=0)
    output_tokens_reported: int = Field(ge=0)
    usage_complete: bool
    pending_attempt_ids: tuple[Identity, ...] = Field(max_length=10000)
    duration_ms_all_attempts: int = Field(ge=0)
    valid_shape_attempts: int = Field(ge=0)
    live_successes: Literal[0]
    cost_per_live_success_usd: None
    live_eligible: Literal[False]


class BridgeResult(Record):
    schema_version: Literal[1] = 1
    rows: tuple[ArmRow, ...]
    attempts: tuple[Attempt, ...]
    snapshots: tuple[AttemptSnapshot, ...]
    unconverted_attempt_ids: tuple[Identity, ...]
    known_usd_decimal: str
    unresolved_usd_upper_decimal: str
    billing_fully_known: bool
    authoritative_accounting: ProducerAccounting
    accounting_sha256: Digest
    per_arm_costs: dict[str, dict]
    live_evidence_eligible: Literal[False] = False
    limitations: tuple[str, ...]


def _json(raw: str):
    if len(raw.encode("utf-8")) > 16 * 1024 * 1024:
        raise ValueError("model export exceeds byte bound")

    def pairs(items):
        result = {}
        for name, value in items:
            if name in result:
                raise ValueError("duplicate model export key")
            result[name] = value
        return result

    def invalid(value):
        raise ValueError("nonfinite model export number")

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def _amount(value: str) -> Decimal:
    try:
        parsed = Decimal(value)
    except DecimalException as error:
        raise ValueError("invalid model cost amount") from error
    if not parsed.is_finite() or parsed < 0:
        raise ValueError("invalid model cost amount")
    return parsed


def validate_accounting(accounting: ProducerAccounting, rows: tuple[AttemptSnapshot, ...]) -> None:
    """Reconcile every invocation attempt, including no-row failures and liabilities."""
    known = sum((_amount(row.known_usd) for row in rows if row.known_usd is not None), Decimal(0))
    upper = sum((_amount(row.unresolved_usd_upper) for row in rows), Decimal(0))
    pending = tuple(row.attempt_id for row in rows if row.requires_reconciliation)
    fully_known = all(row.billing_known for row in rows)
    if (accounting.requests != len(rows) or _amount(accounting.known_usd) != known
            or _amount(accounting.unresolved_usd_upper) != upper
            or accounting.billing_fully_known != fully_known
            or set(accounting.pending_attempt_ids) != set(pending)
            or len(accounting.pending_attempt_ids) != len(pending)
            or accounting.input_tokens_reported != sum(row.input_tokens or 0 for row in rows)
            or accounting.output_tokens_reported != sum(row.output_tokens or 0 for row in rows)
            or accounting.usage_complete != all(row.input_tokens is not None and row.output_tokens is not None for row in rows)
            or accounting.duration_ms_all_attempts != sum(row.duration_ms for row in rows)
            or accounting.valid_shape_attempts != sum(row.status == "ok" for row in rows)):
        raise ValueError("producer accounting omits or contradicts all-attempt receipts")
    if fully_known:
        if accounting.total_usd is None or _amount(accounting.total_usd) != known:
            raise ValueError("known total differs from all-attempt cost")
    elif accounting.total_usd is not None:
        raise ValueError("unknown billing cannot publish a total cost")


def _arm_costs(rows: tuple[AttemptSnapshot, ...]) -> dict:
    result = {}
    for arm in ("L", "P", "M"):
        selected = [row for row in rows if row.arm == arm]
        known = sum((_amount(row.known_usd) for row in selected if row.known_usd is not None), Decimal(0))
        upper = sum((_amount(row.unresolved_usd_upper) for row in selected), Decimal(0))
        fully_known = all(row.billing_known and not row.requires_reconciliation for row in selected)
        result[arm] = {
            "scope": "all invocation attempts for this arm; cumulative journal not reconciled",
            "requests": len(selected), "known_usd_decimal": str(known),
            "unresolved_usd_upper_decimal": str(upper), "billing_fully_known": fully_known,
            "total_usd_decimal": str(known) if fully_known else None,
            "pending_attempt_ids": [row.attempt_id for row in selected if row.requires_reconciliation],
            "usage_complete": all(row.input_tokens is not None and row.output_tokens is not None for row in selected),
            "cumulative_journal_complete": False, "live_evidence_eligible": False,
            "cost_per_live_success_usd": None,
        }
    return result


def bridge_bundle(bundle: ExportBundle, pins: tuple[MeasurementPin, ...],
                  journal_links: tuple[JournalLink, ...] = ()) -> BridgeResult:
    """D5's actual producer is fake/protocol-only; no bridge can make it live.

    Exact journal receipts are external custody inputs. Missing links keep raw
    snapshot accounting but prevent creation of a stronger utility Attempt.
    """
    provenance = _json(bundle.provenance_json)
    if (type(provenance) is not dict or bundle.live_eligible or provenance.get("live_eligible") is not False
            or provenance.get("schema") != 1):
        raise ValueError("unsupported/live model producer export")
    for label, raw in (("attempts", bundle.attempts_json),
                       ("accounting", bundle.accounting_json),
                       ("observations", bundle.observations_json)):
        if hashlib.sha256(raw.encode("utf-8")).hexdigest() != provenance.get(label + "_sha256"):
            raise ValueError("D5 export hash mismatch")
    raw_attempts = _json(bundle.attempts_json)
    if type(raw_attempts) is not list or len(raw_attempts) > 10000:
        raise ValueError("bounded D5 attempt list required")
    snapshots = tuple(AttemptSnapshot.model_validate_json(json.dumps(row)) for row in raw_attempts)
    if len({row.attempt_id for row in snapshots}) != len(snapshots):
        raise ValueError("duplicate D5 attempt")
    accounting = ProducerAccounting.model_validate_json(json.dumps(_json(bundle.accounting_json)))
    validate_accounting(accounting, snapshots)
    links = {row.attempt_id: row for row in journal_links}
    if len(links) != len(journal_links) or not set(links) <= {row.attempt_id for row in snapshots}:
        raise ValueError("duplicate/foreign journal link")
    pin_by_arm = {}
    for pin in pins:
        for attempt_id in pin.attempt_ids:
            if attempt_id in pin_by_arm:
                raise ValueError("attempt assigned to multiple measurement pins")
            pin_by_arm[attempt_id] = pin
        if (pin.build_sha256 != provenance["build_sha256"]
                or pin.corpus_sha256 != provenance["corpus_sha256"]):
            raise ValueError("bridge build/corpus mismatch")
    converted = []
    missing = []
    known = Decimal(0)
    upper = Decimal(0)
    for row in snapshots:
        known += _amount(row.known_usd) if row.known_usd is not None else Decimal(0)
        upper += _amount(row.unresolved_usd_upper)
        if row.billing_known and row.known_usd is None:
            raise ValueError("D5 billing-known amount missing")
        pin = pin_by_arm.get(row.attempt_id)
        link = links.get(row.attempt_id)
        if pin is None or link is None:
            missing.append(row.attempt_id)
            continue
        # Context/provenance.source_sha256 is the pinned raw saved-plan digest.
        # hashes["input"] is only the canonical model request digest; retain it
        # untouched in AttemptSnapshot metadata and never substitute it for raw.
        raw_case_hash = provenance["source_sha256"]
        request_hash = row.hashes.get("input")
        input_hash = row.hashes.get("projection")
        if request_hash is None or input_hash is None:
            missing.append(row.attempt_id)
            continue
        if (row.hashes.get("build") != provenance["build_sha256"]
                or row.hashes.get("corpus") != provenance["corpus_sha256"]):
            raise ValueError("attempt build/corpus differs from producer provenance")
        converted.append(Attempt(
            attempt_id=row.attempt_id, arm=row.arm, pin_sha256=metadata_digest(pin), origin="mock",
            input_sha256=input_hash, source_sha256=raw_case_hash,
            response_sha256=row.response_sha256, start_record_sha256=link.start_record_sha256,
            terminal_record_sha256=link.terminal_record_sha256, status=row.status,
            elapsed_seconds=row.duration_ms / 1000, input_tokens=row.input_tokens,
            output_tokens=row.output_tokens,
            known_usd=float(_amount(row.known_usd)) if row.known_usd is not None else None,
            billing_known=row.billing_known and not row.requires_reconciliation,
            unresolved_usd_upper=float(_amount(row.unresolved_usd_upper)),
        ))
    # Never mutate D baseline or turn a model plumbing outcome into an executed row.
    rows = tuple(row if row.arm == "D" else row.model_copy(update={
        "schema_version": 2, "measurement_kind": "mock", "eligibility_ref": None,
        "status": "not_run"}) for row in bundle.rows)
    return BridgeResult(
        rows=rows, attempts=tuple(converted), snapshots=snapshots,
        unconverted_attempt_ids=tuple(missing), known_usd_decimal=str(known),
        unresolved_usd_upper_decimal=str(upper),
        billing_fully_known=bool(snapshots) and all(
            row.billing_known and not row.requires_reconciliation for row in snapshots),
        authoritative_accounting=accounting, accounting_sha256=provenance["accounting_sha256"],
        per_arm_costs=_arm_costs(snapshots),
        limitations=("D5 producer exports are mock/protocol only: NOT MEASURED.",
                     "No start/terminal journal digest, word count or annotation is invented.",
                     "All raw attempt snapshots and liabilities survive incomplete conversion."))


class LBatch(Record):
    cases: tuple[ExplanationCase, ...] = Field(max_length=4096)
    observations: tuple[LObservation, ...] = Field(max_length=4096)
    pin: MeasurementPin
    expected_pin_sha256: Digest
    attempts: tuple[Attempt, ...] = Field(max_length=10000)
    approved_cost_per_success_usd: float | None = Field(ge=0, allow_inf_nan=False)


class PBatch(Record):
    cases: tuple[ExplanationCase, ...] = Field(max_length=4096)
    observations: tuple[PObservation, ...] = Field(max_length=4096)
    pin: MeasurementPin
    expected_pin_sha256: Digest
    attempts: tuple[Attempt, ...] = Field(max_length=10000)
    generator_authors: tuple[Identity, ...] = Field(min_length=1, max_length=256)
    appointed_assessors: tuple[Identity, Identity]
    appointed_adjudicator: Identity


class MBatch(Record):
    pin: MeasurementPin
    expected_pin_sha256: Digest
    attempts: tuple[Attempt, ...] = Field(max_length=10000)


class ProducerExport(Record):
    """Allowlisted ExportBundle fields only; never Result or raw experimental prose."""
    rows: tuple[ArmRow, ...] = Field(max_length=100000)
    attempts_json: str = Field(max_length=16 * 1024 * 1024)
    provenance_json: str = Field(max_length=1024 * 1024)
    accounting_json: str = Field(max_length=1024 * 1024)
    observations_json: str = Field(max_length=16 * 1024 * 1024)
    live_eligible: Literal[False] = False


class UtilityRequest(Record):
    schema_version: Literal[1] = 1
    l: LBatch | None = None
    p: PBatch | None = None
    m: MBatch | None = None
    producer_exports: tuple[ProducerExport, ...] = Field(default=(), max_length=256)


def links_for_bundle(bundle: ExportBundle, journal_links: tuple[JournalLink, ...]) -> tuple[JournalLink, ...]:
    """Narrow the one global link set to this invocation before D5 validation."""
    raw = _json(bundle.attempts_json)
    if type(raw) is not list:
        raise ValueError("bounded D5 attempt list required")
    attempt_ids = {row.get("attempt_id") for row in raw if type(row) is dict}
    if len(attempt_ids) != len(raw):
        raise ValueError("malformed/duplicate D5 attempt identity")
    return tuple(link for link in journal_links if link.attempt_id in attempt_ids)


def utility_summaries(request: UtilityRequest) -> dict:
    result = {arm: {"measurement_status": "INCOMPLETE", "reason": "missing_utility_denominator"}
              for arm in ("L", "P", "M")}
    if request.l is not None:
        batch = request.l
        result["L"] = l_utility(batch.cases, batch.observations, batch.pin, batch.attempts,
                                batch.expected_pin_sha256, batch.approved_cost_per_success_usd)
    if request.p is not None:
        batch = request.p
        result["P"] = p_utility(batch.cases, batch.observations, batch.pin, batch.attempts,
                                batch.expected_pin_sha256, set(batch.generator_authors),
                                batch.appointed_assessors, batch.appointed_adjudicator)
    if request.m is not None:
        batch = request.m
        cost = attempt_summary(batch.pin, batch.attempts, batch.expected_pin_sha256, "M", 0)
        result["M"] = {"measurement_status": "RECORDED" if cost["live_evidence_eligible"]
                       else "INCOMPLETE", "cost": cost,
                       "cost_per_success_scope": "M is detection, not successful explanation"}
    if request.producer_exports:
        bridges = [bridge_bundle(bundle, ()) for bundle in request.producer_exports]
        identities = [row.attempt_id for bridge in bridges for row in bridge.snapshots]
        if len(identities) != len(set(identities)):
            raise ValueError("producer invocations repeat an attempt")
        for arm in ("L", "P", "M"):
            parts = [bridge.per_arm_costs[arm] for bridge in bridges]
            known = sum((_amount(part["known_usd_decimal"]) for part in parts), Decimal(0))
            upper = sum((_amount(part["unresolved_usd_upper_decimal"]) for part in parts), Decimal(0))
            fully_known = all(part["billing_fully_known"] for part in parts)
            result[arm]["producer_all_attempt_cost"] = {
                "scope": "all imported invocation attempts; not cumulative journal reconciliation",
                "requests": sum(part["requests"] for part in parts),
                "known_usd_decimal": str(known), "unresolved_usd_upper_decimal": str(upper),
                "total_usd_decimal": str(known) if fully_known else None,
                "billing_fully_known": fully_known, "cumulative_journal_complete": False,
                "pending_attempt_ids": [name for part in parts for name in part["pending_attempt_ids"]],
                "usage_complete": all(part["usage_complete"] for part in parts),
                "live_evidence_eligible": False, "cost_per_live_success_usd": None,
            }
            # An ineligible producer's successful-shaped rows cannot become live by
            # attaching a second unrelated utility receipt channel.
            result[arm]["measurement_status"] = "INCOMPLETE"
        result["producer_invocations"] = [
            {"accounting_sha256": bridge.accounting_sha256,
             "accounting": bridge.authoritative_accounting.model_dump(mode="json"),
             "unconverted_attempt_ids": list(bridge.unconverted_attempt_ids)} for bridge in bridges]
    return result
