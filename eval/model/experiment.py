"""D/L/P/M source orchestration. Imports/calls are deferred until authorized activation.

Only exact safe projections reach the injected transport. Local row joins, baseline,
corpus provenance, gold, splits, scanner results and the private M map never reach it.
No live adapter, subprocess, tool API, retry or automatic journal reconciliation exists.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
import hashlib
import json
import math
import re
from time import perf_counter
from typing import Any

from pydantic import TypeAdapter

from iac_review.attempts import AttemptJournal, JournalError, Reservation
from iac_review.contracts import PlanDocument
from iac_review.explain import SelectionResult, build_capsule, validate_selection
from eval.model.protocol import Prediction, model_only_input, validate_predictions
from eval.model.transport import Arm, INSTRUCTIONS, Reply, Request, Terminal, Transport, Usage
from eval.runner.scoring import ArmRow


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False)


def digest(value: str | bytes) -> str:
    return hashlib.sha256(value.encode("utf-8") if isinstance(value, str) else value).hexdigest()


@dataclass(frozen=True)
class Context:
    build_sha256: str
    source_sha256: str
    corpus_sha256: str
    config_sha256: str


@dataclass(frozen=True)
class Limits:
    input_tokens_upper: int = 65_536
    output_tokens_upper: int = 4_096
    max_input_bytes: int = 65_536
    max_output_bytes: int = 16_384
    timeout_seconds: float = 30.0
    max_attempts: int = 100


@dataclass(frozen=True)
class FindingLink:
    """Local join only; never part of a transport Request."""

    finding_id: str
    case_id: str
    resource_id: str
    rule_id: str


@dataclass(frozen=True)
class ResourceLink:
    """Join the report's fresh public resource ID to the parser's local opaque key."""

    resource_id: str
    resource_key: str


@dataclass(frozen=True)
class Attempt:
    attempt_id: str
    arm: Arm
    status: Terminal
    duration_ms: int
    input_tokens: int | None
    output_tokens: int | None
    known_usd: str | None
    unresolved_usd_upper: str
    billing_known: bool
    hashes: tuple[tuple[str, str], ...]
    response_sha256: str | None
    price_sha256: str
    usage_sha256: str
    requires_reconciliation: bool
    # Deliberately cannot be supplied by a transport or promoted by a caller.
    live_eligible: bool = field(default=False, init=False)


@dataclass(frozen=True)
class Observation:
    arm: Arm
    finding_id: str | None
    status: str
    reason: str
    attempt: Attempt | None
    selection: SelectionResult | None = field(default=None, repr=False)
    # Untrusted experimental prose is transient assessor input, never product text/export.
    claims: tuple[str, ...] = field(default=(), repr=False)
    predictions: tuple[Prediction, ...] = ()


@dataclass(frozen=True)
class Result:
    context: Context
    baseline: tuple[ArmRow, ...]
    baseline_sha256: str
    links: tuple[FindingLink, ...]
    observations: tuple[Observation, ...]
    # Opaque M -> local resource identity only. No private plan values/addresses/pointers.
    model_resource_map: tuple[tuple[str, str], ...]
    journal_summary_json: str
    live_eligible: bool = field(default=False, init=False)


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate response key")
        value[key] = item
    return value


def _response(payload: bytes) -> dict[str, Any]:
    def reject_constant(_: str) -> None:
        raise ValueError("nonfinite response number")

    value = json.loads(payload, object_pairs_hook=_object, parse_constant=reject_constant)
    if type(value) is not dict:
        raise ValueError("response must be a JSON object")
    return value


def _usage(value: Usage) -> Usage:
    if not isinstance(value, Usage):
        return Usage()
    tokens = tuple(v if type(v) is int and v >= 0 else None
                   for v in (value.input_tokens, value.output_tokens))
    usd = value.known_usd
    if usd is not None and (not isinstance(usd, Decimal) or not usd.is_finite() or usd < 0):
        usd = None
    # Invalid token metadata cannot erase an independently reported known charge.
    return Usage(tokens[0], tokens[1], usd)


def _baseline_hash(rows: tuple[ArmRow, ...]) -> str:
    return digest(canonical([json.loads(row.model_dump_json()) for row in rows]))


def run_experiments(
    *, plan: PlanDocument, shareable: dict[str, Any], baseline: tuple[ArmRow, ...],
    links: tuple[FindingLink, ...], resource_links: tuple[ResourceLink, ...],
    context: Context, transport: Transport,
    journal: AttemptJournal, limits: Limits = Limits(),
) -> Result:
    """One L/P call per linked finding, one isolated M call; D is supplied, never rerun.

    Intended for future keyless activation. This source-construction package has NOT
    executed it. Gold/split/scanner records are intentionally absent from this API.
    Journal must have separate exclusive ownership and separately chosen mock budget.
    """
    for value in (context.build_sha256, context.source_sha256,
                  context.corpus_sha256, context.config_sha256):
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError("context requires pinned SHA256 identities")
    for value in (limits.input_tokens_upper, limits.output_tokens_upper,
                  limits.max_input_bytes, limits.max_output_bytes, limits.max_attempts):
        if type(value) is not int or value <= 0:
            raise ValueError("limits must be positive integers")
    if not math.isfinite(limits.timeout_seconds) or limits.timeout_seconds <= 0:
        raise ValueError("timeout must be finite and positive")
    identity = transport.identity
    if identity.kind not in ("mock", "protocol"):
        raise ValueError("live transports are outside this construction grant")
    for value in (identity.provider, identity.model, identity.version):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}", value):
            raise ValueError("transport identity must be a fixed version label")
    if (journal.price.provider, journal.price.model) != (identity.provider, identity.model):
        raise ValueError("journal price and transport identity disagree")
    if plan.identity.sha256 != context.source_sha256:
        raise ValueError("source identity mismatch")
    # Detach caller data before exposing any callback. Tuple/string-only wires are immutable.
    frozen = tuple(ArmRow.model_validate_json(row.model_dump_json()) for row in baseline)
    baseline_hash = _baseline_hash(frozen)
    keyed = {(row.case_id, row.resource_id, row.rule_id): row for row in frozen}
    if len(keyed) != len(frozen) or any(
        row.arm != "D" or row.source_sha256 != context.source_sha256
        or row.build_sha256 != context.build_sha256 for row in frozen
    ):
        raise ValueError("baseline must be unique pinned D rows")
    if len({row.case_id for row in frozen}) > 1:
        raise ValueError("one plan invocation cannot contain multiple case identities")
    local_keys = {resource.key for resource in plan.resources}
    public_by_key = {link.resource_key: link.resource_id for link in resource_links}
    if set(public_by_key) != local_keys or len(public_by_key) != len(resource_links) \
            or len(set(public_by_key.values())) != len(resource_links):
        raise ValueError("resource joins must cover the exact plan without collisions")
    if {row.resource_id for row in frozen} != set(public_by_key.values()):
        raise ValueError("D rows and local resource joins disagree")
    if len({link.finding_id for link in links}) != len(links):
        raise ValueError("duplicate explanation finding join")
    if len({(link.case_id, link.resource_id, link.rule_id) for link in links}) != len(links):
        raise ValueError("duplicate explanation row join")
    capsules = []
    for link in links:
        row = keyed.get((link.case_id, link.resource_id, link.rule_id))
        capsule = build_capsule(json.loads(canonical(shareable)), link.finding_id)
        matching = [r for r in shareable.get("evaluations", ())
                    if r.get("finding_id") == link.finding_id]
        if row is None or row.status != "ok" or row.rule_id != capsule.rule_id \
                or row.outcome != capsule.outcome or row.applicability != "supported" \
                or len(matching) != 1 or matching[0].get("resource_id") != link.resource_id:
            raise ValueError("capsule and pinned D row disagree")
        capsules.append((link, capsule))
    # Build M from PlanDocument alone BEFORE invoking any L/P callback. Do not pass
    # D findings, shareable report, local joins or private_map through to the model.
    model_request, private_map = model_only_input(plan)
    model_json = model_request.model_dump_json()
    model_map = tuple((r.resource_id, public_by_key[private_map[r.resource_id]])
                      for r in model_request.resources)
    del private_map
    observations: list[Observation] = []
    attempted = 0
    halt = False

    def invoke(arm: Arm, payload: str, finding_id: str | None, validator: Any) -> Observation:
        nonlocal attempted, halt
        if halt or attempted >= limits.max_attempts:
            return Observation(arm, finding_id, "not_run", "stopped_or_request_cap", None)
        if len(payload.encode("utf-8")) > limits.max_input_bytes:
            return Observation(arm, finding_id, "not_run", "input_size_limit", None)
        request = Request(arm, payload, INSTRUCTIONS[arm], limits.input_tokens_upper,
                          limits.output_tokens_upper, limits.timeout_seconds)
        hashes = {
            "build": context.build_sha256, "corpus": context.corpus_sha256,
            "projection": digest(payload), "prompt": digest(request.instruction),
            "input": digest(canonical({"arm": arm, "instruction": request.instruction,
                                        "payload": payload})),
            "model": digest(canonical([identity.provider, identity.model, identity.version,
                                        identity.kind])),
            "config": digest(canonical([context.config_sha256, limits.input_tokens_upper,
                                         limits.output_tokens_upper, limits.max_input_bytes,
                                         limits.max_output_bytes, limits.timeout_seconds,
                                         limits.max_attempts])),
        }
        bound = (Decimal(limits.input_tokens_upper) * journal.price.input_usd_per_million
                 + Decimal(limits.output_tokens_upper) * journal.price.output_usd_per_million
                 ) / Decimal(1_000_000)
        try:
            attempt_id = journal.start(Reservation(
                input_tokens_upper=limits.input_tokens_upper,
                output_tokens_upper=limits.output_tokens_upper,
                request_usd_upper=bound, hashes=hashes))
        except JournalError:
            halt = True
            return Observation(arm, finding_id, "not_run", "journal_start_blocked", None)
        attempted += 1
        start = perf_counter()
        usage = Usage()
        response_hash = None
        selected = None
        claims: tuple[str, ...] = ()
        predictions: tuple[Prediction, ...] = ()
        status: Terminal = "error"
        reason = "transport_error"
        try:
            reply = transport.complete(request)
            if not isinstance(reply, Reply):
                raise ValueError("invalid transport envelope")
            usage = _usage(reply.usage)
            if reply.status not in ("ok", "invalid", "timeout", "error", "cancelled"):
                raise ValueError("invalid transport status")
            status = reply.status
            reason = "transport_" + status
            if type(reply.payload) is not bytes or len(reply.payload) > limits.max_output_bytes:
                status, reason = "invalid", "response_size_or_type"
            else:
                response_hash = digest(reply.payload)
                if status == "ok":
                    try:
                        selected, claims, predictions = validator(_response(reply.payload))
                        if selected is not None and not selected.accepted:
                            status, reason = "invalid", "invalid_selection"
                        else:
                            reason = "validated_shape_not_semantic_approval"
                    except (ValueError, TypeError, KeyError, RecursionError, UnicodeError):
                        status, reason = "invalid", "invalid_response"
        except TimeoutError:
            status, reason = "timeout", "transport_timeout"
        except KeyboardInterrupt:
            status, reason = "cancelled", "operator_cancelled"
        except Exception:
            # Exception strings may contain request text/secrets. Never record them.
            status, reason = "error", "transport_error"
        elapsed = max(0, int((perf_counter() - start) * 1000))
        if elapsed > limits.timeout_seconds * 1000 and status != "cancelled":
            status, reason = "timeout", "cooperative_deadline_exceeded"
        if status != "ok":
            # Invalid L remains a deterministic fallback; unverified P/M is withheld.
            selected, predictions = None, ()
            # Parsed P claims stay transient for assessors even when a cooperative
            # deadline was exceeded; withholding must not erase generated claims.
        if status in ("timeout", "cancelled"):
            halt = True
        # If durable terminal append fails, propagate: start remains a liability.
        # Never manufacture an apparently complete receipt for a failed append.
        journal.terminal(attempt_id, status, elapsed, input_tokens=usage.input_tokens,
                         output_tokens=usage.output_tokens, known_usd=usage.known_usd,
                         response_sha256=response_hash)
        billing_known = status != "timeout" and all(v is not None for v in (
            usage.input_tokens, usage.output_tokens, usage.known_usd))
        unresolved = max(bound - (usage.known_usd or Decimal(0)), Decimal(0)) \
            if not billing_known else Decimal(0)
        receipt = Attempt(attempt_id, arm, status, elapsed, usage.input_tokens,
                          usage.output_tokens, None if usage.known_usd is None else str(usage.known_usd),
                          str(unresolved), billing_known, tuple(sorted(hashes.items())), response_hash,
                          digest(journal.price.model_dump_json()),
                          digest(canonical([usage.input_tokens, usage.output_tokens,
                                            None if usage.known_usd is None else str(usage.known_usd)])),
                          not billing_known)
        return Observation(arm, finding_id, status, reason, receipt, selected, claims, predictions)

    for link, capsule in capsules:
        payload = capsule.model_dump_json()

        def validate_l(value: dict[str, Any], current: Any = capsule) -> tuple:
            return validate_selection(current, value), (), ()

        def validate_p(value: dict[str, Any]) -> tuple:
            if set(value) != {"claims"} or type(value["claims"]) is not list \
                    or not 1 <= len(value["claims"]) <= 128:
                raise ValueError("invalid experimental prose shape")
            if any(type(claim) is not str or not claim.strip() for claim in value["claims"]):
                raise ValueError("empty or invalid claim")
            return None, tuple(value["claims"]), ()

        observations.append(invoke("L", payload, link.finding_id, validate_l))
        observations.append(invoke("P", payload, link.finding_id, validate_p))

    def validate_m(value: dict[str, Any]) -> tuple:
        if set(value) != {"predictions"} or type(value["predictions"]) is not list:
            raise ValueError("invalid model-only response")
        predictions = TypeAdapter(tuple[Prediction, ...]).validate_json(
            canonical(value["predictions"]))
        validate_predictions(model_request, predictions)
        return None, (), predictions

    if model_request.resources:
        observations.append(invoke("M", model_json, None, validate_m))
    if _baseline_hash(frozen) != baseline_hash:
        raise ValueError("D baseline changed during explanation experiment")
    return Result(context, frozen, baseline_hash, links, tuple(observations), model_map,
                  canonical(journal.summary()))
