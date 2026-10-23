"""External activation pins and exact durable journal-start binding; no I/O on import.

Agreement of hashes is structural, never proof of operator authority or live eligibility.
The caller must obtain activation and expected pins from its external approval owner.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from ipaddress import ip_address
import json
import math
import re
from time import monotonic

from iac_review.attempts import AttemptJournal
from iac_review.ingest import decode_source, read_source_bytes
from eval.model.experiment import canonical, digest
from eval.model.provider_wire import (
    ENDPOINT, ApprovedAttempt, ProviderConfig, model_request_digest, permit_digest, request_digest,
)
from eval.model.transport import Request


def require(ok: bool, code: str) -> None:
    if not ok:
        raise ValueError(code)


def remaining(deadline: float) -> float:
    require(type(deadline) in (int, float) and math.isfinite(deadline), "provider_deadline_invalid")
    value = deadline - monotonic()
    if value <= 0:
        raise TimeoutError("provider_whole_attempt_deadline")
    return value


@dataclass(frozen=True)
class StartedAttempt:
    attempt_id: str
    journal_sha256: str
    start_record_sha256: str
    price_sha256: str
    budget_sha256: str
    hashes: tuple[tuple[str, str], ...]
    input_tokens_upper: int
    output_tokens_upper: int
    usd_upper: str


def started_attempt(journal: AttemptJournal, attempt_id: str) -> StartedAttempt:
    """Read the actual active owner's durable journal, never mint another start.

    Require the exact final unmatched start and no other pending liabilities.
    The external controller separately pins this returned journal/start identity.
    """
    require(isinstance(journal, AttemptJournal), "provider_actual_journal_required")
    require(type(attempt_id) is str and re.fullmatch(r"[0-9a-f]{32}", attempt_id) is not None,
            "provider_attempt_id_invalid")
    data = read_source_bytes(journal.path)
    snapshot = AttemptJournal.snapshot(journal.path)
    require(digest(data) == snapshot["journal_sha256"] and snapshot["worker_lock_present"]
            and not snapshot["reservation_overrun"], "provider_journal_changed_or_unowned")
    records = [decode_source(line) for line in data.splitlines()]
    require(bool(records), "provider_durable_start_missing")
    event = records[-1]
    require(event["event"] == "request_start" and event["attempt_id"] == attempt_id,
            "provider_exact_final_start_required")
    pending = [a["attempt_id"] for a in snapshot["attempts"] if a["requires_reconciliation"]]
    require(pending == [attempt_id] and snapshot["attempts"][-1]["status"] == "interrupted",
            "provider_journal_liability_or_terminal_conflict")
    require(event["price"] == json.loads(journal.price.model_dump_json()),
            "provider_journal_price_changed")
    require(read_source_bytes(journal.path) == data, "provider_journal_changed")
    return StartedAttempt(attempt_id, digest(data), digest(canonical(event)),
        digest(journal.price.model_dump_json()), digest(journal.budget.model_dump_json()),
        tuple(sorted(event["hashes"].items())), event["input_tokens_upper"],
        event["output_tokens_upper"], event["usd_upper"])


@dataclass(frozen=True)
class Activation:
    """One externally pinned request admission, with no credential value or payload."""

    provider: str
    model: str
    model_version: str
    approval_sha256: str
    provider_sha256: str
    data_transfer_sha256: str
    price_sha256: str
    budget_sha256: str
    journal_sha256: str
    journal_config_sha256: str
    model_request_sha256: str
    wire_request_sha256: str
    approved_ip_literal: str
    max_output_bytes: int
    endpoint: str = ENDPOINT
    enabled: bool = False


@dataclass(frozen=True)
class Admission:
    activation: Activation
    permit: ApprovedAttempt
    expected_activation_sha256: str
    expected_permit_sha256: str


def activation_digest(value: Activation) -> str:
    return digest(canonical(asdict(value)))


def validate_admission(admission: Admission, config: ProviderConfig, request: Request,
                       start: StartedAttempt, deadline: float) -> None:
    """Pure checks run before any environment access or connector creation."""
    remaining(deadline)
    a, p = admission.activation, admission.permit
    require(a.enabled is True and activation_digest(a) == admission.expected_activation_sha256
            and permit_digest(p) == admission.expected_permit_sha256, "provider_activation_pin_required")
    for value in (a.approval_sha256, a.provider_sha256, a.data_transfer_sha256, a.price_sha256,
                  a.budget_sha256, a.journal_sha256, a.journal_config_sha256,
                  a.model_request_sha256, a.wire_request_sha256):
        require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None,
                "provider_activation_refs_incomplete")
    require((a.provider, a.model, a.model_version, a.endpoint) == (
        "openai-compatible", config.model, config.model_version, ENDPOINT), "provider_activation_identity_mismatch")
    require(type(a.max_output_bytes) is int and 1 <= a.max_output_bytes <= config.max_text_bytes,
            "provider_activation_output_bound")
    try:
        ip = ip_address(a.approved_ip_literal)
    except ValueError:
        raise ValueError("provider_approved_numeric_address_required") from None
    require(str(ip) == a.approved_ip_literal and ip.is_global and not ip.is_multicast
            and not ip.is_unspecified and not ip.is_reserved, "provider_approved_numeric_address_required")
    hashes = dict(start.hashes)
    require(a.journal_sha256 == start.journal_sha256 and p.attempt_id == start.attempt_id
            and p.start_record_sha256 == start.start_record_sha256
            and a.price_sha256 == p.price_sha256 == start.price_sha256
            and a.budget_sha256 == p.budget_sha256 == start.budget_sha256,
            "provider_exact_journal_permit_mismatch")
    require(a.approval_sha256 == p.approval_sha256 and a.provider_sha256 == p.provider_sha256
            and a.data_transfer_sha256 == p.data_transfer_sha256,
            "provider_external_approval_mismatch")
    require(a.model_request_sha256 == p.model_request_sha256 == hashes.get("input") == model_request_digest(request)
            and a.wire_request_sha256 == p.request_sha256 == request_digest(request, config)
            and hashes.get("projection") == p.projection_sha256 == digest(request.payload_json)
            and hashes.get("prompt") == p.prompt_sha256 == digest(request.instruction)
            and hashes.get("config") == a.journal_config_sha256
            and hashes.get("model") == digest(canonical([
                "openai-compatible", config.model, config.model_version, "protocol"]))
            and start.input_tokens_upper == request.input_tokens_upper == p.input_tokens_upper
            and start.output_tokens_upper == request.output_tokens_upper == p.output_tokens_upper,
            "provider_request_journal_binding_mismatch")
    remaining(deadline)
