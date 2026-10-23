"""Disabled Responses wire codec with CLOSED in-memory fake HTTP only.

No socket/HTTP client, credential read, retry or real execution path exists here.
Approval hashes are supplied pins, not authenticated authority or live evidence.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from hashlib import sha256
import json
import math
import re
from time import monotonic

from iac_review.explain import ExplanationCapsule, build_capsule
from iac_review.ingest import decode_source
from eval.model.protocol import ModelOnlyRequest
from eval.model.transport import INSTRUCTIONS, Reply, Request, TransportIdentity, Usage

ENDPOINT = "https://api.openai.com/v1/responses"
CREDENTIAL_ENV_NAME = "OPENAI_API_KEY"  # Name only. No getenv/environ/credential adapter.
MODEL_ENV_NAME = "IAC_REVIEW_MODEL"
_HASH = re.compile(r"[0-9a-f]{64}")
_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}")
_ACTIONS = {("no-op",), ("create",), ("read",), ("update",), ("delete",),
            ("delete", "create"), ("create", "delete"), ("unsupported",)}


def _json(value) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _hash(value: str | bytes) -> str:
    return sha256(value.encode("utf-8") if isinstance(value, str) else value).hexdigest()


def _require(value: bool, code: str) -> None:
    if not value:
        raise ValueError(code)


@dataclass(frozen=True)
class ProviderConfig:
    model: str
    model_version: str
    endpoint: str = ENDPOINT
    credential_env_name: str = CREDENTIAL_ENV_NAME
    max_request_bytes: int = 262_144
    max_response_bytes: int = 262_144
    max_text_bytes: int = 16_384
    max_timeout_seconds: float = 30.0


@dataclass(frozen=True)
class ApprovedAttempt:
    """Explicit external-controller pins for ONE fake exchange, never real authority."""

    attempt_id: str
    provider: str
    model: str
    model_version: str
    endpoint: str
    approval_sha256: str
    provider_sha256: str
    price_sha256: str
    budget_sha256: str
    data_transfer_sha256: str
    start_record_sha256: str
    projection_sha256: str
    prompt_sha256: str
    request_sha256: str
    input_tokens_upper: int
    output_tokens_upper: int
    # Exact existing journal hashes["input"], separate from wire/config digest.
    model_request_sha256: str = ""


def permit_digest(permit: ApprovedAttempt) -> str:
    return _hash(_json(asdict(permit)))


def request_digest(request: Request, config: ProviderConfig) -> str:
    """Wire/config permit digest; NOT journal input hash and never raw plan identity."""
    return _hash(_json({"arm": request.arm, "projection": _hash(request.payload_json),
        "prompt": _hash(request.instruction), "input_tokens_upper": request.input_tokens_upper,
        "output_tokens_upper": request.output_tokens_upper, "timeout_seconds": request.timeout_seconds,
        "config": asdict(config)}))


def model_request_digest(request: Request) -> str:
    """Exact producer canonical {arm,instruction,payload}; preserves journal semantics."""
    return _hash(_json({"arm": request.arm, "instruction": request.instruction,
                        "payload": request.payload_json}))


@dataclass(frozen=True)
class FakeHttpRequest:
    url: str
    body: bytes = field(repr=False)
    timeout_seconds: float
    max_response_bytes: int
    headers: tuple[tuple[str, str], ...] = (("Content-Type", "application/json"),)
    follow_redirects: bool = False


@dataclass(frozen=True)
class FakeHttpResponse:
    status_code: int
    body: bytes = field(repr=False)
    url: str = ENDPOINT
    content_type: str = "application/json"
    elapsed_seconds: float = 0.0


class FakeHttp:
    """An in-memory fixture, not a wrapper around any network library."""

    def __init__(self, responses: tuple[FakeHttpResponse | Exception, ...]) -> None:
        self.responses = responses
        self.requests: list[FakeHttpRequest] = []

    def post(self, request: FakeHttpRequest) -> FakeHttpResponse:
        index = len(self.requests)
        self.requests.append(request)
        if index >= len(self.responses):
            raise ValueError("fake_http_fixture_exhausted")
        response = self.responses[index]
        if isinstance(response, Exception):
            raise response
        return response


def _safe_projection(request: Request) -> None:
    """Independently reject raw plan/arbitrary prompt/gold/split/scanner injections."""
    _require(request.arm in INSTRUCTIONS and request.instruction == INSTRUCTIONS[request.arm],
             "provider_prompt_not_frozen")
    decode_source(request.payload_json.encode("utf-8"))  # strict keys/nesting/numbers
    if request.arm in ("L", "P"):
        capsule = ExplanationCapsule.model_validate_json(request.payload_json)
        projected = {"projection": "shareable", "evaluations": [{
            "finding_id": capsule.finding_id, "rule_id": capsule.rule_id, "outcome": capsule.outcome,
            "facts": [fact.model_dump(mode="json") for fact in capsule.facts],
            "limitation_ids": list(capsule.required_limitation_ids)}], "limitations": []}
        rebuilt = build_capsule(projected, capsule.finding_id)
        _require(rebuilt == capsule and rebuilt.model_dump_json() == request.payload_json,
                 "provider_capsule_not_safe_canonical")
        return
    model = ModelOnlyRequest.model_validate_json(request.payload_json)
    expected_policy = ModelOnlyRequest(case_id=model.case_id, resources=()).policy
    _require(model.policy == expected_policy and model.model_dump_json() == request.payload_json,
             "provider_M_policy_or_projection_changed")
    seen = set()

    def opaque(value):
        _require(re.fullmatch(r"[0-9a-f]{32}", value) is not None and value not in seen,
                 "provider_M_foreign_or_duplicate_id")
        seen.add(value)

    opaque(model.case_id)
    _require(len(model.resources) <= 10000, "provider_M_resource_limit")
    for resource in model.resources:
        opaque(resource.resource_id)
        _require(resource.actions in _ACTIONS and len(resource.facts) <= 256, "provider_M_action_or_fact_limit")
        slots = set()
        for fact in resource.facts:
            opaque(fact.fact_id)
            _require((fact.side, fact.field) not in slots, "provider_M_duplicate_fact_slot")
            slots.add((fact.side, fact.field))
            value = fact.value
            _require(fact.field != "prior_exists" or fact.side == "before", "provider_M_prior_side_invalid")
            if fact.state != "known":
                _require(value is None or fact.field == "prior_exists" and fact.side == "before"
                         and fact.state in ("null", "absent") and value is False,
                         "provider_M_unavailable_value_disclosed")
            elif fact.field in ("publicly_accessible", "storage_encrypted", "encrypted", "prior_exists"):
                _require(type(value) is bool, "provider_M_boolean_invalid")
            elif fact.field in ("from_port", "to_port"):
                _require(type(value) is int and -1 <= value <= 65535, "provider_M_port_invalid")
            elif fact.field == "type":
                _require(value in ("ingress", "egress"), "provider_M_direction_invalid")
            elif fact.field == "protocol":
                _require(value in ("tcp", "6", "-1", "udp", "17", "icmp", "icmpv6"), "provider_M_protocol_invalid")
            else:
                _require(type(value) is list and all(type(v) is str and v in ("0.0.0.0/0", "::/0") for v in value),
                         "provider_M_CIDR_not_allowlisted")


def _usage(raw) -> Usage:
    if type(raw) is not dict:
        return Usage()
    values = [raw.get("input_tokens"), raw.get("output_tokens")]
    counts = [v if type(v) is int and v >= 0 else None for v in values]
    total = raw.get("total_tokens")
    if all(v is not None for v in counts) and total is not None:
        if type(total) is not int or total != sum(counts):
            return Usage()
    # Token usage is not a billing receipt; never fabricate known USD from counts.
    return Usage(counts[0], counts[1], None)


def _text(raw: dict, cap: int) -> tuple[bytes, bool]:
    output = raw.get("output")
    _require(type(output) is list and len(output) <= 256, "provider_output_array_invalid")
    parts = []
    size = 0
    refused = False
    for item in output:
        _require(type(item) is dict, "provider_output_item_invalid")
        if item.get("type") == "reasoning":
            continue  # Never expose reasoning metadata as an explanation or a tool.
        _require(item.get("type") == "message" and item.get("role") == "assistant"
                 and item.get("status", "completed") in ("completed", "incomplete"),
                 "provider_tool_or_foreign_output")
        content = item.get("content")
        _require(type(content) is list and len(content) <= 256, "provider_content_array_invalid")
        for part in content:
            _require(type(part) is dict and part.get("type") in ("output_text", "refusal"),
                     "provider_content_type_unsupported")
            refusal = part["type"] == "refusal"
            value = part.get("refusal" if refusal else "text")
            _require(type(value) is str, "provider_text_invalid")
            data = value.encode("utf-8", errors="strict")
            size += len(data)
            _require(size <= cap, "provider_text_byte_limit")
            parts.append(data)
            refused |= refusal
    return b"".join(parts), refused


class ResponsesWire:
    """Callable codec, disabled by default; only exact FakeHttp is accepted.

    A future real connector needs a new authorized implementation, real credential
    control, hard I/O enforcement and independent live provenance. Pins are not
    proof that approval/start/budget receipts are authentic.
    """

    def __init__(self, config: ProviderConfig, http: FakeHttp, *, enabled: bool = False,
                 permit: ApprovedAttempt | None = None, expected_permit_sha256: str | None = None) -> None:
        self.config, self.http = config, http
        self.enabled, self.permit, self.expected_permit_sha256 = enabled, permit, expected_permit_sha256
        self.identity = TransportIdentity("openai-compatible", config.model, config.model_version, "protocol")
        self._used: set[str] = set()
        self.receipts: list[dict] = []  # Hashes/status only, no prompt/response/credential text.

    def prepare(self, request: Request) -> FakeHttpRequest:
        _require(self.enabled is True, "provider_wire_disabled")
        _require(type(self.http) is FakeHttp, "real_http_unimplemented")
        config, permit = self.config, self.permit
        _require(config.endpoint == ENDPOINT and config.credential_env_name == CREDENTIAL_ENV_NAME,
                 "provider_endpoint_or_credential_name_not_fixed")
        _require(type(config.model) is str and type(config.model_version) is str
                 and _LABEL.fullmatch(config.model) is not None and _LABEL.fullmatch(config.model_version) is not None,
                 "provider_exact_model_pin_required")
        _require(all(type(v) is int and 1 <= v <= 1024 * 1024 for v in (
            config.max_request_bytes, config.max_response_bytes, config.max_text_bytes))
            and config.max_text_bytes <= 65536
            and type(config.max_timeout_seconds) in (int, float) and math.isfinite(config.max_timeout_seconds)
            and 0 < config.max_timeout_seconds <= 60, "provider_config_bounds_invalid")
        _require(type(request.input_tokens_upper) is int and request.input_tokens_upper > 0
                 and type(request.output_tokens_upper) is int and request.output_tokens_upper >= 16
                 and type(request.timeout_seconds) in (int, float) and math.isfinite(request.timeout_seconds)
                 and 0 < request.timeout_seconds <= config.max_timeout_seconds
                 and len(request.payload_json.encode("utf-8")) <= 65536, "provider_request_bounds_invalid")
        _require(permit is not None and permit_digest(permit) == self.expected_permit_sha256,
                 "provider_explicit_permit_pin_required")
        _require(type(permit.attempt_id) is str and re.fullmatch(r"[0-9a-f]{32}", permit.attempt_id) is not None
                 and permit.attempt_id not in self._used, "provider_attempt_permit_used_or_invalid")
        for value in (permit.approval_sha256, permit.provider_sha256, permit.price_sha256,
                      permit.budget_sha256, permit.data_transfer_sha256, permit.start_record_sha256,
                      permit.model_request_sha256):
            _require(type(value) is str and _HASH.fullmatch(value) is not None, "provider_approval_refs_incomplete")
        _require((permit.provider, permit.model, permit.model_version, permit.endpoint) == (
            self.identity.provider, config.model, config.model_version, ENDPOINT)
            and permit.projection_sha256 == _hash(request.payload_json)
            and permit.prompt_sha256 == _hash(request.instruction)
            and permit.request_sha256 == request_digest(request, config)
            and permit.model_request_sha256 == model_request_digest(request)
            and permit.input_tokens_upper == request.input_tokens_upper
            and permit.output_tokens_upper == request.output_tokens_upper, "provider_permit_request_mismatch")
        _safe_projection(request)
        body = _json({"model": config.model, "instructions": request.instruction,
            "input": request.payload_json, "max_output_tokens": request.output_tokens_upper,
            "store": False, "stream": False, "tools": [], "tool_choice": "none",
            "parallel_tool_calls": False}).encode("utf-8")
        _require(len(body) <= config.max_request_bytes, "provider_http_request_byte_limit")
        return FakeHttpRequest(ENDPOINT, body, request.timeout_seconds, config.max_response_bytes)

    def complete(self, request: Request) -> Reply:
        wire = self.prepare(request)  # No HTTP on disabled/missing/changed approval.
        permit = self.permit
        self._used.add(permit.attempt_id)  # One exchange; failures do not create a retry grant.
        started = monotonic()
        usage = Usage()
        status, payload, http_status, response_hash = "error", b"", None, None
        raw_body = b""
        payload_kind = "no_response"
        response_limit_exceeded = False
        provider_state = None
        try:
            response = self.http.post(wire)
            http_status = response.status_code
            _require(response.url == ENDPOINT and type(response.content_type) is str
                     and response.content_type.split(";", 1)[0].strip().lower()
                     == "application/json", "provider_redirect_or_content_type_rejected")
            response_limit_exceeded = type(response.body) is bytes and len(response.body) > wire.max_response_bytes
            _require(type(response.body) is bytes and not response_limit_exceeded, "provider_http_response_byte_limit")
            raw_body = response.body
            response_hash = _hash(response.body)
            raw = decode_source(response.body)
            _require(type(raw) is dict, "provider_response_object_required")
            usage = _usage(raw.get("usage"))
            _require(usage.input_tokens is None or usage.input_tokens <= request.input_tokens_upper,
                     "provider_reported_input_overrun")
            _require(usage.output_tokens is None or usage.output_tokens <= request.output_tokens_upper,
                     "provider_reported_output_overrun")
            if type(http_status) is not int or http_status != 200:
                payload = response.body
                payload_kind = "http_error_envelope"
                status = "error"
            else:
                _require(raw.get("model") == self.config.model, "provider_response_model_changed")
                provider_state = raw.get("status")
                payload, refused = _text(raw, self.config.max_text_bytes)
                payload_kind = "model_text"
                state = provider_state
                status = "ok" if state == "completed" and raw.get("error") is None and payload and not refused else "invalid"
                if state == "failed":
                    status = "error"
                elif state == "cancelled":
                    status = "cancelled"
            _require(type(response.elapsed_seconds) in (int, float)
                     and math.isfinite(response.elapsed_seconds) and response.elapsed_seconds >= 0,
                     "provider_elapsed_invalid")
            if max(response.elapsed_seconds, monotonic() - started) > wire.timeout_seconds:
                status = "timeout"
        except TimeoutError:
            status = "timeout"
        except (ValueError, TypeError, KeyError, UnicodeError, OSError):
            status = "invalid" if http_status == 200 else "error"
            if provider_state in ("failed", "cancelled"):
                status = "error" if provider_state == "failed" else "cancelled"
            # Keep the whole bounded malformed envelope; the experiment layer
            # explicitly marks/truncates oversized returned payloads, never hides
            # an unannounced prefix as an exact generated explanation.
            payload = raw_body
            payload_kind = "invalid_http_envelope" if raw_body else "no_response"
        self.receipts.append({"attempt_id": permit.attempt_id, "permit_sha256": self.expected_permit_sha256,
            "model_request_sha256": permit.model_request_sha256,
            "wire_request_sha256": permit.request_sha256, "raw_source_sha256": None,
            "http_status": http_status, "http_response_sha256": response_hash,
            "returned_payload_sha256": _hash(payload), "payload_kind": payload_kind,
            "response_limit_exceeded": response_limit_exceeded, "status": status,
            "fake_http": True, "live_eligible": False, "billing_authenticated": False})
        return Reply(status, payload, usage)
