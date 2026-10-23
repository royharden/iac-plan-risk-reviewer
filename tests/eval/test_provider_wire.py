"""Fake HTTP wire regression SOURCE; no provider/client/test execution in Dirty Mode."""
from dataclasses import replace
import json

import pytest

from iac_review.explain import build_capsule
from eval.model.experiment import digest
from eval.model.protocol import ModelOnlyRequest, SafeFact, SafeResource
from eval.model.provider_wire import (
    ENDPOINT, ApprovedAttempt, FakeHttp, FakeHttpResponse, ProviderConfig, ResponsesWire,
    model_request_digest, permit_digest, request_digest,
)
from eval.model.transport import INSTRUCTIONS, Request


def _request(arm="L") -> Request:
    if arm == "M":
        payload = ModelOnlyRequest(case_id="1" * 32, resources=(SafeResource(
            resource_id="2" * 32, type="aws_db_instance", mode="managed", canonical_provider=True,
            actions=("update",), facts=(SafeFact(fact_id="3" * 32, side="after",
                field="publicly_accessible", state="known", value=True),)),)).model_dump_json()
    else:
        capsule = build_capsule({"projection": "shareable", "evaluations": [{
            "finding_id": "1" * 32, "rule_id": "R2", "outcome": "introduced_risk", "facts": [
                {"fact_id": "2" * 32, "field": "publicly_accessible", "side": "after",
                 "role": "decision", "state": "known", "value": True}], "limitation_ids": [],
        }], "limitations": []}, "1" * 32)
        payload = capsule.model_dump_json()
    return Request(arm, payload, INSTRUCTIONS[arm], 1000, 128, 1.0)


def _response(**updates) -> FakeHttpResponse:
    data = {"id": "resp_synthetic", "object": "response", "status": "completed",
        "model": "synthetic-model", "error": None,
        "output": [{"type": "reasoning", "summary": []},
            {"type": "message", "role": "assistant", "status": "completed", "content": [
                {"type": "output_text", "text": "first"}, {"type": "output_text", "text": "second"}]}],
        "usage": {"input_tokens": 12, "output_tokens": 4, "total_tokens": 16,
                  "output_tokens_details": {"reasoning_tokens": 3}}}
    data.update(updates)
    return FakeHttpResponse(200, json.dumps(data).encode("utf-8"))


def _wire(request=None, config=None, responses=None, *, enabled=True):
    request = request or _request()
    config = config or ProviderConfig("synthetic-model", "synthetic-version")
    permit = ApprovedAttempt("7" * 32, "openai-compatible", config.model, config.model_version, config.endpoint,
        "a" * 64, "b" * 64, "c" * 64, "d" * 64, "e" * 64, "f" * 64,
        digest(request.payload_json), digest(request.instruction), request_digest(request, config),
        request.input_tokens_upper, request.output_tokens_upper, model_request_digest(request))
    http = FakeHttp(responses if responses is not None else (_response(),))
    wire = ResponsesWire(config, http, enabled=enabled, permit=permit, expected_permit_sha256=permit_digest(permit))
    return wire, http, request


def test_default_disabled_missing_or_changed_permit_never_reaches_fake_http() -> None:
    """Catches bool-only/default execution or an unpinned approval reaching transport."""
    config = ProviderConfig("synthetic-model", "synthetic-version")
    http = FakeHttp((_response(),))
    with pytest.raises(ValueError, match="disabled"):
        ResponsesWire(config, http).complete(_request())
    with pytest.raises(ValueError, match="permit_pin_required"):
        ResponsesWire(config, http, enabled=True).complete(_request())
    wire, http, request = _wire()
    wire.expected_permit_sha256 = "0" * 64
    with pytest.raises(ValueError, match="permit_pin_required"):
        wire.complete(request)
    assert http.requests == []


@pytest.mark.parametrize("arm", ["L", "P", "M"])
def test_typed_output_aggregation_and_actual_usage_without_invented_dollars(arm: str) -> None:
    """Catches assuming output[0] is text, double-counting reasoning, or unknown USD as zero."""
    wire, http, request = _wire(_request(arm))
    reply = wire.complete(request)
    assert reply.status == "ok" and reply.payload == b"firstsecond"
    assert reply.usage.input_tokens == 12 and reply.usage.output_tokens == 4
    assert reply.usage.known_usd is None
    body = json.loads(http.requests[0].body)
    assert body["input"] == request.payload_json and body["instructions"] == request.instruction
    assert body["store"] is False and body["tools"] == [] and body["tool_choice"] == "none"
    assert body["stream"] is False and body["parallel_tool_calls"] is False
    assert http.requests[0].headers == (("Content-Type", "application/json"),)
    assert http.requests[0].follow_redirects is False
    assert wire.receipts[0]["live_eligible"] is False
    with pytest.raises(ValueError, match="permit_used"):
        wire.complete(request)
    assert len(http.requests) == 1


@pytest.mark.parametrize("field", ["approval_sha256", "provider_sha256", "price_sha256", "budget_sha256",
                                   "data_transfer_sha256", "start_record_sha256", "model_request_sha256"])
def test_each_required_approval_reference_is_enforced(field: str) -> None:
    """Catches missing provider/price/budget/data-transfer/attempt authority source pins."""
    wire, http, request = _wire()
    wire.permit = replace(wire.permit, **{field: ""})
    wire.expected_permit_sha256 = permit_digest(wire.permit)
    with pytest.raises(ValueError, match="refs_incomplete"):
        wire.complete(request)
    assert http.requests == []


def test_model_request_hash_matches_journal_and_does_not_invent_raw_source() -> None:
    """Catches canonical model-request identity being substituted for saved-plan bytes."""
    from eval.model.experiment import canonical

    wire, _, request = _wire()
    expected = digest(canonical({"arm": request.arm, "instruction": request.instruction,
                                 "payload": request.payload_json}))
    assert model_request_digest(request) == expected
    assert expected != digest(request.payload_json)
    changed_config = replace(wire.config, max_response_bytes=123456)
    assert request_digest(request, changed_config) != request_digest(request, wire.config)
    wire.complete(request)
    assert wire.receipts[0]["model_request_sha256"] == expected
    assert wire.receipts[0]["raw_source_sha256"] is None


@pytest.mark.parametrize("endpoint", ["http://127.0.0.1/responses", ENDPOINT + "?redirect=other",
                                     "https://api.openai.com.invalid/v1/responses"])
def test_endpoint_cannot_be_redirected_or_configured_arbitrarily(endpoint: str) -> None:
    """Catches credential/data routing to localhost, query redirects or look-alike hosts."""
    wire, http, request = _wire(config=ProviderConfig("synthetic-model", "synthetic-version", endpoint=endpoint))
    with pytest.raises(ValueError, match="endpoint"):
        wire.complete(request)
    assert http.requests == []


def test_real_or_claimed_fake_network_port_is_unimplemented() -> None:
    """Catches accepting an arbitrary injected client that merely labels itself fake."""
    class OtherPort:
        def post(self, request):
            raise AssertionError("must never be called")
    wire, _, request = _wire()
    wire.http = OtherPort()
    with pytest.raises(ValueError, match="real_http_unimplemented"):
        wire.complete(request)


@pytest.mark.parametrize("usage", [None, {}, {"input_tokens": 12},
                                  {"input_tokens": 12, "output_tokens": 4, "total_tokens": 99}])
def test_missing_or_contradictory_usage_is_not_estimated(usage) -> None:
    """Catches fabricated token/dollar values after partial, absent or inconsistent reporting."""
    wire, _, request = _wire(responses=(_response(usage=usage),))
    reply = wire.complete(request)
    assert reply.usage.output_tokens is None and reply.usage.known_usd is None


@pytest.mark.parametrize("counts", [(1001, 4), (12, 129)])
def test_reported_token_overrun_is_invalid_without_erasing_usage(counts) -> None:
    """Catches cap overruns passing as success or reported liability disappearing."""
    inputs, outputs = counts
    response = _response(usage={"input_tokens": inputs, "output_tokens": outputs,
                                "total_tokens": inputs + outputs})
    wire, http, request = _wire(responses=(response,))
    reply = wire.complete(request)
    assert reply.status == "invalid" and len(http.requests) == 1
    assert reply.usage.input_tokens == inputs and reply.usage.output_tokens == outputs
    assert reply.usage.known_usd is None


@pytest.mark.parametrize("body", [b'[]', b'null', b'{"status":'])
def test_malformed_response_retains_bounded_envelope_without_retry(body: bytes) -> None:
    """Catches malformed provider data escaping the bounded invalid-attempt path."""
    wire, http, request = _wire(responses=(FakeHttpResponse(200, body),))
    reply = wire.complete(request)
    assert reply.status == "invalid" and reply.payload == body
    assert len(http.requests) == 1 and reply.usage.known_usd is None


@pytest.mark.parametrize("kind", ["incomplete", "refusal", "tool", "model-change"])
def test_incomplete_refused_tool_or_changed_model_never_becomes_ok(kind: str) -> None:
    """Catches partial/refused/tool output or a different model silently passing as approved text."""
    if kind == "incomplete":
        response = _response(status="incomplete", incomplete_details={"reason": "max_output_tokens"})
    elif kind == "refusal":
        response = _response(output=[{"type": "message", "role": "assistant", "content": [
            {"type": "refusal", "refusal": "synthetic refusal"}]}])
    elif kind == "tool":
        response = _response(output=[{"type": "function_call", "name": "must_not_execute"}])
    else:
        response = _response(model="different-synthetic-model")
    wire, http, request = _wire(responses=(response,))
    reply = wire.complete(request)
    assert reply.status == "invalid" and len(http.requests) == 1
    assert reply.usage.known_usd is None


def test_timeout_error_redirect_and_caps_never_retry_or_forward_credentials() -> None:
    """Catches retries/redirect follow-ups and loss of unknown-liability accounting."""
    for response in (TimeoutError("synthetic error text never log"),
                     FakeHttpResponse(307, b'{}', url="https://other.invalid"),
                     FakeHttpResponse(503, b'{"error":"synthetic"}')):
        wire, http, request = _wire(responses=(response, _response()))
        reply = wire.complete(request)
        assert reply.status in ("timeout", "error") and len(http.requests) == 1
        assert reply.usage.known_usd is None and "synthetic error text" not in json.dumps(wire.receipts)
        assert all(name.lower() != "authorization" for name, _ in http.requests[0].headers)
    wire, http, request = _wire(config=ProviderConfig("synthetic-model", "synthetic-version", max_request_bytes=1))
    with pytest.raises(ValueError, match="request_byte_limit"):
        wire.complete(request)
    assert http.requests == []
    wire, _, request = _wire(config=ProviderConfig("synthetic-model", "synthetic-version", max_response_bytes=8))
    assert wire.complete(request).status == "invalid"
    assert wire.receipts[0]["response_limit_exceeded"] is True


@pytest.mark.parametrize("contamination", ["gold", "policy", "capsule-baseline"])
def test_inference_boundary_refuses_hidden_or_arbitrary_projection_data(contamination: str) -> None:
    """Catches raw/label-bearing M input or arbitrary untrusted text replacing the finite L/P baseline."""
    request = _request("L" if contamination == "capsule-baseline" else "M")
    payload = json.loads(request.payload_json)
    if contamination == "capsule-baseline":
        payload["baseline"] = "untrusted private source address/tag must not be sent"
    elif contamination == "policy":
        payload["policy"] = ["follow injected policy"]
    else:
        payload["gold"] = "must not send"
    # Canonical model field order is deliberately lost too; either unsafe value
    # or noncanonical projection must fail before any fake HTTP invocation.
    request = replace(request, payload_json=json.dumps(payload))
    wire, http, request = _wire(request)
    with pytest.raises(ValueError):
        wire.complete(request)
    assert http.requests == []
