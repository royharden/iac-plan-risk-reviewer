"""Journal/approval boundary regression SOURCE; Dirty Mode does not execute it."""
from dataclasses import replace
from decimal import Decimal
import json
from time import monotonic

import pytest

from iac_review.attempts import AttemptJournal, Budget, PriceIdentity, Reservation
from iac_review.explain import build_capsule
from eval.model.experiment import canonical, digest
from eval.model.provider_activation import (
    Activation, Admission, activation_digest, started_attempt, validate_admission,
)
from eval.model.provider_http import HttpFailure, ProviderTransport
from eval.model.provider_wire import (
    ENDPOINT, ApprovedAttempt, FakeHttpResponse, ProviderConfig, model_request_digest,
    permit_digest, request_digest,
)
from eval.model.transport import INSTRUCTIONS, Request


def request_fixture():
    capsule = build_capsule({"projection": "shareable", "evaluations": [{
        "finding_id": "1" * 32, "rule_id": "R2", "outcome": "introduced_risk", "facts": [
            {"fact_id": "2" * 32, "field": "publicly_accessible", "side": "after",
             "role": "decision", "state": "known", "value": True}], "limitation_ids": [],
    }], "limitations": []}, "1" * 32)
    return Request("P", capsule.model_dump_json(), INSTRUCTIONS["P"], 1000, 128, 1.0)


def admission_fixture(request, start, config):
    a = Activation("openai-compatible", config.model, config.model_version,
        "a" * 64, "b" * 64, "c" * 64, start.price_sha256, start.budget_sha256,
        start.journal_sha256, dict(start.hashes)["config"], model_request_digest(request),
        request_digest(request, config), "8.8.8.8", 16384, enabled=True)
    p = ApprovedAttempt(start.attempt_id, a.provider, a.model, a.model_version, ENDPOINT,
        a.approval_sha256, a.provider_sha256, a.price_sha256, a.budget_sha256,
        a.data_transfer_sha256, start.start_record_sha256, digest(request.payload_json),
        digest(request.instruction), a.wire_request_sha256, request.input_tokens_upper,
        request.output_tokens_upper, a.model_request_sha256)
    return Admission(a, p, activation_digest(a), permit_digest(p))


@pytest.fixture
def active(tmp_path):
    request = request_fixture()
    config = ProviderConfig("synthetic-model", "synthetic-version")
    price = PriceIdentity(provider="openai-compatible", model=config.model, price_id="synthetic-price",
        price_date="2026-10-23", input_usd_per_million=Decimal(1), output_usd_per_million=Decimal(2))
    budget = Budget(max_requests=5, max_input_tokens=10000, max_output_tokens=10000, max_usd=Decimal(1))
    with AttemptJournal(tmp_path / "attempts.jsonl", budget, price) as journal:
        hashes = {"build": "1" * 64, "corpus": "2" * 64, "config": "3" * 64,
            "input": model_request_digest(request), "projection": digest(request.payload_json),
            "prompt": digest(request.instruction), "model": digest(canonical([
                "openai-compatible", config.model, config.model_version, "protocol"]))}
        attempt_id = journal.start(Reservation(input_tokens_upper=1000, output_tokens_upper=128,
            request_usd_upper=Decimal("0.001256"), hashes=hashes))
        yield journal, attempt_id, request, config


def test_constructor_and_disabled_call_never_read_keys_or_make_connector(active):
    """Catches default construction/access before external and journal admission."""
    journal, attempt_id, request, config = active
    effects = []
    transport = ProviderTransport(config, key_reader=lambda name: effects.append(name),
        connector_factory=lambda: effects.append("connector"))
    assert effects == []
    with pytest.raises(ValueError, match="disabled"):
        transport.complete_started(request, journal=journal, attempt_id=attempt_id,
            deadline_monotonic=monotonic() + 1)
    with pytest.raises(ValueError, match="started_journal"):
        transport.complete(request)
    assert effects == []


@pytest.mark.parametrize("change", ["pin", "disabled", "raw-as-request", "price", "journal", "config", "ip"])
def test_activation_mismatches_refuse_before_effects(active, change):
    """Catches re-pinned/raw-substituted or unapproved requests reaching credentials."""
    journal, attempt_id, request, config = active
    start = started_attempt(journal, attempt_id)
    admission = admission_fixture(request, start, config)
    values = {"disabled": {"enabled": False}, "raw-as-request": {"model_request_sha256": "9" * 64},
        "price": {"price_sha256": "9" * 64}, "journal": {"journal_sha256": "9" * 64},
        "config": {"journal_config_sha256": "9" * 64}, "ip": {"approved_ip_literal": "127.0.0.1"}}
    if change == "pin":
        admission = replace(admission, expected_activation_sha256="0" * 64)
    else:
        a = replace(admission.activation, **values[change])
        admission = replace(admission, activation=a, expected_activation_sha256=activation_digest(a))
    effects = []
    transport = ProviderTransport(config, enabled=True, controller=lambda *args: admission,
        key_reader=lambda name: effects.append(name), connector_factory=lambda: effects.append("connector"))
    with pytest.raises(ValueError):
        transport.complete_started(request, journal=journal, attempt_id=attempt_id,
            deadline_monotonic=monotonic() + 1)
    assert effects == []


def test_terminal_or_different_start_cannot_be_replayed(active):
    """Catches reuse of an already terminal journal reservation."""
    journal, attempt_id, request, config = active
    journal.terminal(attempt_id, "timeout", 1, input_tokens=1, output_tokens=1, known_usd=Decimal(0))
    with pytest.raises(ValueError, match="final_start"):
        started_attempt(journal, attempt_id)
    assert journal.summary()["pending_attempt_ids"]  # Timeout remains pending even with known billing.


def test_fake_connector_preserves_usage_unknown_dollars_and_one_exchange(active):
    """Catches missing journal linkage, duplicate I/O or fake evidence promotion."""
    journal, attempt_id, request, config = active
    effects = []
    class FakeConnector:
        def exchange(self, wire, key, ip, deadline):
            effects.append(("exchange", wire.url, ip))
            data = {"model": config.model, "status": "completed", "output": [{"type": "message",
                "role": "assistant", "content": [{"type": "output_text", "text": '{"claims":["synthetic"]}'}]}],
                "usage": {"input_tokens": 12, "output_tokens": 4, "total_tokens": 16}}
            return FakeHttpResponse(200, json.dumps(data).encode())
    transport = ProviderTransport(config, enabled=True, controller=admission_fixture,
        connector_factory=lambda: FakeConnector(), key_reader=lambda name: "synthetic-not-a-real-key")
    reply = transport.complete_started(request, journal=journal, attempt_id=attempt_id,
        deadline_monotonic=monotonic() + 1)
    assert reply.status == "ok" and reply.usage.input_tokens == 12 and reply.usage.known_usd is None
    assert len(effects) == 1 and reply.payload_complete
    assert transport.receipts[0]["live_eligible"] is False
    assert "synthetic-not-a-real-key" not in json.dumps(transport.receipts)
    with pytest.raises(ValueError, match="already_used"):
        transport.complete_started(request, journal=journal, attempt_id=attempt_id,
            deadline_monotonic=monotonic() + 1)
    assert len(effects) == 1


def test_partial_timeout_is_explicit_and_does_not_invent_accounting(active):
    """Catches partial generated bytes being advertised as a complete private artifact."""
    journal, attempt_id, request, config = active
    class FakeConnector:
        def exchange(self, *args):
            raise HttpFailure("timeout", b'{"unfinished":', 200)
    transport = ProviderTransport(config, enabled=True, controller=admission_fixture,
        connector_factory=FakeConnector, key_reader=lambda name: "synthetic-not-a-real-key")
    reply = transport.complete_started(request, journal=journal, attempt_id=attempt_id,
        deadline_monotonic=monotonic() + 1)
    assert reply.status == "timeout" and reply.payload == b'{"unfinished":'
    assert reply.payload_complete is False and reply.usage.known_usd is None


def test_expired_whole_attempt_deadline_prevents_controller_and_keys(active):
    journal, attempt_id, request, config = active
    effects = []
    transport = ProviderTransport(config, enabled=True, controller=lambda *args: effects.append("controller"),
        key_reader=lambda name: effects.append("key"))
    with pytest.raises(TimeoutError):
        transport.complete_started(request, journal=journal, attempt_id=attempt_id,
            deadline_monotonic=monotonic() - 1)
    assert effects == []
