"""Finite adapter regression SOURCE. Nothing here has run in Dirty Mode."""
from dataclasses import asdict, replace
from decimal import Decimal
import json

import pytest

from iac_review.attempts import AttemptJournal, Budget, PriceIdentity
from iac_review.explain import build_capsule, validate_selection
from eval.model.experiment import Context, Limits, canonical, digest
from eval.model.selector_adapter import AdmittedSelector, binding_digest, make_binding
from eval.model.transport import FakeTransport, Reply, Usage
from eval.runner.scoring import ArmRow


def projection_fixture():
    shareable = {"projection": "shareable", "case_id": "1" * 32,
        "summary": {"needs_review": True, "severity": "high", "coverage": "limited"},
        "limitations": [{"id": "coverage_gap"}], "evaluations": [{
            "finding_id": "2" * 32, "resource_id": "6" * 32, "rule_id": "R2",
            "outcome": "introduced_risk", "applicability": "supported", "limitation_ids": [],
            "facts": [
                {"fact_id": "3" * 32, "field": "publicly_accessible", "side": "before",
                 "role": "decision", "state": "known", "value": False},
                {"fact_id": "4" * 32, "field": "publicly_accessible", "side": "after",
                 "role": "decision", "state": "known", "value": True},
                {"fact_id": "5" * 32, "field": "actions", "side": "actions",
                 "role": "supporting", "state": "known", "value": ["update"]}]}]}
    context = Context("a" * 64, "b" * 64, "c" * 64, "d" * 64)
    baseline = ArmRow(case_id="1" * 32, resource_id="6" * 32, rule_id="R2", arm="D", status="ok",
        applicability="supported", outcome="introduced_risk", reason_code="synthetic-test",
        decision_fact_ids=("3" * 32, "4" * 32), required_limitation_ids=("coverage_gap",),
        source_sha256=context.source_sha256, build_sha256=context.build_sha256,
        measurement_ref="sha256:" + "e" * 64)
    return shareable, context, baseline


def binding_fixture(shareable, context, baseline):
    return make_binding(shareable=shareable, finding_id="2" * 32, baseline=baseline, context=context,
        expected_shareable_sha256=digest(canonical(shareable)),
        expected_baseline_sha256=digest(canonical(baseline.model_dump(mode="json"))), authority_sha256="f" * 64)


class RecordingFake(FakeTransport):
    def __init__(self, reply=None):
        super().__init__(reply)
        self.requests = []
    def complete(self, request):
        self.requests.append(request)
        return super().complete(request)


@pytest.fixture
def configured(tmp_path):
    shareable, context, baseline = projection_fixture()
    binding = binding_fixture(shareable, context, baseline)
    budget = Budget(max_requests=10, max_input_tokens=100000, max_output_tokens=10000, max_usd=Decimal(1))
    price = PriceIdentity(provider="mock", model="finite-fake", price_id="synthetic-nonzero",
        price_date="2026-10-23", input_usd_per_million=Decimal(1), output_usd_per_million=Decimal(2))
    with AttemptJournal(tmp_path / "attempts.jsonl", budget, price) as journal:
        transport = RecordingFake()
        adapter = AdmittedSelector(enabled=True, binding=binding, expected_binding_sha256=binding_digest(binding),
            transport=transport, journal=journal,
            limits=Limits(input_tokens_upper=1000, output_tokens_upper=128, max_attempts=1))
        yield adapter, transport, journal, shareable, baseline


def test_default_disabled_returns_exact_core_fallback_without_attempt(configured):
    adapter, transport, journal, shareable, _ = configured
    capsule = build_capsule(shareable, "2" * 32)
    disabled = AdmittedSelector()
    response = disabled.select(capsule)
    result = validate_selection(capsule, response)
    assert result.accepted is False and result.text == capsule.baseline
    assert result.limitation_ids == capsule.required_limitation_ids
    assert disabled.receipts == () and transport.requests == [] and journal.summary()["requests"] == 0


def test_success_is_one_L_only_and_returns_finite_wire(configured):
    adapter, transport, journal, shareable, baseline = configured
    before = canonical(shareable), baseline.model_dump_json()
    capsule = build_capsule(shareable, "2" * 32)
    selected = validate_selection(capsule, adapter.select(capsule))
    assert selected.accepted and selected.limitation_ids == capsule.required_limitation_ids
    assert [r.arm for r in transport.requests] == ["L"]
    assert journal.summary()["requests"] == 1 and len(adapter.receipts) == 1
    assert adapter.receipts[0].attempt.live_eligible is False
    assert before == (canonical(shareable), baseline.model_dump_json())
    payload = json.loads(transport.requests[0].payload_json)
    assert set(payload) == {"finding_id", "rule_id", "outcome", "facts", "required_fact_ids",
                            "required_limitation_ids", "baseline"}
    assert not {"gold", "split", "scanner", "source_sha256", "authority_sha256"} & payload.keys()


@pytest.mark.parametrize("change", ["baseline", "mutable-list", "finding", "required-ids", "limitation", "pin", "authority"])
def test_changed_or_unsafe_nested_capsule_is_denied_without_start(configured, change):
    adapter, transport, journal, shareable, _ = configured
    capsule = build_capsule(shareable, "2" * 32)
    if change == "baseline":
        capsule = capsule.model_copy(update={"baseline": "private-address-tag-canary"})
    elif change == "mutable-list":
        capsule.facts[-1].value.append("private-address-tag-canary")
    elif change == "finding":
        capsule = capsule.model_copy(update={"finding_id": "9" * 32})
    elif change == "required-ids":
        capsule = capsule.model_copy(update={"required_fact_ids": tuple(reversed(capsule.required_fact_ids))})
    elif change == "limitation":
        capsule = capsule.model_copy(update={"required_limitation_ids": ()})
    elif change == "authority":
        adapter.binding = replace(adapter.binding, authority_sha256="")
        adapter.expected_binding_sha256 = binding_digest(adapter.binding)
    else:
        adapter.expected_binding_sha256 = "0" * 64
    assert adapter.select(capsule).clauses == ()
    assert adapter.receipts == () and transport.requests == [] and journal.summary()["requests"] == 0
    assert "private-address-tag-canary" not in json.dumps([asdict(r) for r in adapter.receipts])


@pytest.mark.parametrize("kind", ["free-text", "missing-fact", "reversed", "malformed", "partial", "output-cap"])
def test_invalid_selection_keeps_failed_charge_and_exact_core_fallback(configured, kind):
    adapter, transport, journal, shareable, _ = configured
    capsule = build_capsule(shareable, "2" * 32)
    selected = {"clauses": [{"template_id": "outcome"}], "limitation_ids": ["coverage_gap"]}
    if kind == "free-text":
        selected["claims"] = ["private-response-canary"]
    elif kind == "reversed":
        selected["clauses"].append({"template_id": "boolean_transition", "fact_ids": ["4" * 32, "3" * 32]})
    payload = b"{not json" if kind == "malformed" else json.dumps(selected).encode()
    reply = Reply("ok", payload, Usage(12, 4, Decimal("0.0001")))
    if kind == "partial":
        from eval.model.provider_http import ProviderReply
        reply = ProviderReply(reply.status, reply.payload, reply.usage, False)
    elif kind == "output-cap":
        adapter.limits = replace(adapter.limits, max_output_bytes=8)
    transport._reply = reply
    rendered = validate_selection(capsule, adapter.select(capsule))
    assert not rendered.accepted and rendered.text == capsule.baseline
    assert journal.summary()["known_usd"] == "0.0001"
    assert adapter.receipts[0].attempt.status == "invalid"
    assert adapter.receipts[0].attempt.known_usd == "0.0001"
    assert len(transport.requests) == 1 and transport.requests[0].arm == "L"
    assert "private-response-canary" not in json.dumps([asdict(r) for r in adapter.receipts])


@pytest.mark.parametrize("status", ["timeout", "error", "cancelled"])
def test_unknown_or_timeout_billing_blocks_another_selector_call(configured, status):
    adapter, transport, journal, shareable, _ = configured
    capsule = build_capsule(shareable, "2" * 32)
    transport._reply = Reply(status, usage=Usage(12, 4, Decimal("0.0001")) if status == "timeout" else Usage())
    assert not validate_selection(capsule, adapter.select(capsule)).accepted
    assert journal.summary()["pending_attempt_ids"]
    assert not validate_selection(capsule, adapter.select(capsule)).accepted
    assert len(transport.requests) == 1 and len(adapter.receipts) == 1
    assert journal.summary()["requests"] == 1 and journal.summary()["new_requests_blocked"]


def test_input_cap_and_wrong_price_are_zero_start_denials(configured):
    adapter, transport, journal, shareable, _ = configured
    capsule = build_capsule(shareable, "2" * 32)
    adapter.limits = replace(adapter.limits, max_input_bytes=1)
    assert adapter.select(capsule).clauses == ()
    assert transport.requests == [] and adapter.receipts == () and journal.summary()["requests"] == 0
    adapter.limits = replace(adapter.limits, max_input_bytes=65536)
    transport.identity = replace(transport.identity, model="different-synthetic-model")
    assert adapter.select(capsule).clauses == ()
    assert transport.requests == [] and adapter.receipts == () and journal.summary()["requests"] == 0


def test_binding_rejects_wrong_D_facts_even_with_recomputed_record_pin():
    shareable, context, baseline = projection_fixture()
    altered = baseline.model_copy(update={"decision_fact_ids": ("9" * 32,)})
    with pytest.raises(ValueError, match="binding_mismatch"):
        binding_fixture(shareable, context, altered)
