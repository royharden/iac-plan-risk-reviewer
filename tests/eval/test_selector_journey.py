"""Actual report/capsule composition regression SOURCE, not an executed journey."""
from dataclasses import asdict, replace
from decimal import Decimal
import json

import pytest

from iac_review.attempts import AttemptJournal, Budget, PriceIdentity
from iac_review.explain import build_capsule
from iac_review.ingest import load_plan
from iac_review.report import build_report
from iac_review.rules import evaluate
from eval.model.experiment import Context, Limits, canonical, digest
from eval.model.selector_adapter import (
    AdmittedSelector, binding_digest, explain_with_admitted_selector, make_binding,
)
from eval.model.transport import FakeTransport, Reply, Usage
from eval.runner.scoring import ArmRow

CANARY = "private_synthetic_selector_canary"


class RecordingFake(FakeTransport):
    def __init__(self):
        super().__init__()
        self.requests = []
    def complete(self, request):
        self.requests.append(request)
        return super().complete(request)


@pytest.fixture
def journey(tmp_path):
    source = tmp_path / "synthetic.json"
    source.write_text(json.dumps({"format_version": "1.2", "terraform_version": "1.9.8",
        "complete": True, "errored": False, "resource_changes": [{
            "address": "aws_db_instance." + CANARY, "name": CANARY,
            "provider_name": "registry.terraform.io/hashicorp/aws", "type": "aws_db_instance", "mode": "managed",
            "change": {"actions": ["update"], "before": {"publicly_accessible": False,
                "storage_encrypted": True, "tags": {"private": CANARY}},
                "after": {"publicly_accessible": True, "storage_encrypted": True, "tags": {"private": CANARY}},
                "before_sensitive": {"tags": True}, "after_sensitive": {"tags": True}, "after_unknown": {}}}]}))
    plan = load_plan(source)
    report = build_report(plan, evaluate(plan))
    row = next(r for r in report.shareable["evaluations"] if r["rule_id"] == "R2")
    private = next(r for r in report.private["evaluations"] if r["finding_id"] == row["finding_id"])
    context = Context("a" * 64, plan.identity.sha256, "c" * 64, "d" * 64)
    baseline = ArmRow(case_id=report.shareable["case_id"], resource_id=row["resource_id"], rule_id="R2",
        arm="D", status="ok", applicability=row["applicability"], outcome=row["outcome"],
        reason_code=private["reason_code"], decision_fact_ids=tuple(f["fact_id"] for f in row["facts"]
            if f["role"] == "decision"), required_limitation_ids=tuple(sorted(set(row["limitation_ids"]) |
                {v["id"] for v in report.shareable["limitations"]})), source_sha256=context.source_sha256,
        build_sha256=context.build_sha256, measurement_ref="sha256:" + digest(canonical(report.shareable)))
    binding = make_binding(shareable=report.shareable, finding_id=row["finding_id"], baseline=baseline, context=context,
        expected_shareable_sha256=digest(canonical(report.shareable)),
        expected_baseline_sha256=digest(canonical(baseline.model_dump(mode="json"))), authority_sha256="f" * 64)
    budget = Budget(max_requests=2, max_input_tokens=10000, max_output_tokens=1000, max_usd=Decimal(1))
    price = PriceIdentity(provider="mock", model="finite-fake", price_id="synthetic-price", price_date="2026-10-23",
        input_usd_per_million=Decimal(1), output_usd_per_million=Decimal(2))
    with AttemptJournal(tmp_path / "shared.jsonl", budget, price) as journal:
        transport = RecordingFake()
        selector = AdmittedSelector(enabled=True, binding=binding, expected_binding_sha256=binding_digest(binding),
            transport=transport, journal=journal, limits=Limits(input_tokens_upper=1000, output_tokens_upper=128))
        yield report, row["finding_id"], baseline, selector, transport, journal


def test_same_finding_valid_then_invalid_preserves_D_exit_coverage_and_private_boundary(journey):
    report, finding, baseline, selector, transport, journal = journey
    before = canonical(report.shareable), report.exit_code, baseline.model_dump_json()
    valid = explain_with_admitted_selector(report, finding, selector=selector)
    transport._reply = Reply("ok", b'{"clauses":[],"limitation_ids":[]}', Usage(12, 4, Decimal("0.0001")))
    invalid = explain_with_admitted_selector(report, finding, selector=selector)
    capsule = build_capsule(report.shareable, finding)
    assert valid.selection.accepted and not invalid.selection.accepted
    assert invalid.selection.text == capsule.baseline and invalid.selection.limitation_ids == capsule.required_limitation_ids
    assert before == (canonical(report.shareable), report.exit_code, baseline.model_dump_json())
    assert valid.finding_id == invalid.finding_id == finding
    assert valid.outcome == invalid.outcome == baseline.outcome
    assert valid.receipt.attempt.attempt_id != invalid.receipt.attempt.attempt_id
    assert [r.arm for r in transport.requests] == ["L", "L"] and journal.summary()["requests"] == 2
    assert journal.summary()["known_usd"] == "0.0001"
    assert all(CANARY not in r.payload_json for r in transport.requests)
    assert CANARY not in json.dumps([asdict(r) for r in selector.receipts])
    assert valid.live_eligible is invalid.live_eligible is False


def test_default_and_report_pin_denial_do_not_start(journey):
    report, finding, _, selector, transport, journal = journey
    result = explain_with_admitted_selector(report, finding)
    assert not result.selection.accepted and result.receipt is None
    changed = json.loads(canonical(report.shareable))
    changed["summary"]["synthetic_marker"] = True
    other = report.model_copy(update={"shareable": changed})
    result = explain_with_admitted_selector(other, finding, selector=selector)
    assert not result.selection.accepted and result.receipt is None
    assert transport.requests == [] and selector.receipts == () and journal.summary()["requests"] == 0


def test_global_cap_keeps_only_two_receipts_and_never_runs_P_M(journey):
    report, finding, _, selector, transport, journal = journey
    for _ in range(2):
        assert explain_with_admitted_selector(report, finding, selector=selector).selection.accepted
    denied = explain_with_admitted_selector(report, finding, selector=selector)
    assert not denied.selection.accepted and denied.receipt is None
    assert len(selector.receipts) == 2 and [r.arm for r in transport.requests] == ["L", "L"]
    assert journal.summary()["requests"] == 2


def test_pending_timeout_keeps_upper_liability_and_blocks_next_call(journey):
    report, finding, _, selector, transport, journal = journey
    transport._reply = Reply("timeout", usage=Usage(12, 4, Decimal("0.0001")))
    first = explain_with_admitted_selector(report, finding, selector=selector)
    second = explain_with_admitted_selector(report, finding, selector=selector)
    assert not first.selection.accepted and not second.selection.accepted and second.receipt is None
    assert len(transport.requests) == 1 and len(selector.receipts) == 1
    assert journal.summary()["pending_attempt_ids"]
    assert Decimal(journal.summary()["unresolved_usd_upper"]) > 0


def test_price_mismatch_has_no_start_or_fabricated_receipt(journey):
    report, finding, _, selector, transport, journal = journey
    transport.identity = replace(transport.identity, model="different-synthetic-model")
    result = explain_with_admitted_selector(report, finding, selector=selector)
    assert not result.selection.accepted and result.receipt is None
    assert journal.summary()["requests"] == 0 and selector.receipts == () and transport.requests == []


def test_mutating_injected_code_cannot_replace_product_report_silently(journey):
    report, finding, _, selector, transport, journal = journey
    class MutatingFake(RecordingFake):
        def complete(self, request):
            report.shareable["summary"]["synthetic_mutation"] = True
            return super().complete(request)
    selector.transport = MutatingFake()
    with pytest.raises(ValueError, match="report_or_exit_changed"):
        explain_with_admitted_selector(report, finding, selector=selector)
    assert journal.summary()["requests"] == 1 and len(selector.receipts) == 1
