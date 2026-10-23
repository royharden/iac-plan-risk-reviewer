"""Fixed-coordinator regression SOURCE only; not imported/run during Dirty Mode.

Input facts and fake responses are public plumbing data, never oracle labels.
"""
from __future__ import annotations

from dataclasses import replace
from decimal import Decimal
import hashlib
import json

import pytest

from iac_review.attempts import AttemptJournal, Budget, PriceIdentity
from eval.model.experiment import Limits
from eval.model.transport import FakeTransport, Reply
from eval.runner.benchmark import BenchmarkConfig, CaseSpec, FIXED_ARMS, coordinate


def fixture(tmp_path, *, requests=100):
    cases = []
    for number in (1, 2):
        raw = json.dumps({"format_version": "1.2", "complete": True, "errored": False,
            "resource_changes": [{"address": "aws_db_instance.synthetic_address_canary",
                "mode": "managed", "type": "aws_db_instance", "name": "synthetic_address_canary",
                "provider_name": "registry.terraform.io/hashicorp/aws",
                "change": {"actions": ["create"], "before": None,
                           "after": {"publicly_accessible": True, "storage_encrypted": False,
                                     "tags": {"private_canary": "never_transport_this"}},
                           "before_sensitive": {}, "after_sensitive": {}, "after_unknown": {}}}]}).encode()
        path = tmp_path / f"case-{number}.json"
        path.write_bytes(raw)
        cases.append(CaseSpec(f"external_case_{number}", path, hashlib.sha256(raw).hexdigest(),
                              "public_config", "public_family", "public_mutation"))
    budget = Budget(max_requests=requests, max_input_tokens=1_000_000,
                    max_output_tokens=100_000, max_usd=Decimal(0))
    config = BenchmarkConfig("public_run", "public_edition", "a" * 64, tuple(cases), budget,
                              model_limits=Limits(input_tokens_upper=128, output_tokens_upper=32),
                              synthetic_input_attested=True)
    journal_path = tmp_path / "attempts.jsonl"
    journal_path.touch()
    price = PriceIdentity(provider="mock", model="finite-fake", price_id="mock-zero-not-provider-price",
                           price_date="2026-10-23", input_usd_per_million=Decimal(0),
                           output_usd_per_million=Decimal(0))
    return config, journal_path, price


def test_every_case_has_exactly_the_seven_fixed_arm_statuses(tmp_path) -> None:
    """what_bug_this_catches: missing scanner/model arm omitted from incomplete comparison output."""
    config, path, price = fixture(tmp_path)
    with AttemptJournal(path, config.budget, price) as journal:
        result = coordinate(config, journal=journal, transport=FakeTransport())
    assert len(result.statuses) == len(config.cases) * 7
    for case in config.cases:
        assert tuple(row.arm for row in result.statuses if row.case_id == case.case_id) == FIXED_ARMS
    assert result.live_eligible is False
    assert all(row.eligibility_ref is None for row in result.rows)


def test_request_cap_is_shared_across_cases_without_reset(tmp_path) -> None:
    """what_bug_this_catches: per-case model driver silently obtains a new request budget."""
    config, path, price = fixture(tmp_path, requests=1)
    with AttemptJournal(path, config.budget, price) as journal:
        result = coordinate(config, journal=journal, transport=FakeTransport())
        assert journal.summary()["requests"] == 1
    source = json.loads(result.private_provenance_json)
    assert len(source["journal_snapshot"]["attempts"]) == 1
    assert any(row.case_id == "external_case_2" and row.arm == "M" and row.status == "not_run"
               for row in result.statuses)


def test_unknown_usage_stops_model_starts_in_all_later_cases(tmp_path) -> None:
    """what_bug_this_catches: unknown liability cleared by moving to the next synthetic case."""
    config, path, price = fixture(tmp_path)
    with AttemptJournal(path, config.budget, price) as journal:
        result = coordinate(config, journal=journal, transport=FakeTransport(Reply("error")))
        summary = journal.summary()
        assert summary["requests"] == 1 and summary["new_requests_blocked"] is True
        assert summary["pending_attempt_ids"]
    assert all(row.status == "not_run" for row in result.statuses
               if row.case_id == "external_case_2" and row.arm in {"L", "P", "M"})
    assert len(json.loads(result.private_provenance_json)["journal_snapshot"]["attempts"]) == 1


def test_transport_never_receives_raw_canaries_external_case_labels_or_scanners(tmp_path) -> None:
    """what_bug_this_catches: raw/split/scanner joins contaminate the model inference boundary."""
    config, path, price = fixture(tmp_path)

    class RecordingFake(FakeTransport):
        def __init__(self):
            super().__init__()
            self.requests = []

        def complete(self, request):
            self.requests.append(request)
            return super().complete(request)

    transport = RecordingFake()
    with AttemptJournal(path, config.budget, price) as journal:
        result = coordinate(config, journal=journal, transport=transport)
    assert transport.requests
    for request in transport.requests:
        assert "never_transport_this" not in request.payload_json
        assert "synthetic_address_canary" not in request.payload_json
        assert "external_case_" not in request.payload_json
        assert "scanner_results" not in request.payload_json and '"split"' not in request.payload_json
        if request.arm == "M":
            assert '"outcome"' not in request.payload_json and '"finding_id"' not in request.payload_json
    public = result.public_summary_json
    assert "private/" not in public and "never_transport_this" not in public and '"claims"' not in public


def test_heldout_scope_rejects_before_any_case_payload_access(tmp_path, monkeypatch) -> None:
    """what_bug_this_catches: metadata preflight or a split flag authorizes hidden payload access."""
    config, path, price = fixture(tmp_path)

    def forbid(_):
        raise AssertionError("case payload must not be touched")

    monkeypatch.setattr("eval.runner.benchmark.verify_case", forbid)
    with AttemptJournal(path, config.budget, price) as journal:
        with pytest.raises(ValueError, match="before_payload_access"):
            coordinate(replace(config, input_scope="heldout"), journal=journal, transport=FakeTransport())


def test_hash_abort_keeps_later_cases_explicitly_not_run(tmp_path) -> None:
    """what_bug_this_catches: changed input abandons later cases instead of retaining required arm rows."""
    config, path, price = fixture(tmp_path)
    config.cases[0].plan_path.write_bytes(config.cases[0].plan_path.read_bytes() + b" ")
    with AttemptJournal(path, config.budget, price) as journal:
        result = coordinate(config, journal=journal, transport=FakeTransport())
        assert journal.summary()["requests"] == 0
    assert len(result.statuses) == 14
    assert all(row.status == "invalid" for row in result.statuses if row.case_id == "external_case_1")
    assert all(row.status == "not_run" for row in result.statuses if row.case_id == "external_case_2")
    assert json.loads(result.public_summary_json)["aborted"] is True
