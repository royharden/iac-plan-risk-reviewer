"""Regression SOURCE ONLY under Dirty Mode; not executed during construction."""
from dataclasses import replace
from decimal import Decimal
import json
from pathlib import Path

import pytest

from eval.model.driver import DriverConfig, main, run_driver
from eval.model.experiment import Limits
from eval.model.transport import FakeTransport, Reply, Request, Usage

CANARY = "synthetic_private_canary_46b0"


def _plan(tmp_path: Path) -> Path:
    source = tmp_path / "synthetic.json"
    source.write_text(json.dumps({
        "format_version": "1.2", "terraform_version": "1.9.8", "complete": True,
        "errored": False, "resource_changes": [{
            "address": "aws_db_instance." + CANARY, "name": CANARY,
            "provider_name": "registry.terraform.io/hashicorp/aws", "mode": "managed",
            "type": "aws_db_instance", "change": {
                "actions": ["update"],
                "before": {"publicly_accessible": False, "storage_encrypted": True,
                           "tags": {"secret": CANARY}},
                "after": {"publicly_accessible": True, "storage_encrypted": False,
                          "tags": {"secret": CANARY}},
                "before_sensitive": {"tags": True}, "after_sensitive": {"tags": True},
                "after_unknown": {},
            },
        }],
    }), encoding="utf-8")
    return source


def _config(tmp_path: Path) -> DriverConfig:
    return DriverConfig(_plan(tmp_path), tmp_path / "run", True, 20, 2_000_000,
                        200_000, Decimal("1"))


class RecordingFake(FakeTransport):
    def __init__(self) -> None:
        super().__init__()
        self.requests: list[Request] = []

    def complete(self, request: Request) -> Reply:
        self.requests.append(request)
        return super().complete(request)


def test_private_values_and_inference_metadata_stay_out(tmp_path: Path) -> None:
    """Catches raw plan/address/tag exports or D/gold/provenance injection into M."""
    recorder = RecordingFake()
    config = _config(tmp_path)
    artifact = run_driver(config, transport=recorder)
    text = artifact.read_text(encoding="utf-8")
    assert CANARY not in text and str(config.synthetic_plan) not in text
    assert CANARY not in (config.out / "attempts.jsonl").read_text(encoding="utf-8")
    assert recorder.requests
    for request in recorder.requests:
        assert CANARY not in request.payload_json
        assert str(config.synthetic_plan) not in request.payload_json
        payload = json.loads(request.payload_json)
        assert not {"gold", "split", "scanner", "source_path", "build_sha256"} & payload.keys()
        if request.arm == "M":
            assert set(payload) == {"case_id", "policy_version", "resources", "policy"}
            assert all(set(row) == {"resource_id", "type", "mode", "canonical_provider", "actions", "facts"}
                       for row in payload["resources"])


def test_mock_bridge_preserves_d_and_never_admits_model_rows(tmp_path: Path) -> None:
    """Catches model mutation of D, false live metrics, or P becoming a risk decision."""
    output = json.loads(run_driver(_config(tmp_path)).read_text(encoding="utf-8"))
    assert output["live_eligible"] is False and output["product_acceptance"] is False
    assert set(output["measurement_status"].values()) == {"NOT MEASURED"}
    baseline = {(r["case_id"], r["resource_id"], r["rule_id"]): r
                for r in output["rows"] if r["arm"] == "D"}
    for row in output["rows"]:
        if row["arm"] != "D":
            assert row["status"] == "not_run"
        if row["arm"] == "L":
            original = baseline[(row["case_id"], row["resource_id"], row["rule_id"])]
            assert (row["outcome"], row["applicability"], row["decision_fact_ids"]) == (
                original["outcome"], original["applicability"], original["decision_fact_ids"])
        if row["arm"] == "P":
            assert row["outcome"] is None
    assert output["accounting"]["live_successes"] == 0
    assert output["accounting"]["cost_per_live_success_usd"] is None
    assert all(not row["live_eligible"] for row in output["attempts"])


def test_input_byte_cap_prevents_any_transport_start(tmp_path: Path) -> None:
    """Catches caps applied only after sending or journal starts for unsent input."""
    recorder = RecordingFake()
    config = replace(_config(tmp_path), limits=Limits(max_input_bytes=1))
    output = json.loads(run_driver(config, transport=recorder).read_text(encoding="utf-8"))
    assert recorder.requests == []
    assert output["accounting"]["requests"] == 0 and output["attempts"] == []
    assert all(row["status"] == "not_run" for row in output["observations"])


def test_failed_attempt_keeps_reported_cost_and_usage(tmp_path: Path) -> None:
    """Catches dropped invalid-response charges or retries after a reservation overrun."""
    transport = FakeTransport(Reply("ok", b"{}", Usage(3, 1, Decimal("0.005"))))
    output = json.loads(run_driver(_config(tmp_path), transport=transport).read_text(encoding="utf-8"))
    assert output["accounting"]["requests"] == 1
    assert output["accounting"]["known_usd"] == "0.005"
    assert output["accounting"]["input_tokens_reported"] == 3
    assert output["attempts"][0]["status"] == "invalid"
    assert output["journal_summary"]["new_requests_blocked"] is True


def test_output_cap_and_request_cap_keep_one_accounted_attempt(tmp_path: Path) -> None:
    """Catches oversized reply disclosure and additional starts beyond the total cap."""
    config = replace(_config(tmp_path), max_requests=1, limits=Limits(max_output_bytes=8))
    transport = FakeTransport(Reply("ok", CANARY.encode("utf-8"), Usage(0, 0, Decimal(0))))
    text = run_driver(config, transport=transport).read_text(encoding="utf-8")
    output = json.loads(text)
    assert CANARY not in text
    assert output["accounting"]["requests"] == 1
    assert output["attempts"][0]["status"] == "invalid"
    assert output["attempts"][0]["response_sha256"] is None
    assert output["observations"][0]["reason"] == "response_size_or_type"


@pytest.mark.parametrize("scenario", ["timeout", "unknown-usage"])
def test_liability_stops_batch_until_operator_reconciliation(tmp_path: Path, scenario: str) -> None:
    """Catches known-usage timeout becoming free/resolved, or requests after unknown billing."""
    config = replace(_config(tmp_path), fake_scenario=scenario)
    output = json.loads(run_driver(config).read_text(encoding="utf-8"))
    assert output["accounting"]["requests"] == 1
    assert output["journal_summary"]["new_requests_blocked"] is True
    assert output["journal_summary"]["pending_attempt_ids"]
    assert output["accounting"]["billing_fully_known"] is False
    assert output["accounting"]["total_usd"] is None
    assert output["accounting"]["pending_attempt_ids"]


def test_explicit_fake_mode_and_fresh_output_are_required(tmp_path: Path) -> None:
    """Catches accidental live/default execution and overwriting a prior run."""
    config = _config(tmp_path)
    with pytest.raises(ValueError, match="explicit_fake"):
        run_driver(replace(config, fake=False))
    config.out.mkdir()
    sentinel = config.out / "keep.txt"
    sentinel.write_text("keep", encoding="utf-8")
    with pytest.raises(ValueError, match="fresh_output"):
        run_driver(config)
    assert sentinel.read_text(encoding="utf-8") == "keep"
    with pytest.raises(SystemExit) as error:
        main(["--synthetic-plan", "unused.json"])
    assert error.value.code == 3


def test_network_transport_cannot_hide_in_fake_mode(tmp_path: Path) -> None:
    """Catches protocol identity being mistaken for authorization to use network code."""
    from eval.model.provider_http import ProviderTransport
    from eval.model.provider_wire import ProviderConfig

    config = _config(tmp_path)
    transport = ProviderTransport(ProviderConfig("synthetic-model", "synthetic-version"))
    with pytest.raises(ValueError, match="forbidden_in_fake_mode"):
        run_driver(config, transport=transport)
    with pytest.raises(ValueError, match="shared_journal_required"):
        run_driver(replace(config, fake=False), transport=transport, provider_mode=True)
    assert not config.out.exists() and transport.receipts == []


def test_shared_journal_dispatch_is_after_start_and_driver_does_not_close_it(tmp_path: Path) -> None:
    """Catches a hidden per-case journal/close or transport admission before fsynced start."""
    from time import monotonic
    from iac_review.attempts import AttemptJournal, Budget, PriceIdentity
    from eval.model.provider_activation import started_attempt

    config = replace(_config(tmp_path), limits=Limits(max_attempts=1))
    calls = []
    class JournalAwareFake(FakeTransport):
        def complete_started(self, request, *, journal, attempt_id, deadline_monotonic):
            start = started_attempt(journal, attempt_id)
            assert start.attempt_id == attempt_id and deadline_monotonic > monotonic()
            calls.append(attempt_id)
            return super().complete(request)
    transport = JournalAwareFake()
    budget = Budget(max_requests=config.max_requests, max_input_tokens=config.max_input_tokens,
        max_output_tokens=config.max_output_tokens, max_usd=config.max_usd)
    price = PriceIdentity(provider="mock", model="finite-fake", price_id="synthetic-zero",
        price_date="2026-10-23", input_usd_per_million=Decimal(0), output_usd_per_million=Decimal(0))
    with AttemptJournal(tmp_path / "shared.jsonl", budget, price) as journal:
        first = json.loads(run_driver(config, transport=transport, journal=journal).read_text())
        second = json.loads(run_driver(replace(config, out=tmp_path / "second"),
            transport=transport, journal=journal).read_text())
        assert len(calls) == 2 and calls[0] != calls[1]
        assert first["journal_summary"]["requests"] == 1
        assert second["journal_summary"]["requests"] == 2
        assert not (config.out / "attempts.jsonl").exists()
        assert journal.summary()["requests"] == 2


def test_incomplete_provider_payload_stays_private_diagnostic_and_pending(tmp_path: Path) -> None:
    """Catches incomplete prefixes parsed as valid prose or converted to full artifacts."""
    from eval.model.provider_http import ProviderReply

    class PartialFake(FakeTransport):
        def complete(self, request):
            if request.arm == "P":
                return ProviderReply("timeout", b'{"claims":["prefix"]}', Usage(), False)
            return super().complete(request)
    config = replace(_config(tmp_path), capture_private_prose=tmp_path / "private",
        generator_actor_ids=("a" * 32,))
    output = json.loads(run_driver(config, transport=PartialFake()).read_text())
    assert output["accounting"]["pending_attempt_ids"]
    assert all(row["status"] == "not_run" for row in output["rows"] if row["arm"] != "D")
    private_files = list(config.capture_private_prose.glob("*.json"))
    diagnostics = [json.loads(p.read_text()) for p in private_files
                   if "diagnostic" in p.name]
    assert diagnostics and any(d["response_capture_complete"] is False for d in diagnostics)
    assert all(not row["live_eligible"] for row in output["attempts"])


def test_explicit_programmatic_provider_with_fake_connector_preserves_liability(tmp_path: Path) -> None:
    """Catches zero mock prices in provider mode, duplicated journals or live self-admission."""
    from iac_review.attempts import AttemptJournal, Budget, PriceIdentity
    from eval.model.experiment import canonical, digest
    from eval.model.provider_activation import Activation, Admission, activation_digest
    from eval.model.provider_http import ProviderTransport
    from eval.model.provider_wire import (ENDPOINT, ApprovedAttempt, FakeHttpResponse, ProviderConfig,
        model_request_digest, permit_digest, request_digest)

    config = replace(_config(tmp_path), fake=False)
    provider = ProviderConfig("synthetic-model", "synthetic-version")
    requests = []
    def controller(request, start, model_config):
        requests.append(request)
        a = Activation("openai-compatible", provider.model, provider.model_version,
            "a" * 64, "b" * 64, "c" * 64, start.price_sha256, start.budget_sha256,
            start.journal_sha256, dict(start.hashes)["config"], model_request_digest(request),
            request_digest(request, provider), "8.8.8.8", 16384, enabled=True)
        p = ApprovedAttempt(start.attempt_id, a.provider, a.model, a.model_version, ENDPOINT,
            a.approval_sha256, a.provider_sha256, a.price_sha256, a.budget_sha256,
            a.data_transfer_sha256, start.start_record_sha256, digest(request.payload_json),
            digest(request.instruction), a.wire_request_sha256, request.input_tokens_upper,
            request.output_tokens_upper, a.model_request_sha256)
        return Admission(a, p, activation_digest(a), permit_digest(p))
    class FakeConnector:
        def exchange(self, wire, key, ip, deadline):
            text = FakeTransport().complete(requests[-1]).payload.decode()
            body = {"model": provider.model, "status": "completed", "output": [{"type": "message",
                "role": "assistant", "content": [{"type": "output_text", "text": text}]}],
                "usage": {"input_tokens": 12, "output_tokens": 4, "total_tokens": 16}}
            return FakeHttpResponse(200, canonical(body).encode())
    transport = ProviderTransport(provider, enabled=True, controller=controller,
        connector_factory=FakeConnector, key_reader=lambda name: "synthetic-not-a-real-key")
    budget = Budget(max_requests=config.max_requests, max_input_tokens=config.max_input_tokens,
        max_output_tokens=config.max_output_tokens, max_usd=config.max_usd)
    price = PriceIdentity(provider="openai-compatible", model=provider.model, price_id="synthetic-price",
        price_date="2026-10-23", input_usd_per_million=Decimal(1), output_usd_per_million=Decimal(2))
    with AttemptJournal(tmp_path / "shared.jsonl", budget, price) as journal:
        output = json.loads(run_driver(config, transport=transport, journal=journal,
            provider_mode=True).read_text())
        assert len(requests) == 1 and journal.summary()["new_requests_blocked"] is True
        assert Decimal(output["accounting"]["unresolved_usd_upper"]) > 0
        assert output["accounting"]["billing_fully_known"] is False
        assert output["live_eligible"] is False and set(output["measurement_status"].values()) == {"NOT MEASURED"}
        assert all(row["status"] == "not_run" for row in output["rows"] if row["arm"] != "D")
        assert output["provenance"]["source_sha256"] != output["attempts"][0]["hashes"]["input"]
