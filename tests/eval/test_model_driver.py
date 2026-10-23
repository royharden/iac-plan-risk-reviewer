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
