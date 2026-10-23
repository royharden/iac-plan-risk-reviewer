"""Boundary regression SOURCE. Dirty Mode does not import or execute this file."""
from dataclasses import replace
from decimal import Decimal
import json

import pytest

from iac_review.attempts import AttemptJournal, Reservation, Budget
from eval.model.experiment import canonical, digest
from eval.model.transport import FakeTransport, Reply, Usage
from eval.runner.benchmark import coordinate
from test_benchmark_coordination import fixture


def test_raw_cardinality_and_case_record_pins_are_not_request_counts(tmp_path):
    """what_bug_this_catches: many findings/requests on identical bytes inflate scenario coverage."""
    config, path, price = fixture(tmp_path)
    config = replace(config, cases=tuple(replace(case, case_record_sha256=str(i) * 64)
                                        for i, case in enumerate(config.cases, 1)))
    with AttemptJournal(path, config.budget, price) as journal:
        result = coordinate(config, journal=journal, transport=FakeTransport())
    public, source = json.loads(result.public_summary_json), json.loads(result.private_provenance_json)
    assert public["case_record_count"] == 2
    assert public["verified_distinct_raw_byte_identities"] == 1
    assert public["eligible_scenario_count"] is None
    assert len(source["model_exports"]) == 2
    assert source["run_accounting"]["summary"]["requests"] > 2
    for entry in source["model_attempts"]:
        assert entry["raw_input_sha256"] == config.cases[0].plan_sha256
        assert entry["case_record_sha256"] in {"1" * 64, "2" * 64}
        assert entry["request_input_sha256"] != entry["raw_input_sha256"]
        assert entry["safe_projection_sha256"] != entry["raw_input_sha256"]
    assert sum(len(export["attempts"]) for export in source["model_exports"]) == public["requests"]


def test_started_unexported_attempt_survives_producer_failure(tmp_path):
    """what_bug_this_catches: a producer crash erases a reservation or invents an arm receipt."""
    config, path, price = fixture(tmp_path)

    def broken(**kwargs):
        kwargs["journal"].start(Reservation(input_tokens_upper=1, output_tokens_upper=1,
            request_usd_upper=Decimal(0), hashes={name: "a" * 64 for name in
                ("build", "corpus", "projection", "prompt", "input", "model", "config")}))
        raise RuntimeError("synthetic producer failure")

    with AttemptJournal(path, config.budget, price) as journal:
        result = coordinate(config, journal=journal, transport=FakeTransport(), models=broken)
        assert journal.summary()["requests"] == 1
    source = json.loads(result.private_provenance_json)
    assert len(source["model_attempts"]) == 1
    attempt = source["model_attempts"][0]
    assert attempt["arm"] is None and attempt["producer"] is None
    assert attempt["snapshot"]["requires_reconciliation"] is True
    assert "model_attempt_arm_or_case_unmatched" in json.loads(result.manifest_candidate_json)["missing"]
    assert all(row.status == "not_run" for row in result.statuses if row.arm in {"L", "P", "M"})


def test_build_mismatch_refuses_before_case_access(tmp_path, monkeypatch):
    """what_bug_this_catches: a pinned config runs against different source before admission."""
    config, path, price = fixture(tmp_path)
    monkeypatch.setattr("eval.runner.benchmark.verify_case",
                        lambda _: pytest.fail("payload access before source pin check"))
    with AttemptJournal(path, config.budget, price) as journal:
        with pytest.raises(ValueError, match="before_payload_access"):
            coordinate(config, journal=journal, transport=FakeTransport(), build_verifier=lambda: "b" * 64)


def test_build_change_retains_attempts_but_invalidates_all_statuses(tmp_path):
    """what_bug_this_catches: source changing during a run leaves apparently complete statuses."""
    config, path, price = fixture(tmp_path)
    pins = iter((config.build_sha256, "b" * 64))
    with AttemptJournal(path, config.budget, price) as journal:
        result = coordinate(config, journal=journal, transport=FakeTransport(), build_verifier=lambda: next(pins))
    assert all(status.reason_code == "source_build_changed" for status in result.statuses)
    source = json.loads(result.private_provenance_json)
    assert source["journal_snapshot"]["attempts"]
    assert "source_build_changed" in json.loads(result.manifest_candidate_json)["missing"]


def test_fake_scanner_cannot_claim_live_capture(tmp_path):
    """what_bug_this_catches: an injected scanner bypasses fake-only construction eligibility."""
    config, path, price = fixture(tmp_path)

    def forged(*args, **kwargs):
        return {"fake_only": True, "capture_receipts": [{"execution_kind": "live"}]}

    with AttemptJournal(path, config.budget, price) as journal:
        result = coordinate(config, journal=journal, transport=FakeTransport(), scanners=forged)
    assert all(status.reason_code == "scanner_admission_incomplete" for status in result.statuses
               if status.arm in {"C", "C-custom", "T"})
    assert all(row.eligibility_ref is None for row in result.rows)


@pytest.mark.parametrize("cap", ("tokens", "usd"))
def test_token_and_usd_exposure_do_not_reset_between_cases(tmp_path, cap):
    """what_bug_this_catches: non-request exposure caps silently reset on the second case."""
    config, path, price = fixture(tmp_path)
    budget = Budget(max_requests=100, max_input_tokens=128 if cap == "tokens" else 100000,
                    max_output_tokens=100000, max_usd=Decimal("0.02"))
    price = price.model_copy(update={"input_usd_per_million": Decimal(100),
                                      "output_usd_per_million": Decimal(100)})
    config = replace(config, budget=budget)
    with AttemptJournal(path, budget, price) as journal:
        result = coordinate(config, journal=journal,
            transport=FakeTransport(Reply("error", usage=Usage(128, 32, Decimal("0.016")))))
        assert journal.summary()["requests"] == 1
    assert len(json.loads(result.private_provenance_json)["journal_snapshot"]["attempts"]) == 1


def test_manifest_pin_pair_rejects_before_case_access(tmp_path, monkeypatch):
    """what_bug_this_catches: a loose manifest hash is treated as custody or typed context."""
    config, path, price = fixture(tmp_path)
    monkeypatch.setattr("eval.runner.benchmark.verify_case", lambda _: pytest.fail("case access"))
    with AttemptJournal(path, config.budget, price) as journal:
        with pytest.raises(ValueError, match="together"):
            coordinate(config, journal=journal, transport=FakeTransport(),
                       expected_manifest_context_sha256=digest(canonical({})))


def test_zero_row_export_keeps_independent_case_identity_and_original_receipts(tmp_path, monkeypatch):
    """what_bug_this_catches: rows[0] identity drops a failed export and its started attempts."""
    from eval.model.provenance import export_bundle

    config, path, price = fixture(tmp_path)

    def empty_export(result):
        return replace(export_bundle(result), rows=())

    monkeypatch.setattr("eval.runner.benchmark.export_bundle", empty_export)
    with AttemptJournal(path, config.budget, price) as journal:
        result = coordinate(config, journal=journal, transport=FakeTransport())
    source = json.loads(result.private_provenance_json)
    exported = source["model_exports"][0]
    assert exported["case_id"] == config.cases[0].case_id
    assert exported["raw_input_sha256"] == config.cases[0].plan_sha256
    assert exported["rows"] == [] and exported["attempts"]
    assert len(source["model_attempts"]) == len(exported["attempts"])
    assert len(source["journal_snapshot"]["attempts"]) == len(exported["attempts"])
    assert "model_export_admission_incomplete" in json.loads(result.manifest_candidate_json)["missing"]
    assert all(row.status == "not_run" for row in result.statuses if row.arm in {"L", "P", "M"})
