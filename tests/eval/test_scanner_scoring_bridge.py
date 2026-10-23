"""Public artificial metadata fixtures, not execution evidence. SOURCE NOT RUN."""
from __future__ import annotations

from dataclasses import asdict
import json

import pytest

from eval.runner.scoring import EligibleMeasurement, EligibilityManifest, record_digest
from eval.scanners.driver import ComparisonRow, _capture_digest
from eval.scanners.runner import Limits, Observation, ScanArtifact
from eval.scanners.scoring_bridge import (bridge_report, measurement_ref,
                                          provenance_digest, report_digest)


def fixture(*, prediction: bool = False, status: str = "recorded") -> tuple[dict, EligibilityManifest]:
    # Simulated metadata for gate behavior, never a genuine binary/version pin.
    artifact = ScanArtifact("C-custom", "checkov", "ok" if status == "recorded" else status,
                            "live", "a" * 64, "artificial-fixture-only", "b" * 64,
                            "c" * 64, "d" * 64, "e" * 64, "f" * 64, "1" * 64,
                            "verified", ("CKV_M4_R2",),
                            (Observation("CKV_M4_R2", "private_fixture_locator", "passed"),),
                            raw_exit_code=0, stdout_sha256="2" * 64,
                            stderr_sha256="3" * 64, elapsed_seconds=0.1)
    capture_hash = _capture_digest(artifact)
    row = ComparisonRow("case_1", "resource_1", "R2", "C-custom", status,
                        "introduced_risk", prediction if status == "recorded" else None,
                        status == "recorded", "a" * 64, "4" * 64, capture_hash, ())
    receipt = asdict(artifact)
    receipt.pop("observations")
    receipt.update(case_id="case_1", capture_sha256=capture_hash)
    report = {"schema_version": "m4-scanner-comparison-v1", "input_scope": "development_synthetic",
              "source_enrichment": False, "fake_only": False, "product_acceptance": False,
              "build_sha256": "5" * 64, "rows": [asdict(row)], "capture_receipts": [receipt]}
    meta = EligibleMeasurement(arm="C-custom", measurement_ref=measurement_ref(row),
                               source_sha256=row.plan_sha256, build_sha256="5" * 64,
                               kind="executed", actual_execution_attested=True,
                               provenance_sha256=provenance_digest(row, receipt, "5" * 64))
    return report, EligibilityManifest(edition_id="dev_edition", rows=(meta,))


def approved(report: dict, eligibility: EligibilityManifest, **extra):
    return bridge_report(report, expected_report_sha256=report_digest(report),
                         edition_id="dev_edition", eligibility=eligibility,
                         expected_eligibility_sha256=record_digest(eligibility), **extra)


def test_binary_negative_never_invents_full_outcome() -> None:
    """what_bug_this_catches: binary negative silently converted into known-clear."""
    report, eligibility = fixture(prediction=False)
    batch = approved(report, eligibility)
    row = batch.rows[0]
    assert row.outcome is None
    if batch.binary_schema_available:
        assert row.status == "ok" and row.prediction_target == "introduced_risk"
        assert row.introduced_prediction is False
    else:
        assert row.status == "not_run"
        assert "shared_binary_scorer_schema_pending" in batch.dispositions[0].reasons


def test_missing_external_execution_manifest_is_incomplete() -> None:
    """what_bug_this_catches: source's own live_eligible Boolean self-attests execution."""
    report, _ = fixture(prediction=True)
    batch = bridge_report(report, expected_report_sha256=report_digest(report), edition_id="dev_edition")
    assert batch.rows[0].status == "not_run"
    assert batch.rows[0].eligibility_ref is None
    assert batch.rows[0].measurement_kind == "unverified"


def test_approval_digest_cannot_come_from_changed_manifest() -> None:
    """what_bug_this_catches: edited execution scope accepted under stale authority digest."""
    report, eligibility = fixture()
    with pytest.raises(ValueError, match="external edition approval"):
        bridge_report(report, expected_report_sha256=report_digest(report), edition_id="dev_edition",
                      eligibility=eligibility, expected_eligibility_sha256="0" * 64)


def test_source_mutation_rejects_the_external_report_pin() -> None:
    """what_bug_this_catches: switched binary prediction keeps previously approved source hash."""
    report, _ = fixture()
    expected = report_digest(report)
    report["rows"][0]["introduced_prediction"] = True
    with pytest.raises(ValueError, match="external source pin"):
        bridge_report(report, expected_report_sha256=expected, edition_id="dev_edition")


def test_mock_source_stays_mock_even_with_executed_attestation() -> None:
    """what_bug_this_catches: external-looking attestation overrides explicit fake source."""
    report, eligibility = fixture(prediction=True)
    report["fake_only"] = True
    batch = approved(report, eligibility)
    assert batch.rows[0].status == "not_run"
    assert batch.rows[0].measurement_kind == "mock" and batch.rows[0].eligibility_ref is None
    assert batch.rows[0].outcome is None


def test_changed_binary_or_config_provenance_cannot_reuse_approval() -> None:
    """what_bug_this_catches: new scanner config reuses a matching plan/build eligibility row."""
    report, eligibility = fixture()
    report["capture_receipts"][0]["config_sha256"] = "6" * 64
    batch = approved(report, eligibility)
    assert batch.rows[0].status == "not_run" and batch.rows[0].eligibility_ref is None


def test_changed_output_bounds_cannot_reuse_attestation() -> None:
    """what_bug_this_catches: output/time limits changed without rebinding execution provenance."""
    report, eligibility = fixture()
    batch = approved(report, eligibility, bounds=Limits(timeout_seconds=3.0))
    assert batch.rows[0].status == "not_run" and batch.rows[0].eligibility_ref is None


def test_timeout_and_unused_failed_attempt_remain_visible() -> None:
    """what_bug_this_catches: failed attempts removed because no eligible success references them."""
    report, eligibility = fixture(status="timeout")
    unused = dict(report["capture_receipts"][0], case_id="unused_attempt", capture_sha256="7" * 64)
    report["capture_receipts"].append(unused)
    batch = approved(report, eligibility)
    assert batch.rows[0].status == "timeout" and batch.rows[0].outcome is None
    assert len(batch.attempts) == 2
    assert json.loads(batch.attempts[1].metadata_json)["capture"]["stdout_sha256"] == "2" * 64


def test_duplicate_execution_metadata_is_not_arbitrarily_selected() -> None:
    """what_bug_this_catches: duplicate attestations let an importer cherry-pick the valid one."""
    report, eligibility = fixture()
    repeated = EligibilityManifest(edition_id="dev_edition", rows=eligibility.rows * 2)
    with pytest.raises(ValueError, match="duplicate execution eligibility"):
        approved(report, repeated)


def test_wrong_arm_or_plan_never_borrows_another_capture() -> None:
    """what_bug_this_catches: C-custom observation relabeled as C/T or another plan input."""
    report, eligibility = fixture()
    report["rows"][0]["arm"] = "T"
    batch = approved(report, eligibility)
    assert batch.rows[0].status == "not_run" and batch.rows[0].eligibility_ref is None
    report, eligibility = fixture()
    report["rows"][0]["plan_sha256"] = "8" * 64
    with pytest.raises(ValueError, match="plan identity mismatch"):
        approved(report, eligibility)
