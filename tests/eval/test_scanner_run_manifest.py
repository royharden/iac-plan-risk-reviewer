"""Typed manifest regression SOURCE, not executed. Artificial metadata, no payloads."""
from __future__ import annotations

from dataclasses import asdict, replace
import json

import pytest

from iac_review.contracts.manifest import ArtifactRef, CaseBinding, ComponentVersion
from eval.runner.scoring import EligibilityManifest, record_digest
from eval.scanners.driver import ComparisonRow, _capture_digest
from eval.scanners.runner import Observation, ScanArtifact
from eval.scanners.run_manifest import (ScannerComponents, ScannerRunContext, adapt_scanner_report)
from eval.scanners.scoring_bridge import report_digest


def fixture():
    # Pure metadata fiction for schema behavior, not genuine version/execution pins.
    artifact = ScanArtifact("C", "checkov", "ok", "live", "a" * 64, "fixture-only", "b" * 64,
                            "c" * 64, "d" * 64, "e" * 64, "f" * 64, "1" * 64,
                            "verified", ("CKV_FIXTURE",),
                            (Observation("CKV_FIXTURE", "private_fixture_locator", "passed"),),
                            raw_exit_code=0, stdout_sha256="2" * 64, stderr_sha256="3" * 64,
                            elapsed_seconds=0.2, operator_grant_sha256="7" * 64,
                            start_receipt_sha256="8" * 64, terminal_receipt_sha256="9" * 64)
    capture_sha = _capture_digest(artifact)
    row = ComparisonRow("case_1", "resource_1", "R2", "C", "recorded", "introduced_risk",
                        False, True, "a" * 64, "4" * 64, capture_sha, ())
    receipt = asdict(artifact)
    receipt.pop("observations")
    receipt.update(case_id="case_1", capture_sha256=capture_sha)
    report = {"schema_version": "m4-scanner-comparison-v1", "build_sha256": "5" * 64,
              "input_scope": "development_synthetic", "source_enrichment": False,
              "fake_only": False, "product_acceptance": False, "rows": [asdict(row)],
              "capture_receipts": [receipt]}
    case = CaseBinding(case_id="case_1", split="dev", configuration_id="public_cfg_1",
                       family_id="public_family_1", mutation_lineage="public_mutation_1", raw_source_sha256="a" * 64)
    refs = tuple(ArtifactRef(artifact_id=name, role="producer", path="private/" + name + ".json",
                             sha256=pin * 64, bytes_upper=4096) for name, pin in (
                                 ("operator_grant", "7"), ("start_receipt", "8"), ("terminal_receipt", "9")))
    context = ScannerRunContext("fixture_run", "fixture_edition", "0" * 64, "6" * 64,
                                "b" * 64, (case,), refs)
    eligibility = EligibilityManifest(edition_id="fixture_edition", rows=())
    return report, context, eligibility


def build(report, context, eligibility):
    return adapt_scanner_report(report, expected_report_sha256=report_digest(report), context=context,
                                eligibility=eligibility, expected_eligibility_sha256=record_digest(eligibility))


def test_typed_execution_metadata_does_not_self_authorize_scoring() -> None:
    """what_bug_this_catches: private start/terminal metadata automatically yields eligible comparison rows."""
    report, context, eligibility = fixture()
    result = build(report, context, eligibility)
    assert result.manifest is not None
    assert result.manifest.invocations[0].kind == "executed"
    assert result.manifest.invocations[0].all_attempts_attested is False
    assert result.manifest.eligibility[0].claimed_eligible is False
    assert result.bridge.rows[0].status == "not_run"


def test_missing_authority_pin_yields_draft_not_placeholder_digest() -> None:
    """what_bug_this_catches: required unknown authority filled with fabricated hash/version metadata."""
    report, context, eligibility = fixture()
    result = build(report, replace(context, authority_sha256=None), eligibility)
    assert result.manifest is None and "authority_missing" in result.missing
    assert len(result.bridge.attempts) == 1


def test_fake_receipts_never_acquire_executed_kind_or_eligibility() -> None:
    """what_bug_this_catches: a mocked capture borrows valid-looking operator receipt references."""
    report, context, eligibility = fixture()
    report["fake_only"] = True
    report["capture_receipts"][0]["execution_kind"] = "fake"
    result = build(report, context, eligibility)
    assert result.manifest is not None
    assert result.manifest.attempts[0].kind == "mock"
    assert result.manifest.invocations[0].status == "not_run"
    assert not any(row.claimed_eligible for row in result.manifest.eligibility)


def test_missing_private_receipt_reference_remains_incomplete() -> None:
    """what_bug_this_catches: receipt hash with no actual private artifact binding proves execution."""
    report, context, eligibility = fixture()
    result = build(report, replace(context, artifacts=()), eligibility)
    assert result.manifest is None
    assert "private_execution_receipt_references_missing" in result.missing


def test_case_hash_and_scope_cannot_drift_from_capture() -> None:
    """what_bug_this_catches: same case label rebinds an input or smuggles heldout metadata."""
    report, context, eligibility = fixture()
    wrong = context.cases[0].model_copy(update={"raw_source_sha256": "c" * 64})
    with pytest.raises(ValueError, match="source digest mismatch"):
        build(report, replace(context, cases=(wrong,)), eligibility)
    hidden = context.cases[0].model_copy(update={"split": "heldout"})
    with pytest.raises(ValueError, match="development-only"):
        build(report, replace(context, cases=(hidden,)), eligibility)


def test_public_summary_excludes_private_paths_hashes_and_raw_locators() -> None:
    """what_bug_this_catches: typed private reproducibility metadata accidentally becomes public payload."""
    report, context, eligibility = fixture()
    result = build(report, context, eligibility)
    public = result.public_summary_json
    assert "private/" not in public and "private_fixture_locator" not in public
    assert "a" * 64 not in public and "b" * 64 not in public
    assert json.loads(public)["product_acceptance"] is False


def test_unknown_components_need_explicit_declaration_not_invented_version() -> None:
    """what_bug_this_catches: missing scanner dependency replaced by a fake unknown-version component."""
    report, context, eligibility = fixture()
    receipt = report["capture_receipts"][0]
    receipt.update(execution_kind="none", status="not_run", executable_sha256=None,
                   scanner_version=None, config_sha256=None, operator_grant_sha256=None,
                   start_receipt_sha256=None, terminal_receipt_sha256=None)
    report["rows"][0].update(status="not_run", introduced_prediction=None, live_eligible=False)
    result = build(report, context, eligibility)
    assert result.manifest is None and "scanner_or_config_component_missing" in result.missing
    supplied = ScannerComponents("C", ComponentVersion(component_id="declared_scanner", kind="scanner",
                name="checkov", version="fixture-only", sha256="b" * 64),
                ComponentVersion(component_id="declared_config", kind="config", name="scanner_config",
                                 version="fixture-config", sha256="e" * 64))
    declared = build(report, replace(context, known_components=(supplied,)), eligibility)
    assert declared.manifest is not None
    assert declared.manifest.invocations[0].kind == "unverified"
    assert declared.manifest.invocations[0].status == "not_run"


def test_execution_start_or_terminal_cannot_be_reused_for_another_attempt() -> None:
    """what_bug_this_catches: one process receipt copied to claim multiple separate scanner attempts."""
    report, context, eligibility = fixture()
    copy = dict(report["capture_receipts"][0], arm="T", scanner_name="trivy", capture_sha256="d" * 64)
    report["capture_receipts"].append(copy)
    with pytest.raises(ValueError, match="reused across attempts"):
        build(report, context, eligibility)


def test_hidden_payload_reference_is_not_read_or_admitted() -> None:
    """what_bug_this_catches: scanner metadata adapter accepts unrelated hidden oracle artifacts."""
    report, context, eligibility = fixture()
    reference = ArtifactRef(artifact_id="unrelated_payload", role="oracle", path="private/oracle.json",
                            sha256="f" * 64, bytes_upper=10)
    with pytest.raises(ValueError, match="no hidden/public payload"):
        build(report, replace(context, artifacts=(reference,)), eligibility)


def test_typed_timeout_preserves_terminal_receipt_and_unknown_billing() -> None:
    """what_bug_this_catches: manifest drops a failed attempt or reports unmeasured scanner cost as zero."""
    report, context, eligibility = fixture()
    report["capture_receipts"][0]["status"] = "timeout"
    report["rows"][0].update(status="timeout", introduced_prediction=None, live_eligible=False)
    result = build(report, context, eligibility)
    assert result.manifest is not None
    attempt = result.manifest.attempts[0]
    assert attempt.status == "timeout" and attempt.terminal_receipt_sha256 == "9" * 64
    assert attempt.billing_known is False and attempt.known_usd is None
    assert result.manifest.eligibility[0].claimed_eligible is False


def test_absent_eligibility_pin_stays_draft_without_creating_approval() -> None:
    """what_bug_this_catches: adapter fabricates an empty approved eligibility manifest to fill schema."""
    report, context, _ = fixture()
    result = adapt_scanner_report(report, expected_report_sha256=report_digest(report), context=context)
    assert result.manifest is None and "eligibility_missing" in result.missing
    assert result.bridge.rows[0].eligibility_ref is None
