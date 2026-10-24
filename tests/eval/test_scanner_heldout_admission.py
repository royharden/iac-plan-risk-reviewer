"""Heldout scanner admission regression SOURCE (authored under Dirty Mode, NOT run).

Artificial empty public reports only; no heldout input, scanner output or oracle.
"""
import hashlib
import json

import pytest

from iac_review.contracts.manifest import CaseBinding
from eval.runner.scoring import EligibilityManifest, record_digest
from eval.scanners.run_manifest import ScannerRunContext, adapt_scanner_report
from eval.scanners.runner import manifest_digest
from eval.scanners.scoring_bridge import _canonical

PIN = "a" * 64
ACCESS = "c" * 64


def guarded_manifest(access=ACCESS):
    return {"schema_version": "m4-scanner-run-v1", "input_scope": "heldout", "guarded_input": True,
            "access_authorization_sha256": access, "build_sha256": PIN,
            "cases": [{"case_id": "case_one", "plan_sha256": PIN, "resources": []}], "arms": {}}


def report(scope="heldout", manifest=None):
    value = {"schema_version": "m4-scanner-comparison-v1", "input_scope": scope, "source_enrichment": False,
             "fake_only": False, "product_acceptance": False, "build_sha256": PIN, "rows": [],
             "capture_receipts": [], "manifest_sha256": manifest_digest(manifest or guarded_manifest())}
    return value, hashlib.sha256(_canonical(value)).hexdigest()


def eligibility():
    manifest = EligibilityManifest(edition_id="fixture_edition", rows=())
    return manifest, record_digest(manifest)


def context(split="heldout", **extra):
    binding = CaseBinding(case_id="case_one", split=split, configuration_id="config", family_id="family",
                          mutation_lineage="mutation", raw_source_sha256=PIN)
    values = {"edition_state": "sealed", "heldout_access_authorization_sha256": ACCESS,
              "heldout_scanner_manifest_json": json.dumps(guarded_manifest())}
    values.update(extra)
    return ScannerRunContext("fixture_run", "fixture_edition", policy_sha256=PIN, authority_sha256=PIN,
                             semantic_suite_sha256=PIN, cases=(binding,), **values)


def adapt(value, pin, ctx, with_eligibility=True):
    manifest, manifest_pin = eligibility() if with_eligibility else (None, None)
    return adapt_scanner_report(value, expected_report_sha256=pin, context=ctx,
                                eligibility=manifest, expected_eligibility_sha256=manifest_pin)


def test_heldout_report_without_pinned_eligibility_is_refused():
    """what_bug_this_catches: heldout scanner rows enter typed metadata with no execution eligibility (A1)."""
    value, pin = report()
    with pytest.raises(ValueError, match="pinned execution eligibility"):
        adapt(value, pin, context(), with_eligibility=False)


@pytest.mark.parametrize("missing", ["heldout_access_authorization_sha256", "heldout_scanner_manifest_json"])
def test_heldout_report_without_guarded_manifest_or_access_pin_is_refused(missing):
    """what_bug_this_catches: heldout admission proceeds without the exact guarded manifest/access binding."""
    value, pin = report()
    with pytest.raises(ValueError, match="admission pins missing"):
        adapt(value, pin, context(**{missing: None}))


def test_heldout_report_from_other_manifest_or_access_pin_is_refused():
    """what_bug_this_catches: a report scanned under another manifest/permission is admitted under this one."""
    other = guarded_manifest(access="d" * 64)
    value, pin = report(manifest=other)
    with pytest.raises(ValueError, match="guarded manifest/access pin"):
        adapt(value, pin, context())
    value, pin = report()
    with pytest.raises(ValueError, match="guarded manifest/access pin"):
        adapt(value, pin, context(heldout_access_authorization_sha256="d" * 64))


def test_heldout_report_needs_heldout_edition_state_and_split():
    """what_bug_this_catches: heldout scanner metadata is relabelled as development or dev split."""
    value, pin = report()
    with pytest.raises(ValueError, match="admission pins missing"):
        adapt(value, pin, context(edition_state="development"))
    with pytest.raises(ValueError, match="report scope"):
        adapt(value, pin, context(split="dev"))


def test_development_report_refuses_heldout_context_and_stays_dev():
    """what_bug_this_catches: development admission silently accepts or emits heldout metadata."""
    value, pin = report(scope="development_synthetic")
    with pytest.raises(ValueError, match="cannot carry heldout context"):
        adapt(value, pin, context(split="dev"))
    result = adapt(value, pin, context(split="dev", edition_state="development",
                                       heldout_access_authorization_sha256=None,
                                       heldout_scanner_manifest_json=None))
    assert result.manifest is None or result.manifest.split == "dev"


def test_exact_heldout_binding_admits_metadata_with_heldout_split_only():
    """what_bug_this_catches: a fully pinned heldout report is still refused, or emitted as dev metadata."""
    value, pin = report()
    result = adapt(value, pin, context())
    assert "case_without_capture" in result.missing  # Empty fixture: nothing measured, nothing invented.
    assert result.manifest is None or (result.manifest.split == "heldout"
                                       and result.manifest.edition_state == "sealed")
