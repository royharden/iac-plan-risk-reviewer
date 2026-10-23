"""Public canaries/exit regressions; synthetic development data, not hidden gold.

Source only; later activation must exercise actual export files.
"""
import json

import pytest

from iac_review.ingest import load_plan
from iac_review.report import build_report, write_report
from iac_review.rules import evaluate


def test_private_address_exception_and_masked_value_shareable_boundary(core_change, core_plan_file, tmp_path):
    address = 'aws_db_instance.synthetic["ADDRESS_CANARY<script>alert(1)</script>"]'
    entry = core_change(
        actions=("create",), address=address,
        after={"publicly_accessible": True, "storage_encrypted": "MARKED_VALUE_CANARY",
               "tags": {"name": "UNMARKED_TAG_CANARY"}},
        change_fields={"after_sensitive": {"storage_encrypted": True}},
    )
    path = core_plan_file([entry])
    plan = load_plan(path)
    result = build_report(plan, evaluate(plan))
    private = json.dumps(result.private)
    shared = json.dumps(result.shareable)
    assert "ADDRESS_CANARY" in private  # Documented exact-location exception.
    assert "ADDRESS_CANARY" not in shared and address not in shared
    for text in (private, shared):
        assert "MARKED_VALUE_CANARY" not in text and "UNMARKED_TAG_CANARY" not in text
        assert path.name not in text
    assert "pointer" not in shared and "plan_sha256" not in shared
    assert result.shareable["summary"]["risk_present"] is True
    assert result.exit_code == 2  # A known R2 finding coexists with masked R3.
    out = tmp_path / "reports"
    write_report(result, out)
    html = (out / "private.html").read_text(encoding="utf-8")
    assert "&lt;script&gt;" in html and "<script>" not in html
    assert "MARKED_VALUE_CANARY" not in html
    assert json.loads((out / "export-state.json").read_text())["state"] == "COMPLETE"
    assert not any(file.read_bytes() == path.read_bytes() for file in out.iterdir() if file.is_file())


@pytest.mark.parametrize(("metadata", "fail_on", "expected", "threshold"), [
    ({}, 3, 1, True),
    ({"complete": False}, 3, 2, True),
    ({"errored": True}, 3, 2, True),
    ({"format_version": "1.99"}, 3, 2, True),
    ({}, 4, 0, False),
])
def test_coverage_beats_threshold_and_lower_severity_risk_stays_visible(
    core_change, core_plan_file, metadata, fail_on, expected, threshold,
):
    entry = core_change(actions=("create",), after={"publicly_accessible": True, "storage_encrypted": True})
    plan = load_plan(core_plan_file([entry], **metadata))
    result = build_report(plan, evaluate(plan), fail_on=fail_on)
    assert result.exit_code == expected
    assert result.shareable["summary"]["risk_present"] is True
    assert result.shareable["summary"]["threshold_risk_present"] is threshold
    assert any(row["rule_id"] == "R2" and row["outcome"] == "introduced_risk"
               for row in result.shareable["evaluations"])


def test_empty_complete_is_no_changes_but_noop_risk_is_still_risk(core_change, core_plan_file):
    empty = load_plan(core_plan_file())
    result = build_report(empty, evaluate(empty))
    assert result.exit_code == 0 and result.shareable["summary"]["status"] == "no_changes"
    values = {"publicly_accessible": True, "storage_encrypted": True}
    plan = load_plan(core_plan_file([core_change(actions=("no-op",), before=values, after=values)]))
    result = build_report(plan, evaluate(plan))
    assert result.exit_code == 1
    assert result.shareable["summary"]["unchanged_risks"] == 1
    assert result.shareable["summary"]["status"] != "no_changes"
