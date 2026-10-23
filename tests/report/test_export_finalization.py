"""F3: export faults/deadlines must leave ABORTED, never a completed bundle.

Regression source only; not executed during Dirty Mode.
"""
import json
from pathlib import Path

import pytest

from iac_review import report as reporting
from iac_review.contracts import ReviewReport
from iac_review.ingest import InputError


def synthetic_report():
    return ReviewReport(
        private={"run_id": "a" * 32, "plan": {"sha256": "b" * 64}},
        shareable={"projection": "shareable"}, exit_code=0,
    )


@pytest.mark.parametrize("fault", ["deadline", "write", "finalize"])
def test_failed_export_removes_its_reports_and_keeps_aborted_marker(tmp_path, monkeypatch, fault):
    out = tmp_path / "bundle"
    clock = [0.0]
    monkeypatch.setattr(reporting, "monotonic", lambda: clock[0])

    def render(_projection):
        if fault == "deadline":
            clock[0] = 11.0
        return b"synthetic HTML"

    monkeypatch.setattr(reporting, "_html", render)
    real_open = Path.open

    def open_with_fault(path, *args, **kwargs):
        if fault == "write" and path.parent == out and path.name == "shareable.json":
            raise OSError("synthetic publication failure")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", open_with_fault)
    if fault == "finalize":
        def fail_replace(*_args):
            raise OSError("synthetic finalization failure")
        monkeypatch.setattr(reporting.os, "replace", fail_replace)
    with pytest.raises(InputError if fault == "deadline" else OSError):
        reporting.write_report(synthetic_report(), out, deadline=10.0)
    assert json.loads((out / "export-state.json").read_text())["state"] == "ABORTED"
    assert sorted(path.name for path in out.iterdir()) == ["export-state.json"]


def test_two_argument_writer_keeps_demo_compatibility(tmp_path, monkeypatch):
    monkeypatch.setattr(reporting, "_html", lambda _projection: b"synthetic HTML")
    out = tmp_path / "bundle"
    reporting.write_report(synthetic_report(), out)
    assert json.loads((out / "export-state.json").read_text())["state"] == "COMPLETE"
    assert (out / "private.json").is_file()
    assert (out / "shareable.html").is_file()
    assert not (out / ".pending").exists()
