"""Report consumer must join a closed evidence transaction by ordered occurrence."""
from uuid import uuid4

import pytest

from iac_review import cli
from iac_review import report as reporting
from iac_review.ingest import SourceChangedError


@pytest.mark.parametrize("corruption", ["short", "reordered", "foreign_id", "duplicate_result"])
def test_bad_batch_join_aborts_before_any_export(core_change, core_plan_file, tmp_path,
                                                monkeypatch, corruption):
    source = core_plan_file([core_change(actions=("create",),
        after={"publicly_accessible": True, "storage_encrypted": True})])
    original_batch = reporting.resolve_many
    seen = []

    def corrupted(plan, refs, *, deadline=None):
        assert deadline is not None
        seen.append(tuple(ref.fact_id for ref in refs))
        results = original_batch(plan, refs, deadline=deadline)
        assert len(results) > 1
        if corruption == "short":
            return results[:-1]
        if corruption == "reordered":
            return tuple(reversed(results))
        if corruption == "foreign_id":
            wrong = results[0].ref.model_copy(update={"fact_id": uuid4().hex})
            return (results[0].model_copy(update={"ref": wrong}), *results[1:])
        return (results[0], results[0], *results[2:])

    monkeypatch.setattr(reporting, "resolve_many", corrupted)
    out = tmp_path / "must-not-publish"
    assert cli.main(["inspect", str(source), "--out", str(out)]) == 3
    assert len(seen) == 1 and not out.exists()


def test_persistent_mutation_after_batch_closure_aborts_before_writer(
    core_change, core_plan_file, tmp_path, monkeypatch,
):
    source = core_plan_file([core_change(actions=("create",),
        after={"publicly_accessible": True, "storage_encrypted": True})])
    original_batch = reporting.resolve_many

    def change_after_closure(plan, refs, *, deadline=None):
        results = original_batch(plan, refs, deadline=deadline)
        source.write_bytes(source.read_bytes() + b" ")
        return results

    monkeypatch.setattr(reporting, "resolve_many", change_after_closure)
    out = tmp_path / "must-not-publish"
    assert cli.main(["inspect", str(source), "--out", str(out)]) == 3
    assert not out.exists()


def test_batch_read_failure_cannot_produce_a_success_marker(core_change, core_plan_file,
                                                           tmp_path, monkeypatch, capsys):
    source = core_plan_file([core_change(actions=("create",),
        after={"publicly_accessible": True, "storage_encrypted": True})])

    def failed(*_args, **_kwargs):
        raise SourceChangedError("source_digest_changed")

    monkeypatch.setattr(reporting, "resolve_many", failed)
    out = tmp_path / "must-not-publish"
    assert cli.main(["inspect", str(source), "--out", str(out)]) == 3
    console = capsys.readouterr()
    assert "review_exported" not in console.out and "source_digest_changed" in console.err
    assert not out.exists()
