"""F3: CLI delegates its deadline and cannot fail a post-finalization clock check.

Regression source only; not executed during Dirty Mode.
"""
from iac_review import cli, report, rules
from iac_review.contracts import ReviewReport
from iac_review.ingest import InputError


def test_cli_passes_whole_review_deadline_and_returns_finalized_exit(monkeypatch, capsys):
    clock = [1.0]
    monkeypatch.setattr(cli.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(cli, "load_plan", lambda _path: None)
    monkeypatch.setattr(cli, "verify_unchanged", lambda _plan: None)
    monkeypatch.setattr(rules, "evaluate", lambda _plan: ())
    monkeypatch.setattr(report, "build_report", lambda *_args, **_kwargs:
                        ReviewReport(private={}, shareable={}, exit_code=1))
    seen = []

    def finalize(_report, _out, *, deadline):
        seen.append(deadline)
        clock[0] = deadline + 1

    monkeypatch.setattr(report, "write_report", finalize)
    assert cli.main(["inspect", "synthetic.json", "--out", "unused"]) == 1
    assert seen == [1.0 + cli.MAX_SECONDS]
    assert "review_exported" in capsys.readouterr().out


def test_cli_export_deadline_failure_returns_abort_without_success_message(monkeypatch, capsys):
    monkeypatch.setattr(cli, "load_plan", lambda _path: None)
    monkeypatch.setattr(cli, "verify_unchanged", lambda _plan: None)
    monkeypatch.setattr(rules, "evaluate", lambda _plan: ())
    monkeypatch.setattr(report, "build_report", lambda *_args, **_kwargs:
                        ReviewReport(private={}, shareable={}, exit_code=0))

    def fail_export(*_args, **_kwargs):
        raise InputError("review_time_limit")

    monkeypatch.setattr(report, "write_report", fail_export)
    assert cli.main(["inspect", "synthetic.json", "--out", "unused"]) == 3
    output = capsys.readouterr()
    assert "review_exported" not in output.out
    assert "review_aborted code=review_time_limit" in output.err
