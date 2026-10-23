"""CLI return/privacy boundaries over synthetic local files; source only."""
import json

import pytest

from iac_review import cli


@pytest.mark.parametrize(("scenario", "expected"), [
    ("clear", 0), ("risk", 1), ("unsupported", 2), ("malformed", 3),
])
def test_inspect_exit_precedence_and_no_raw_input_in_console(
    core_change, core_plan_file, tmp_path, capsys, scenario, expected,
):
    entry = core_change(
        actions=("create",), address='aws_db_instance.synthetic["CONSOLE_CANARY"]',
        after={"publicly_accessible": scenario != "clear", "storage_encrypted": True},
    )
    metadata = {"format_version": "1.99"} if scenario == "unsupported" else {}
    path = core_plan_file([entry], **metadata)
    if scenario == "malformed":
        path.write_bytes(b'{"CONSOLE_CANARY":')
    out = tmp_path / "report"
    assert cli.main(["inspect", str(path), "--out", str(out)]) == expected
    output = capsys.readouterr()
    assert "CONSOLE_CANARY" not in output.out + output.err
    assert str(path) not in output.out + output.err
    if scenario == "malformed":
        assert "review_aborted" in output.err and not (out / "shareable.json").exists()
    else:
        marker = json.loads((out / "export-state.json").read_text())
        assert marker["state"] == "COMPLETE" and marker["exit_code"] == expected
        shared = json.loads((out / "shareable.json").read_text())
        assert shared["summary"]["exit_code"] == expected
        if scenario == "unsupported":
            assert shared["summary"]["risk_present"] is True


def test_usage_error_is_three_not_coverage_two(capsys):
    assert cli.main(["inspect", "synthetic.json"]) == 3
    assert "required" in capsys.readouterr().err


def test_existing_output_is_preserved_and_not_overwritten(core_plan_file, tmp_path, capsys):
    path = core_plan_file()
    out = tmp_path / "occupied"
    out.mkdir()
    sentinel = out / "user-data.txt"
    sentinel.write_text("PREEXISTING_CANARY", encoding="utf-8")
    assert cli.main(["inspect", str(path), "--out", str(out)]) == 3
    assert sentinel.read_text() == "PREEXISTING_CANARY"
    assert sorted(file.name for file in out.iterdir()) == ["user-data.txt"]
    assert "PREEXISTING_CANARY" not in capsys.readouterr().err
