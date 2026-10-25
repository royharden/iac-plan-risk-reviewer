"""Public synthetic CLI journeys through a real Python process, without providers."""
import json
import os
import subprocess
import sys
from hashlib import sha256
from pathlib import Path

import pytest

import iac_review

ROOT = Path(__file__).resolve().parents[2]


def invoke(*arguments):
    # Supply only process essentials, never credentials or provider configuration.
    environment = {name: os.environ[name] for name in ("SystemRoot", "PATH", "TEMP", "TMP")
                   if name in os.environ}
    environment.update(PYTHONPATH=str(Path(iac_review.__file__).resolve().parents[1]),
                       PYTHONUTF8="1")
    return subprocess.run([sys.executable, "-m", "iac_review", *map(str, arguments)],
                          cwd=ROOT, env=environment, text=True, encoding="utf-8",
                          capture_output=True, timeout=35, check=False)


@pytest.mark.parametrize("scenario,expected", [
    ("clear", 0), ("risk", 1), ("risk_and_unknown", 2),
    ("risk_and_incomplete", 2), ("risk_and_errored", 2),
    ("unsupported_minor", 2), ("malformed", 3),
])
def test_public_cli_exit_precedence_and_private_shareable_journey(
    core_change, core_plan_file, tmp_path, scenario, expected,
):
    # Catches packaging/entrypoint, output finalization and combined risk/unknown errors.
    entry = core_change(actions=("create",),
                        address='aws_db_instance.synthetic["RV1_ADDRESS_CANARY"]',
                        after={"publicly_accessible": scenario != "clear", "storage_encrypted": True,
                               "tags": {"unmarked": "RV1_TAG_CANARY"}})
    if scenario == "risk_and_unknown":
        entry["change"]["after_unknown"] = {"storage_encrypted": True}
    metadata = {}
    if scenario == "risk_and_incomplete":
        metadata["complete"] = False
    elif scenario == "risk_and_errored":
        metadata["errored"] = True
    elif scenario == "unsupported_minor":
        metadata["format_version"] = "1.99"
    source = core_plan_file([entry], **metadata)
    if scenario == "malformed":
        source.write_bytes(b'{"RV1_PARSE_CANARY":')
    source_digest = sha256(source.read_bytes()).hexdigest()
    output = tmp_path / "private-output"
    result = invoke("inspect", source, "--out", output)
    assert result.returncode == expected, result.stdout + result.stderr
    console = result.stdout + result.stderr
    assert not any(canary in console for canary in
                   ("RV1_ADDRESS_CANARY", "RV1_TAG_CANARY", "RV1_PARSE_CANARY", str(source)))
    assert sha256(source.read_bytes()).hexdigest() == source_digest
    if scenario == "malformed":
        assert "review_aborted" in result.stderr
        assert not (output / "export-state.json").exists()
        return
    marker = json.loads((output / "export-state.json").read_text(encoding="utf-8"))
    assert marker == {"state": "COMPLETE", "exit_code": expected}
    shared = json.loads((output / "shareable.json").read_text(encoding="utf-8"))
    assert shared["summary"]["exit_code"] == expected
    assert shared["summary"]["risk_present"] is (scenario != "clear")
    for name in ("shareable.json", "shareable.html"):
        content = (output / name).read_text(encoding="utf-8")
        assert "RV1_ADDRESS_CANARY" not in content and "RV1_TAG_CANARY" not in content
        assert str(source) not in content
    # Successful export must also survive the separate reader and safe export path.
    verified = invoke("verify-report", output, "--plan", source)
    assert verified.returncode == 0, verified.stdout + verified.stderr
    verification = json.loads(verified.stdout)
    assert verification["source_digest_verified"] is True
    assert verification["run_manifest_bound"] is True
    assert verification["artifacts_verified"] == 5
    share_dir = tmp_path / "safe-export"
    exported = invoke("share", output, "--plan", source, "--out", share_dir)
    assert exported.returncode == expected, exported.stdout + exported.stderr
    for artifact in share_dir.iterdir():
        if artifact.is_file():
            content = artifact.read_text(encoding="utf-8")
            assert "RV1_ADDRESS_CANARY" not in content and "RV1_TAG_CANARY" not in content
            assert str(source) not in content
    # No extra files are written next to the input or outside the chosen outputs.
    assert set(tmp_path.iterdir()) == {source, output, share_dir}


def test_cli_refuses_tampered_source_and_preserves_existing_output(core_plan_file, tmp_path):
    source = core_plan_file()
    output = tmp_path / "bundle"
    assert invoke("inspect", source, "--out", output).returncode == 0
    source.write_text('{"modified": true}', encoding="utf-8")
    assert invoke("verify-report", output, "--plan", source).returncode == 3
    occupied = tmp_path / "occupied"
    occupied.mkdir()
    sentinel = occupied / "user-data.txt"
    sentinel.write_text("PRESERVE_RV1", encoding="utf-8")
    # A valid new input still must not overwrite an occupied directory.
    fresh_source = core_plan_file()
    assert invoke("inspect", fresh_source, "--out", occupied).returncode == 3
    assert sentinel.read_text(encoding="utf-8") == "PRESERVE_RV1"
    assert list(occupied.iterdir()) == [sentinel]
