"""Public synthetic CLI-only journeys; no provider/scanner/holdout access."""

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.fixture
def tmp_path(request):
    # Retained ordinary directories; pytest's standard fixture attempts current
    # symlink housekeeping, which this run prohibits even for nonexistent paths.
    root = Path(os.environ["R04_TEST_OUTPUT"])
    path = root / ("case-" + hashlib.sha256(request.node.nodeid.encode()).hexdigest()[:16])
    path.mkdir(exist_ok=False)
    return path


def invoke(*args):
    import iac_review

    environment = {
        key: os.environ[key] for key in ("SystemRoot", "PATH", "TEMP", "TMP") if key in os.environ
    }
    environment.update(
        PYTHONPATH=str(Path(iac_review.__file__).resolve().parents[1]),
        PYTHONUTF8="1",
        PYTHONDONTWRITEBYTECODE="1",
    )
    return subprocess.run(
        [sys.executable, "-B", "-m", "iac_review", *map(str, args)],
        env=environment,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
        check=False,
    )


def plan(case):
    resource = {
        "address": 'aws_db_instance.example["R04_ADDRESS_CANARY"]',
        "mode": "managed",
        "type": "aws_db_instance",
        "name": "example",
        "provider_name": "registry.terraform.io/hashicorp/aws",
        "change": {
            "actions": ["create"],
            "before": None,
            "after": {
                "publicly_accessible": case != "clear",
                "storage_encrypted": True,
                "tags": {"unmarked": "R04_TAG_CANARY"},
            },
        },
    }
    value = {
        "format_version": "1.2",
        "terraform_version": "1.9.0",
        "complete": True,
        "errored": False,
        "resource_changes": [resource],
    }
    if case == "unknown":
        resource["change"]["after_unknown"] = {"storage_encrypted": True}
    elif case == "incomplete":
        value["complete"] = False
    elif case == "errored":
        value["errored"] = True
    elif case == "minor":
        value["format_version"] = "1.99"
    return value


@pytest.mark.parametrize(
    "case,expected",
    [
        ("clear", 0),
        ("risk", 1),
        ("unknown", 2),
        ("incomplete", 2),
        ("errored", 2),
        ("minor", 2),
        ("malformed", 3),
    ],
)
def test_exit_privacy_verify_export(tmp_path, case, expected):
    # Regression: risk plus unknown must remain exit2 and preserve risk_present.
    source = tmp_path / "public-synthetic.json"
    source.write_text(
        '{"R04_PARSE_CANARY":' if case == "malformed" else json.dumps(plan(case)), encoding="utf-8"
    )
    original = source.read_bytes()
    output = tmp_path / "private-report"
    result = invoke("inspect", source, "--out", output)
    assert result.returncode == expected, result.stdout + result.stderr
    assert source.read_bytes() == original
    for canary in ("R04_ADDRESS_CANARY", "R04_TAG_CANARY", "R04_PARSE_CANARY", str(source)):
        assert canary not in result.stdout + result.stderr
    if case == "malformed":
        assert not (output / "export-state.json").exists()
        return
    shared = json.loads((output / "shareable.json").read_text(encoding="utf-8"))
    assert shared["summary"]["exit_code"] == expected
    assert shared["summary"]["risk_present"] is (case != "clear")
    for filename in ("shareable.json", "shareable.html"):
        text = (output / filename).read_text(encoding="utf-8")
        assert "R04_ADDRESS_CANARY" not in text and "R04_TAG_CANARY" not in text
        assert str(source) not in text
    verification = invoke("verify-report", output, "--plan", source)
    assert verification.returncode == 0, verification.stderr
    verified = json.loads(verification.stdout)
    assert verified["source_digest_verified"] is True
    assert verified["run_manifest_bound"] is True
    assert verified["artifacts_verified"] == 5
    exported = tmp_path / "safe-export"
    export = invoke("share", output, "--plan", source, "--out", exported)
    assert export.returncode == expected, export.stdout + export.stderr
    files = list(exported.iterdir())
    assert files
    assert all("R04_ADDRESS_CANARY" not in path.read_text(encoding="utf-8") for path in files)
    # A changed source never verifies as the original report.
    source.write_bytes(original + b" ")
    refused = invoke("verify-report", output, "--plan", source)
    assert refused.returncode != 0
    assert hashlib.sha256(source.read_bytes()).digest() != hashlib.sha256(original).digest()
