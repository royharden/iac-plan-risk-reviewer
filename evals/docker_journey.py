"""Offline container journey: real CLI process, report verification and safe export.

No provider, credential, cloud or database path. Output remains in the stopped
M4-owned container for inspection. Container lifetime/cleanup is operator-owned.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from evals.run_public import run


def cli(*args):
    return subprocess.run(
        [sys.executable, "-m", "iac_review", *map(str, args)],
        capture_output=True,
        text=True,
        timeout=40,
        check=False,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
    )


def main():
    output = Path(tempfile.mkdtemp(prefix="m4-rv2-e2e-"))
    matrix = run()
    rows = []
    for case, expected in (
        ("r1-world-ssh-create", 1),
        ("r1-https-outside-policy", 0),
        ("r1-unknown-prior", 2),
    ):
        plan = ROOT / "fixtures/scenarios/dev" / f"{case}.json"
        bundle = output / case
        inspected = cli("inspect", plan, "--out", bundle)
        verified = cli("verify-report", bundle, "--plan", plan)
        shared = output / f"{case}-share"
        exported = cli("share", bundle, "--plan", plan, "--out", shared)
        payload = (
            b"".join(p.read_bytes() for p in shared.iterdir() if p.is_file())
            if shared.exists()
            else b""
        )
        passed = (
            inspected.returncode == expected
            and verified.returncode == 0
            and exported.returncode == expected
            and shared.is_dir()
            and bool(payload)
            and b"ADDRESS_CANARY_RV2" not in payload
        )
        rows.append(
            {
                "case_id": case,
                "expected_exit": expected,
                "inspect_exit": inspected.returncode,
                "verify_exit": verified.returncode,
                "share_exit": exported.returncode,
                "passed": passed,
            }
        )
    malformed = output / "m4-malformed.json"
    malformed.write_text('{"format_version":', encoding="utf-8")
    rejected = cli("inspect", malformed, "--out", output / "malformed-report")
    rows.append(
        {
            "case_id": "malformed",
            "expected_exit": 3,
            "inspect_exit": rejected.returncode,
            "passed": rejected.returncode == 3 and not (output / "malformed-report").exists(),
        }
    )
    result = {
        "public_matrix": matrix,
        "cli_journeys": rows,
        "output_directory": str(output),
        "passed": not matrix["failed"] and all(r["passed"] for r in rows),
        "product_acceptance": False,
        "hidden_evaluation": "NOT RUN",
        "live_models": "NOT RUN",
    }
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
