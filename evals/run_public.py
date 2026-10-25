"""Run only the fixed, public dev inventory. No caller-supplied corpus or split."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


def run():
    from iac_review.ingest import load_plan
    from iac_review.report import build_report
    from iac_review.rules import evaluate

    inventory_path = ROOT / "fixtures/expected/dev/rv2-policy-v1.json"
    inventory = json.loads(inventory_path.read_bytes())
    if inventory["split"] != "dev" or inventory["independent_hidden_oracle"] is not False:
        raise ValueError("public development inventory required")
    rows = []
    for case in inventory["cases"]:
        relative = Path(case["path"])
        path = ROOT / relative
        expected_parent = ROOT / "fixtures/scenarios/dev"
        if (
            case["split"] != "dev"
            or relative.is_absolute()
            or ".." in relative.parts
            or path.parent != expected_parent
            or any(p.is_symlink() for p in (path, *path.parents))
        ):
            raise ValueError("case escapes fixed public development root")
        if hashlib.sha256(path.read_bytes()).hexdigest() != case["sha256"]:
            raise ValueError("public fixture digest mismatch")
        try:
            plan = load_plan(path)
            report = build_report(plan, evaluate(plan))
            matching = [r for r in report.private["evaluations"] if r["rule_id"] == case["rule_id"]]
            if len(matching) != 1:
                raise ValueError("missing/duplicate target evaluation")
            actual = matching[0]
            correct = all(actual[k] == case[k] for k in ("applicability", "outcome"))
            determinate = actual["outcome"] in {"introduced_risk", "unchanged_risk", "clear"}
            evidence = not determinate or (
                bool(actual["facts"])
                and all(fact["resolution"] == "resolved" for fact in actual["facts"])
                and not report.private["evidence_failures"]
            )
            shared = json.dumps(report.shareable)
            privacy = "ADDRESS_CANARY_RV2" not in shared and "resource_changes/" not in shared
            rows.append(
                {
                    "case_id": case["case_id"],
                    "rule_id": case["rule_id"],
                    "expected": case["outcome"],
                    "actual": actual["outcome"],
                    "passed": correct and privacy and evidence,
                    "evidence_passed": evidence,
                    "privacy_passed": privacy,
                    "exit_code": report.exit_code,
                }
            )
        except (ValueError, OSError, TypeError, KeyError, IndexError, RuntimeError) as exc:
            rows.append(
                {
                    "case_id": case["case_id"],
                    "rule_id": case["rule_id"],
                    "passed": False,
                    "error": type(exc).__name__,
                }
            )
    return {
        "schema_version": 1,
        "split": "dev",
        "measurement": "executed-public-development",
        "inventory_sha256": hashlib.sha256(inventory_path.read_bytes()).hexdigest(),
        "product_acceptance": False,
        "hidden_evaluation": "NOT RUN",
        "model_scanner_comparison": "NOT MEASURED",
        "cases": rows,
        "total": len(rows),
        "passed": sum(row["passed"] for row in rows),
        "failed": sum(not row["passed"] for row in rows),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, help="New JSON result file; never overwrite")
    args = parser.parse_args(argv)
    result = run()
    raw = json.dumps(result, indent=2) + "\n"
    if args.out:
        with args.out.open("x", encoding="utf-8") as stream:
            stream.write(raw)
    print(raw)
    return 0 if result["total"] and not result["failed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
