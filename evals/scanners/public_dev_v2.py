"""INT-approved synthetic full-plan DEV edition, never genuine producer provenance.

Values projection follows Terraform's known planned-state representation:
https://developer.hashicorp.com/terraform/internals/json-format
Unknown dict fields are omitted; unknown list positions become null. Unchanged
resource_changes retains the distinction from known null and every mask.
No scanner-only enrichment or deleted-resource callback placeholder is produced.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from copy import deepcopy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EDITION = "m4-public-fullplan-dev-v2"
RELATIVE = Path("evals/scanners/fixtures") / EDITION
OLD_MANIFEST = Path("fixtures/expected/dev/rv2-policy-v1.json")
MAX_BYTES = 16 * 1024 * 1024
_OMIT = object()


def canonical(value):
    # No line terminators: Git autocrlf cannot alter a corpus byte digest.
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path):
    if any(p.is_symlink() or p.is_junction() for p in (path, *path.parents)):
        raise ValueError("linked public input refused")
    if not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise ValueError("bounded regular public input required")
    with path.open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("public input grew beyond bound")
    return raw


def _project(value, unknown):
    if unknown is True:
        return _OMIT
    if unknown is False or unknown == {} or unknown == []:
        return deepcopy(value)
    if isinstance(unknown, dict) and isinstance(value, dict):
        projected = {}
        for key, item in value.items():
            result = _project(item, unknown.get(key, False))
            if result is not _OMIT:
                projected[key] = result
        return projected
    if isinstance(unknown, list) and isinstance(value, list):
        if len(unknown) > len(value):
            raise ValueError("unknown array mask exceeds represented positions")
        projected = []
        for index, item in enumerate(value):
            result = _project(item, unknown[index] if index < len(unknown) else False)
            projected.append(None if result is _OMIT else result)
        return projected
    raise ValueError("unknown mask shape cannot define known planned state")


def project_plan(original):
    if "planned_values" in original:
        raise ValueError("original edition unexpectedly has planned_values")
    result = deepcopy(original)
    resources, notes = [], []
    for index, resource in enumerate(original["resource_changes"]):
        change = resource["change"]
        if resource.get("deposed") is not None:
            notes.append({"resource_index": index, "reason": "deposed_identity_not_projected"})
            continue
        if change["actions"] == ["delete"]:
            notes.append({"resource_index": index, "reason": "delete_only_has_no_planned_resource"})
            continue
        if change["after"] is None:
            notes.append({"resource_index": index, "reason": "null_after_has_no_planned_resource"})
            continue
        if not isinstance(change["after"], dict):
            raise TypeError("synthetic planned resource values must be an object")
        values = _project(change["after"], change.get("after_unknown", {}))
        if values is _OMIT:
            values = {}
            notes.append({"resource_index": index, "reason": "unknown_after_root_withheld"})
        planned = {
            key: deepcopy(resource[key])
            for key in ("address", "mode", "type", "name", "provider_name")
        }
        if "index" in resource:
            planned["index"] = deepcopy(resource["index"])
        planned.update(
            schema_version=0,
            values=values,
            sensitive_values=deepcopy(change.get("after_sensitive", {})),
        )
        resources.append(planned)
    result["planned_values"] = {"root_module": {"resources": resources}}
    # A canonical comparison preserves exact JSON types, including bool vs number.
    if canonical({k: v for k, v in result.items() if k != "planned_values"}) != canonical(original):
        raise ValueError("unrelated original plan fields changed")
    return result, notes


def generate(root=ROOT):
    old_raw = read(root / OLD_MANIFEST)
    old = json.loads(old_raw)
    if (
        old.get("split") != "dev"
        or old.get("independent_hidden_oracle") is not False
        or len(old["cases"]) != 24
    ):
        raise ValueError("fixed original public dev edition required")
    inventory, expected, outputs = [], [], {}
    seen = set()
    for case in old["cases"]:
        case_id = case["case_id"]
        relative = f"fixtures/scenarios/dev/{case_id}.json"
        if (
            not re.fullmatch(r"[a-z0-9-]+", case_id)
            or case_id in seen
            or case["path"] != relative
            or case["split"] != "dev"
        ):
            raise ValueError("case escapes original public inventory")
        seen.add(case_id)
        raw = read(root / relative)
        if sha(raw) != case["sha256"]:
            raise ValueError("original frozen raw digest mismatch")
        new, notes = project_plan(json.loads(raw))
        new_raw = canonical(new)
        new_path = RELATIVE / "plans" / f"{case_id}.json"
        outputs[new_path] = new_raw
        inventory.append(
            {
                "case_id": case_id,
                "split": "dev",
                "path": new_path.as_posix(),
                "sha256": sha(new_raw),
                "original_path": relative,
                "original_sha256": sha(raw),
                "scenario_ancestor": case_id,
                "projection_notes": notes,
            }
        )
        expected.append(
            {
                "case_id": case_id,
                "sha256": sha(new_raw),
                **{key: case[key] for key in ("rule_id", "applicability", "outcome")},
            }
        )
    metadata = {
        "schema_version": "m4-public-fullplan-development-v2",
        "edition_id": EDITION,
        "split": "dev",
        "original_commit": "484eb2208f877bb55add90ee5de6080cf08e4e4e",
        "original_inventory_sha256": sha(old_raw),
        "scenario_count": 24,
        "additional_independent_scenarios": 0,
        "synthetic_envelope_only": True,
        "producer_provider_compatibility_tested": False,
        "schema_version_zero_is_synthetic": True,
        "configuration_or_hcl_added": False,
        "cases": inventory,
    }
    outputs[RELATIVE / "expected.json"] = canonical(
        {
            "edition_id": EDITION,
            "split": "dev",
            "label_origin": "original independent public policy table; resource_changes unchanged",
            "hidden_acceptance_oracle": False,
            "cases": expected,
        }
    )
    # Label-free inventory is separate; only raw plans/inventory may enter scanner packaging.
    outputs[RELATIVE / "inventory.json"] = canonical(metadata)
    # Check every collision before publishing anything; no overwrite or cleanup.
    for relative, raw in outputs.items():
        path = root / relative
        if path.exists() and read(path) != raw:
            raise ValueError("immutable v2 output differs")
    for relative, raw in outputs.items():
        path = root / relative
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("xb") as stream:
                stream.write(raw)
    return metadata


def evaluate(root=ROOT):
    from iac_review.ingest import load_plan
    from iac_review.report import build_report
    from iac_review.rules import evaluate as rules

    inventory_raw = read(root / RELATIVE / "inventory.json")
    inventory = json.loads(inventory_raw)
    expected = {
        row["case_id"]: row for row in json.loads(read(root / RELATIVE / "expected.json"))["cases"]
    }
    rows = []
    for item in inventory["cases"]:
        target = expected[item["case_id"]]
        path = root / item["path"]
        if item["path"] != (RELATIVE / "plans" / f"{item['case_id']}.json").as_posix():
            raise ValueError("v2 case path differs from fixed inventory")
        if sha(read(path)) != item["sha256"] or target["sha256"] != item["sha256"]:
            raise ValueError("v2 input/expected hash mismatch")
        plan = load_plan(path)
        report = build_report(plan, rules(plan))
        found = [
            row for row in report.private["evaluations"] if row["rule_id"] == target["rule_id"]
        ]
        correct = len(found) == 1 and all(
            found[0][key] == target[key] for key in ("applicability", "outcome")
        )
        private = "ADDRESS_CANARY_RV2" not in json.dumps(report.shareable)
        rows.append(
            {
                "case_id": item["case_id"],
                "input_sha256": item["sha256"],
                "expected": target["outcome"],
                "actual": found[0]["outcome"] if len(found) == 1 else None,
                "passed": correct and private,
                "privacy_passed": private,
            }
        )
    return {
        "edition_id": EDITION,
        "split": "dev",
        "inventory_sha256": sha(inventory_raw),
        "total": len(rows),
        "passed": sum(row["passed"] for row in rows),
        "failed": sum(not row["passed"] for row in rows),
        "cases": rows,
        "product_acceptance": False,
        "scanner_model_measurements": "NOT RUN",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evaluate", action="store_true")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    result = evaluate() if args.evaluate else generate()
    raw = json.dumps(result, indent=2) + "\n"
    if args.out:
        with args.out.open("x", encoding="utf-8") as stream:
            stream.write(raw)
    print(raw)
    return 1 if args.evaluate and (result["total"] != 24 or result["failed"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
