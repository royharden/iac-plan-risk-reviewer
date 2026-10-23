"""Score imported frozen records; never invokes product code or creates oracle labels."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from eval.runner.scoring import ArmRow, Edition, OracleRow, score  # noqa: E402


def read_json(path: Path) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 16 * 1024 * 1024:
        raise ValueError("evaluation input must be a bounded regular file")
    def pairs(items):
        result = {}
        for name, value in items:
            if name in result:
                raise ValueError("duplicate JSON key")
            result[name] = value
        return result
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=pairs)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--split", choices=("dev", "validation", "heldout"), required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--oracle", type=Path, required=True)
    parser.add_argument("--measurements", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--allow-sealed-exposure", action="store_true",
                        help="requires independent INT approval; opening consumes this edition")
    args = parser.parse_args()
    try:
        edition = Edition.model_validate_json(json.dumps(read_json(args.manifest)))
        if args.split == "heldout":
            if not (edition.independent_custody_attested and edition.inference_exclusion_attested):
                raise ValueError("heldout custody and inference exclusions must be attested")
            if edition.eligible_heldout_explanations < 24:
                raise ValueError("heldout explanation inventory incomplete")
            if edition.state == "sealed" and not args.allow_sealed_exposure:
                raise ValueError("sealed edition requires explicit exposure approval")
            if edition.state == "development":
                raise ValueError("development edition is not heldout evidence")
        # Refuse ambiguous output before any hidden input is opened.
        if args.out.exists():
            raise ValueError("output directory must be new")
        if args.out.parent.is_symlink():
            raise ValueError("symlink output parent forbidden")
        source_hashes = {}
        source_bytes = {}
        for label, path in (("oracle", args.oracle), ("measurements", args.measurements)):
            if path.is_symlink() or not path.is_file() or path.stat().st_size > 16 * 1024 * 1024:
                raise ValueError("evaluation input must be bounded regular file")
            source_bytes[label] = path.read_bytes()
            if len(source_bytes[label]) > 16 * 1024 * 1024:
                raise ValueError("evaluation input grew beyond byte cap")
            source_hashes[label] = hashlib.sha256(source_bytes[label]).hexdigest()
        if source_hashes["oracle"] != edition.oracle_sha256:
            raise ValueError("oracle bytes do not match sealed manifest")
        # Write the irreversible exposure receipt before scorer/label access; no fresh-holdout claim
        # may survive a subsequent parse failure. Custodian separately updates edition ownership.
        args.out.mkdir(parents=True, exist_ok=False)
        exposure = {"edition_id": edition.edition_id, "split": args.split,
                    "state": "consumed_holdout" if args.split == "heldout" else "development",
                    "input_hashes": source_hashes, "build_sha256": edition.frozen_build_sha256}
        (args.out / "exposure.json").write_text(json.dumps(exposure, indent=2), encoding="utf-8")
        oracle = [OracleRow.model_validate_json(line) for line in
                  source_bytes["oracle"].decode("utf-8").splitlines() if line.strip()]
        measured = [ArmRow.model_validate_json(line) for line in
                    source_bytes["measurements"].decode("utf-8").splitlines() if line.strip()]
        if any(row.build_sha256 != edition.frozen_build_sha256 for row in measured):
            raise ValueError("measurement build differs from frozen edition")
        result = score(oracle, measured, args.split) | {"provenance": exposure}
        (args.out / "results.jsonl").write_text(json.dumps(result) + "\n", encoding="utf-8")
        lines = ["# Imported evaluation results", "", "No product acceptance follows this score.",
                 "", "| Arm | Status | Failed rows | Billing fully known |", "|---|---|---|---|"]
        for arm, row in result["arms"].items():
            lines.append(f"| {arm} | {row['measurement_status']} | {len(row['failures'])} | "
                         f"{row['billing_fully_known']} |")
        (args.out / "results.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
        return 0 if all(row["measurement_status"] == "RECORDED"
                        for row in result["arms"].values()) else 2
    except (ValueError, OSError) as error:
        print(f"evaluation refused: {type(error).__name__}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
