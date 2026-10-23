"""Explicit scanner comparison driver; defaults to no runner and incomplete rows.

Future fake-only runs are plumbing, never live evidence. Runtime activation must
be authorized after Dirty Mode closes; construction did not execute this script.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from eval.scanners.driver import compare, load_manifest  # noqa: E402
from eval.scanners.runner import BoundedSubprocessRunner  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--mode", choices=("pending", "fake-only", "live"), default="pending")
    parser.add_argument("--authorize-runtime", action="store_true",
                        help="later authorized activation only; forbidden during Dirty Mode")
    parser.add_argument("--sandbox-receipt", type=Path,
                        help="operator-owned confinement receipt required for live mode")
    parser.add_argument("--out", type=Path, required=True,
                        help="new run directory directly under product results/")
    args = parser.parse_args()
    try:
        output = args.out.absolute()
        product = Path(__file__).resolve().parents[1]
        expected_parent = product / "results"
        if (output.exists() or output.is_symlink() or output.parent.is_symlink()
                or output.parent.resolve() != expected_parent.resolve()
                or output.name in {"", ".", ".."}):
            raise ValueError("new exclusive product results directory required")
        if args.mode != "live" and (args.authorize_runtime or args.sandbox_receipt):
            raise ValueError("runtime switches are invalid outside explicit live mode")
        manifest = load_manifest(args.manifest)
        runner = None
        sandbox_sha256 = None
        if args.mode == "live":
            if not args.authorize_runtime or args.sandbox_receipt is None:
                raise ValueError("runtime and operator confinement authorization required")
            # A receipt records operator responsibility; it does not create a sandbox.
            from eval.scanners.runner import bounded_read, digest, strict_json
            raw = bounded_read(args.sandbox_receipt, 64 * 1024)
            receipt = strict_json(raw)
            if (not isinstance(receipt, dict)
                    or receipt.get("schema_version") != "m4-scanner-sandbox-v1"
                    or receipt.get("dirty_mode_closed") is not True
                    or receipt.get("runtime_authorized") is not True
                    or receipt.get("network_denied") is not True
                    or receipt.get("descendants_confined") is not True
                    or receipt.get("private_run_directory") is not True
                    or receipt.get("build_sha256") != manifest.get("build_sha256")):
                raise ValueError("missing current sandbox/mode attestation")
            sandbox_sha256 = digest(raw)
            runner = BoundedSubprocessRunner(activation_authorized=True)
        report = compare(manifest, runner=runner, fake_only=args.mode == "fake-only")
        report["activation_mode"] = args.mode
        report["sandbox_receipt_sha256"] = sandbox_sha256
        # Exclusive creation before writing; never overwrite a prior run. No raw
        # plan, output or private address map is copied into these records.
        output.mkdir(parents=True, exist_ok=False)
        with (output / "scanner-comparison.json").open("x", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2, allow_nan=False)
            stream.write("\n")
        with (output / "scanner-rows.jsonl").open("x", encoding="utf-8") as stream:
            for row in report["rows"]:
                stream.write(json.dumps(row, allow_nan=False) + "\n")
        print(json.dumps({"measurement_status": report["measurement_status"],
                          "row_count": len(report["rows"]), "fake_only": report["fake_only"],
                          "source_enrichment": False, "product_acceptance": False}))
        return 0 if report["measurement_status"] == "RECORDED" else 2
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        # Do not echo input paths, scanner stderr or raw plan values into logs.
        print("scanner comparison refused: invalid or unavailable inputs", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
