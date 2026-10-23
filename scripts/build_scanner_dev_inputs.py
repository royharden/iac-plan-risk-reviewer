"""Build public development-only scanner inputs, never labels or measurements.

Source only during Dirty Mode: do not execute this generator until authorized.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from eval.scanners.dev_inputs import write_bundle  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True, help="new local output directory")
    parser.add_argument("--build-sha256", required=True, help="caller-supplied actual build digest")
    args = parser.parse_args()
    try:
        bundle = write_bundle(args.out, build_sha256=args.build_sha256)
        print(json.dumps({"development_only": True, "independent_gold": False,
                          "heldout_eligible": False, "case_count": len(bundle["cases"]),
                          "scanner_execution": False, "compatibility_measured": False}))
        return 0
    except (OSError, ValueError, TypeError):
        print("development input generation refused; any partial directory is preserved", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
