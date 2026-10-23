"""Export scanner capability declarations only; no scanner probe or execution."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from eval.scanners.artifacts import Mapping  # noqa: E402
from eval.scanners.capabilities import inventory  # noqa: E402
from eval.scanners.runner import bounded_read, strict_json  # noqa: E402


def main() -> int:
    product = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy-contract", type=Path,
                        default=product / "policies" / "checkov-custom" / "mapping.json")
    parser.add_argument("--mappings", type=Path,
                        help="optional JSON array of declared strict artifacts.Mapping records")
    parser.add_argument("--out", type=Path, help="optional new metadata JSON file; default stdout")
    args = parser.parse_args()
    try:
        contract = strict_json(bounded_read(args.policy_contract, 256 * 1024))
        mappings = ()
        if args.mappings is not None:
            value = strict_json(bounded_read(args.mappings, 256 * 1024))
            if not isinstance(value, list) or len(value) > 12:
                raise ValueError("bounded mapping array required")
            mappings = tuple(Mapping.model_validate_json(json.dumps(row)) for row in value)
        report = inventory(contract, mappings)
        encoded = json.dumps(report, indent=2, allow_nan=False) + "\n"
        if args.out is None:
            print(encoded, end="")
        else:
            if args.out.is_symlink() or args.out.parent.is_symlink():
                raise ValueError("symlink metadata output forbidden")
            with args.out.open("x", encoding="utf-8") as stream:
                stream.write(encoded)
        # Exit zero means metadata was serialized, never scanner compatibility.
        return 0
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        print("scanner inventory refused: invalid capability metadata", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
