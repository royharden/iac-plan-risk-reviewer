"""Describe/import model-arm obligations; performs no provider calls."""
import argparse
import json


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True,
                        help="sealed edition reference; source construction does not execute it")
    parser.parse_args()
    print(json.dumps({"L": "NOT MEASURED", "P": "NOT MEASURED", "M": "NOT MEASURED",
                      "reason": "Live transport/budget/provenance and independent assessors pending.",
                      "offline_protocol": "eval.model.protocol; imported records: scripts/eval.py",
                      "calls_attempted": False, "product_acceptance": False}, indent=2))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
