"""State scanner obligations without downloading or executing third-party tools."""
import argparse
import json


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.parse_args()
    print(json.dumps({"C": "NOT MEASURED", "C-custom": "NOT MEASURED", "T": "NOT MEASURED",
                      "reason": "Scanner binary/version/mapping and custom-policy activation pending.",
                      "artifact_contract": "eval.scanners.artifacts",
                      "processes_started": False, "product_acceptance": False}, indent=2))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
