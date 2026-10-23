"""Read-only metadata preflight CLI; never unblinds payloads or executes experiments."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--authority-sha256", required=True)
    parser.add_argument("--semantic-suite-sha256", required=True)
    parser.add_argument("--eligibility-sha256", required=True)
    args = parser.parse_args(argv)
    import sys

    product_root = Path(__file__).resolve().parents[1]
    for path in (product_root, product_root / "src"):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))
    from iac_review.contracts.manifest import RunManifest
    from eval.runner.preflight import PreflightPins, _constant, _object, preflight

    try:
        # A caller cannot point the metadata preflight at an oracle/input file.
        path = args.manifest.absolute()
        expected_manifest = args.root.absolute() / "metadata" / "run-manifest.json"
        if path != expected_manifest:
            raise ValueError("manifest must be the fixed metadata/run-manifest.json path")
        if (any(p.is_symlink() or (hasattr(p, "is_junction") and p.is_junction())
                for p in (path, *path.parents)) or not path.is_file() or path.stat().st_size > 4 * 1024 * 1024):
            raise ValueError("manifest must be bounded regular metadata")
        with path.open("rb") as stream:
            raw = stream.read(4 * 1024 * 1024 + 1)
        if len(raw) > 4 * 1024 * 1024:
            raise ValueError("manifest grew past metadata cap")
        obj = json.loads(raw, object_pairs_hook=_object, parse_constant=_constant)
        manifest = RunManifest.model_validate_json(json.dumps(obj))
        pins = PreflightPins(run_manifest_sha256=args.manifest_sha256,
                             authority_sha256=args.authority_sha256,
                             semantic_suite_sha256=args.semantic_suite_sha256,
                             eligibility_sha256=args.eligibility_sha256)
        result = preflight(args.root, manifest, pins)
        print(json.dumps(result, allow_nan=False))
        return 0 if result["evaluation_status"] == "METADATA_ELIGIBLE" else 2
    except (ValueError, OSError, RecursionError, TypeError) as error:
        print(json.dumps({"metadata_status": "REFUSED", "reason": type(error).__name__,
                          "payloads_opened": 0, "product_acceptance": False}))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
