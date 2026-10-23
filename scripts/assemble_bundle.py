"""Private bounded assembly CLI source; default metadata only, no execution on import."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--selection-sha256", required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--authority-sha256", required=True)
    parser.add_argument("--semantic-suite-sha256", required=True)
    parser.add_argument("--eligibility-sha256", required=True)
    parser.add_argument("--include-consumed-synthetic-payloads", action="store_true")
    parser.add_argument("--release-sha256")
    args = parser.parse_args(argv)
    import sys

    product_root = Path(__file__).resolve().parents[1]
    for path in (product_root, product_root / "src"):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))
    from iac_review.contracts.manifest import RunManifest
    from eval.runner.bundle import AssemblySelection, ReleaseAuthorization, assemble, read_control
    from eval.runner.preflight import PreflightPins

    try:
        if bool(args.release_sha256) != args.include_consumed_synthetic_payloads:
            raise ValueError("payload flag and externally pinned release authorization required together")
        manifest = RunManifest.model_validate_json(json.dumps(read_control(args.root, "run-manifest.json")))
        selection = AssemblySelection.model_validate_json(json.dumps(read_control(args.root, "assembly-selection.json")))
        release = ReleaseAuthorization.model_validate_json(json.dumps(read_control(args.root, "release-authorization.json"))) \
            if args.include_consumed_synthetic_payloads else None
        pins = PreflightPins(run_manifest_sha256=args.manifest_sha256,
                             authority_sha256=args.authority_sha256,
                             semantic_suite_sha256=args.semantic_suite_sha256,
                             eligibility_sha256=args.eligibility_sha256)
        receipt = assemble(args.root, args.out, manifest, pins, selection, args.selection_sha256,
                           include_consumed_payloads=args.include_consumed_synthetic_payloads,
                           authorization=release, expected_authorization_sha256=args.release_sha256)
        print(json.dumps({"state": "COMPLETE", "mode": receipt.mode,
                          "copied_files": len(receipt.copied), "payloads_included": receipt.payloads_included,
                          "product_acceptance": False, "authorization_authenticated": False}))
        return 0
    except (ValueError, OSError, TypeError, RecursionError, StopIteration) as error:
        print(json.dumps({"state": "REFUSED", "reason": type(error).__name__, "product_acceptance": False}))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
