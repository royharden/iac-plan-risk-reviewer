"""Future explicit local consumed-edition preparation; no work at import time."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    for name in ("selection", "manifest", "authority", "semantic-suite", "eligibility", "release", "completion"):
        parser.add_argument("--" + name + "-sha256", required=True)
    args = parser.parse_args(argv)
    import sys
    product_root = Path(__file__).resolve().parents[1]
    for path in (product_root, product_root / "src"):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))
    from iac_review.contracts.manifest import RunManifest
    from eval.runner.bundle import AssemblySelection, ReleaseAuthorization, _check_root, read_control
    from eval.runner.edition_release import CompletionReference, prepare_consumed_edition
    from eval.runner.preflight import PreflightPins, _constant, _object

    try:
        # Fixed control metadata only; no arbitrary file option or discovery.
        path = _check_root(args.root, exists=True) / "metadata" / "edition-completion.json"
        if (any(p.is_symlink() or (hasattr(p, "is_junction") and p.is_junction())
                for p in (path, *path.parents))
                or not path.is_file() or path.stat().st_size > 4 * 1024 * 1024):
            raise ValueError("bounded completion control metadata required")
        with path.open("rb") as stream:
            raw = stream.read(4 * 1024 * 1024 + 1)
        if len(raw) > 4 * 1024 * 1024:
            raise ValueError("completion metadata exceeded cap")
        completion = CompletionReference.model_validate_json(json.dumps(
            json.loads(raw, object_pairs_hook=_object, parse_constant=_constant)))
        manifest = RunManifest.model_validate_json(json.dumps(read_control(args.root, "run-manifest.json")))
        selection = AssemblySelection.model_validate_json(json.dumps(read_control(args.root, "assembly-selection.json")))
        release = ReleaseAuthorization.model_validate_json(json.dumps(read_control(args.root, "release-authorization.json")))
        pins = PreflightPins(run_manifest_sha256=args.manifest_sha256,
                             authority_sha256=args.authority_sha256,
                             semantic_suite_sha256=args.semantic_suite_sha256,
                             eligibility_sha256=args.eligibility_sha256)
        result = prepare_consumed_edition(args.root, args.out, manifest, pins, selection,
                                          args.selection_sha256, release, args.release_sha256,
                                          completion, args.completion_sha256)
        try:
            print(json.dumps(result, sort_keys=True))
        except (OSError, KeyboardInterrupt):
            pass  # COMPLETE boundary already committed; console is not publication.
        return 0
    except (ValueError, OSError, TypeError, RecursionError, KeyError, StopIteration):
        print('{"state":"REFUSED","product_acceptance":false}')
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
