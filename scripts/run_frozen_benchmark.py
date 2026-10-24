"""Future fixed frozen journey SOURCE; bare CLI flags cannot activate runtime objects."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from eval.runner.custody import metadata_digest  # noqa: E402
from eval.runner.frozen_run import FrozenRuntime, FrozenRunPins, run_frozen  # noqa: E402
from eval.scanners.runner import bounded_read, strict_json  # noqa: E402


def main(argv=None, *, runtime: FrozenRuntime | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selection", type=Path, required=True)
    parser.add_argument("--selection-sha256", required=True, help="independent canonical frozen selection digest")
    args = parser.parse_args(argv)
    try:
        if type(runtime) is not FrozenRuntime:
            raise ValueError("explicit_owner_injected_runtime_required")
        pins = FrozenRunPins.model_validate_json(json.dumps(strict_json(bounded_read(args.selection, 256 * 1024))))
        if metadata_digest(pins) != args.selection_sha256:
            raise ValueError("external_frozen_selection_pin_mismatch")
        result = run_frozen(runtime, pins, expected_pins_sha256=args.selection_sha256)
        print(result.public_summary_json)
        return 2  # Does not admit measurements or unblind an oracle.
    except (ValueError, OSError, TypeError, KeyError, RuntimeError):
        print("frozen journey refused/incomplete; preserve the original shared journals", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
