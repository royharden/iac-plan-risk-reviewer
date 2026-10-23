"""Later keyless demo entrypoint. Not executed during Dirty Mode construction."""
from __future__ import annotations

import argparse
from pathlib import Path

from iac_review.ingest import load_plan
from iac_review.report import build_report, write_report
from iac_review.rules import evaluate


def main() -> int:
    parser = argparse.ArgumentParser(description="Create local reports for hand-authored synthetic inputs.")
    parser.add_argument("--out", type=Path, required=True, help="New or empty directory for demo bundles")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = args.out.absolute()
    if any(path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction())
           for path in (output, *output.parents)):
        parser.error("output must not traverse symbolic links")
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        parser.error("output directory must be new or empty")
    output.mkdir(parents=True, exist_ok=True)
    for name in ("public-ssh", "port-443", "unknown-port", "stateful-replacement"):
        plan = load_plan(root / "fixtures" / "demo" / f"{name}.json")
        report = build_report(plan, evaluate(plan))
        write_report(report, output / name)
        print(f"{name}: exit={report.exit_code}; {report.shareable['summary']['status']}")
    print("Synthetic demo only; no model/scanner measurements or product acceptance.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
