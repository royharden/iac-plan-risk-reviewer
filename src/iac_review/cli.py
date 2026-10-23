"""Local inspect/export command. No provider, scanner, network or shell path."""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import Sequence

from iac_review.evidence import verify_unchanged
from iac_review.ingest import InputError, MAX_SECONDS, decode_source, load_plan, read_source_bytes


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="iac-review",
        description="Inspect four declared AWS Terraform change predicates in a saved local JSON plan.",
        epilog="A complete scoped review is not a claim that infrastructure is secure or permission to apply.",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)
    inspect = subcommands.add_parser("inspect", help="Write private and shareable static JSON/HTML reports")
    inspect.add_argument("plan", type=Path, help="Local regular Terraform plan JSON file")
    inspect.add_argument("--out", type=Path, required=True, help="New output directory; keep private artifacts local")
    inspect.add_argument("--fail-on", type=int, choices=range(1, 5), default=3,
                         help="Risk severity threshold (1–4; default 3); lower findings remain visible")
    explain = subcommands.add_parser("explain", help="Validate an offline finite selector response; no provider call")
    explain.add_argument("shareable", type=Path, help="Shareable JSON report, never a private report or raw plan")
    explain.add_argument("--finding", required=True, help="Opaque finding ID in that report")
    explain.add_argument("--selection", type=Path, required=True, help="Offline finite-template selector JSON")
    return parser


def _within_budget(started: float) -> None:
    if time.monotonic() - started > MAX_SECONDS:
        raise InputError("review_time_limit")


def main(argv: Sequence[str] | None = None) -> int:
    """Exit 3 error, 2 inconclusive, 1 threshold risk, 0 complete named scope."""
    try:
        arguments = _parser().parse_args(argv)
    except SystemExit as exc:
        # argparse's standard usage error 2 must not impersonate coverage exit 2.
        return 0 if exc.code == 0 else 3
    started = time.monotonic()
    try:
        if arguments.command == "explain":
            from iac_review.explain import build_capsule, validate_selection

            shared = decode_source(read_source_bytes(arguments.shareable))
            response = decode_source(read_source_bytes(arguments.selection))
            try:
                capsule = build_capsule(shared, arguments.finding)
                selection = validate_selection(capsule, response)
            except (ValueError, TypeError, KeyError, AttributeError) as exc:
                raise InputError("explanation_input_invalid") from exc
            _within_budget(started)
            sys.stdout.write(selection.model_dump_json() + "\n")
            return 0 if selection.accepted else 2
        # Delay product-stage imports until invocation; no optional live extras.
        from iac_review.report import build_report, write_report
        from iac_review.rules import evaluate

        plan = load_plan(arguments.plan)
        _within_budget(started)
        evaluations = evaluate(plan)
        _within_budget(started)
        report = build_report(plan, evaluations, fail_on=arguments.fail_on)
        _within_budget(started)
        # A mutation cannot be hidden by the absence of a particular fact row.
        verify_unchanged(plan)
        write_report(report, arguments.out)
        _within_budget(started)
        # Avoid logging user paths, resource addresses, values or input exceptions.
        sys.stdout.write(f"review_exported exit_code={report.exit_code}; private artifacts are sensitive\n")
        return report.exit_code
    except InputError as exc:
        sys.stderr.write(f"review_aborted code={exc}\n")
        return 3
    except KeyboardInterrupt:
        sys.stderr.write("review_aborted code=cancelled\n")
        return 3
    except Exception:
        # Third-party exception messages can contain the raw plan or local paths.
        # This public command deliberately emits only an invariant fixed code.
        sys.stderr.write("review_aborted code=internal_or_output_error\n")
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
