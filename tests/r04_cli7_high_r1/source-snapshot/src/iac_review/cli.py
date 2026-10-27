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
    verify = subcommands.add_parser("verify-report", help="Verify a finalized local report bundle and artifact hashes")
    verify.add_argument("bundle", type=Path, help="Complete local bundle directory, including private artifacts")
    verify.add_argument("--plan", type=Path, help="Optional explicitly supplied original plan to verify its digest")
    evidence = subcommands.add_parser("evidence", help="Read one pinned mask-safe fact; exact locations are private")
    evidence.add_argument("bundle", type=Path, help="Complete local private bundle; shareable-only input cannot resolve")
    evidence.add_argument("--plan", type=Path, required=True, help="Explicit original local plan with exact pinned digest")
    evidence.add_argument("--finding", required=True, help="Opaque finding ID from the private report")
    evidence.add_argument("--fact", required=True, help="Opaque fact ID within that finding")
    share = subcommands.add_parser("share", help="Regenerate safe files from a bound bundle and explicit original plan")
    share.add_argument("bundle", type=Path, help="Complete bound PRIVATE input bundle")
    share.add_argument("--plan", type=Path, required=True, help="Explicit pinned original plan; never copied")
    share.add_argument("--out", type=Path, required=True, help="Fresh separate share-only directory; existing parent")
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
        if arguments.command == "share":
            from iac_review.shareable_export import export_shareable
            result = export_shareable(arguments.bundle, arguments.plan, arguments.out, deadline=started + MAX_SECONDS)
            try:
                sys.stdout.write(f"shareable_exported review_exit_code={result['review_exit_code']}; not source-resolvable\n")
            except (OSError, KeyboardInterrupt):
                pass
            return result["review_exit_code"]
        if arguments.command in ("verify-report", "evidence"):
            import json
            from iac_review.source_view import verify_report, view_evidence

            if arguments.command == "verify-report":
                result = verify_report(arguments.bundle, arguments.plan, deadline=started + MAX_SECONDS)
            else:
                result = view_evidence(arguments.bundle, arguments.plan, arguments.finding,
                                       arguments.fact, deadline=started + MAX_SECONDS)
            _within_budget(started)
            sys.stdout.write(json.dumps(result, ensure_ascii=True, allow_nan=False) + "\n")
            return 0
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
        write_report(report, arguments.out, deadline=started + MAX_SECONDS)
        # Avoid logging user paths, resource addresses, values or input exceptions.
        try:
            sys.stdout.write(f"review_exported exit_code={report.exit_code}; private artifacts are sensitive\n")
        except OSError:
            # A closed console cannot turn an already finalized bundle into an
            # aborted review. The finalized artifact/exit code remain authoritative.
            pass
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
