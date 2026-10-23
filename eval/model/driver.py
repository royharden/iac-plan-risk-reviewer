"""Explicitly synthetic, fake-only experiment driver; never a live model evaluation."""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import date
from decimal import Decimal, InvalidOperation
import json
import os
from pathlib import Path
import re
import sys

from iac_review.attempts import AttemptJournal, Budget, PriceIdentity
from iac_review.evidence import verify_unchanged
from iac_review.ingest import load_plan
from iac_review.report import build_report
from iac_review.rules import evaluate
from eval.model.experiment import (
    Context, FindingLink, Limits, ResourceLink, canonical, digest, run_experiments,
)
from eval.model.provenance import export_bundle
from eval.model.transport import FakeTransport, Reply, Transport, Usage
from eval.runner.scoring import ArmRow


@dataclass(frozen=True)
class DriverConfig:
    synthetic_plan: Path
    out: Path
    fake: bool
    max_requests: int
    max_input_tokens: int
    max_output_tokens: int
    max_usd: Decimal
    limits: Limits = Limits()
    fake_scenario: str = "valid"
    capture_private_prose: Path | None = None
    generator_actor_ids: tuple[str, ...] = ()


def _plain_path(path: Path) -> Path:
    path = Path(os.path.abspath(path))
    if any(p.is_symlink() or (hasattr(p, "is_junction") and p.is_junction())
           for p in (path, *path.parents)):
        raise ValueError("path_link_rejected")
    return path


def _build_sha256() -> str:
    """Fingerprint relevant source bytes, not Git state or a claimed tested version."""
    root = Path(__file__).absolute().parents[2]
    files = sorted({*root.joinpath("src", "iac_review").rglob("*.py"),
                    *root.joinpath("eval", "model").glob("*.py"),
                    root / "eval" / "runner" / "scoring.py",
                    root / "scripts" / "eval_model.py", root / "pyproject.toml"})
    manifest = [(p.relative_to(root).as_posix(), digest(_plain_path(p).read_bytes())) for p in files]
    return digest(canonical(manifest))


def _fake(scenario: str) -> FakeTransport:
    if scenario == "valid":
        return FakeTransport()
    if scenario == "invalid":
        return FakeTransport(Reply("ok", b"{}", Usage(0, 0, Decimal(0))))
    if scenario == "timeout":
        return FakeTransport(Reply("timeout", usage=Usage(0, 0, Decimal(0))))
    if scenario == "error":
        return FakeTransport(Reply("error", usage=Usage(0, 0, Decimal(0))))
    if scenario == "unknown-usage":
        return FakeTransport(Reply("error"))
    raise ValueError("unknown_fake_scenario")


def run_driver(config: DriverConfig, *, transport: Transport | None = None) -> Path:
    """Future activation API: create one fresh local run directory and safe artifact.

    The CLI cannot load injected code. Programmatic injection is trusted keyless
    mock/protocol code only, never a means of authorizing an actual provider call.
    The driver does not accept oracle labels, corpus splits or scanner records.
    """
    if config.fake is not True:
        raise ValueError("explicit_fake_mode_required")
    counts = (config.max_requests, config.max_input_tokens, config.max_output_tokens)
    if any(type(value) is not int or value <= 0 for value in counts):
        raise ValueError("explicit_positive_caps_required")
    if not isinstance(config.max_usd, Decimal) or not config.max_usd.is_finite() or config.max_usd < 0:
        raise ValueError("finite_nonnegative_usd_cap_required")
    # Validate scenario even when a caller supplies a recording fake/protocol.
    default_transport = _fake(config.fake_scenario)
    selected_transport = transport if transport is not None else default_transport
    if selected_transport.identity.kind not in ("mock", "protocol"):
        raise ValueError("live_transport_disabled")
    source, out = _plain_path(config.synthetic_plan), _plain_path(config.out)
    capture_out = None
    if config.capture_private_prose is not None:
        capture_out = _plain_path(config.capture_private_prose)
        if capture_out == out or out in capture_out.parents or capture_out in out.parents:
            raise ValueError("separate_private_capture_sink_required")
        if capture_out.exists() or not capture_out.parent.is_dir():
            raise ValueError("fresh_private_capture_directory_required")
        actors = config.generator_actor_ids
        if not 1 <= len(actors) <= 16 or len(set(actors)) != len(actors) \
                or any(not re.fullmatch(r"[0-9a-f]{32}", actor) for actor in actors):
            raise ValueError("capture_generator_ids_invalid")
        if config.max_requests > 10_000:
            raise ValueError("capture_request_limit")
    elif config.generator_actor_ids:
        raise ValueError("generator_ids_require_private_capture")
    if out.exists() or not out.parent.is_dir():
        raise ValueError("fresh_output_directory_with_existing_parent_required")
    build = _build_sha256()
    plan = load_plan(source)
    evaluations = evaluate(plan)
    report = build_report(plan, evaluations)
    context = Context(
        build_sha256=build, source_sha256=plan.identity.sha256,
        corpus_sha256=digest(canonical({"synthetic_single_case_sha256": plan.identity.sha256})),
        config_sha256=digest(canonical({
            "mode": "fake-only", "scenario": config.fake_scenario,
            "max_requests": config.max_requests, "max_input_tokens": config.max_input_tokens,
            "max_output_tokens": config.max_output_tokens, "max_usd": str(config.max_usd),
            "capture_private_prose": capture_out is not None,
            "generator_actor_ids": list(config.generator_actor_ids),
        })),
    )
    baseline = []
    links = []
    resource_ids: dict[str, str] = {}
    shared_rows = report.shareable["evaluations"]
    private_rows = report.private["evaluations"]
    global_limits = {row["id"] for row in report.shareable["limitations"]}
    case_id = report.shareable["case_id"]
    baseline_receipt = "sha256:" + digest(canonical(report.shareable))
    # build_report iterates its supplied evaluations in order. Check each join;
    # address strings cannot disambiguate deposed instances and are never used.
    for evaluation, row, private in zip(evaluations, shared_rows, private_rows, strict=True):
        if row["rule_id"] != evaluation.rule_id or private["finding_id"] != row["finding_id"]:
            raise ValueError("deterministic_report_join_mismatch")
        previous = resource_ids.setdefault(evaluation.resource_key, row["resource_id"])
        if previous != row["resource_id"]:
            raise ValueError("deterministic_resource_join_mismatch")
        limitations = tuple(sorted(global_limits | set(row["limitation_ids"])))
        base = ArmRow(
            case_id=case_id, resource_id=row["resource_id"], rule_id=evaluation.rule_id,
            arm="D", status="ok", applicability=row["applicability"], outcome=row["outcome"],
            reason_code=private["reason_code"],
            decision_fact_ids=tuple(fact["fact_id"] for fact in row["facts"] if fact["role"] == "decision"),
            required_limitation_ids=limitations,
            source_sha256=context.source_sha256, build_sha256=context.build_sha256,
            measurement_ref=baseline_receipt,
        )
        baseline.append(base)
        if base.applicability == "supported" and base.outcome is not None:
            links.append(FindingLink(row["finding_id"], case_id, row["resource_id"], evaluation.rule_id))
    budget = Budget(max_requests=config.max_requests, max_input_tokens=config.max_input_tokens,
                    max_output_tokens=config.max_output_tokens, max_usd=config.max_usd)
    identity = selected_transport.identity
    price = PriceIdentity(provider=identity.provider, model=identity.model,
                          price_id="mock-zero-not-provider-price", price_date=date.today().isoformat(),
                          input_usd_per_million=Decimal(0), output_usd_per_million=Decimal(0))
    # mkdir(exist_ok=False) and exclusive writes prevent reusing/overwriting a run.
    # A failure preserves all started attempts for inspection/reconciliation.
    out.mkdir(mode=0o700)
    journal_path = out / "attempts.jsonl"
    journal_path.touch(exist_ok=False)
    with AttemptJournal(journal_path, budget, price) as journal:
        result = run_experiments(
            plan=plan, shareable=report.shareable, baseline=tuple(baseline), links=tuple(links),
            resource_links=tuple(ResourceLink(public, local) for local, public in resource_ids.items()),
            context=context, transport=selected_transport, journal=journal, limits=config.limits,
            capture_private_prose=capture_out is not None,
        )
        verify_unchanged(plan)
        if _build_sha256() != build:
            raise ValueError("experiment_source_changed")
        bundle = export_bundle(result)
        capture_receipt = None
        if capture_out is not None:
            from eval.model.assessment_capture import build_capture, write_private_capture

            private_capture = build_capture(result, generator_actor_ids=config.generator_actor_ids,
                origin="mock" if identity.kind == "mock" else "unverified")
            capture_receipt = write_private_capture(private_capture, capture_out)
        artifact = {
            "schema": 1, "mode": "synthetic_fake_or_protocol_plumbing",
            "live_eligible": False, "product_acceptance": False,
            "measurement_status": {arm: "NOT MEASURED" for arm in ("L", "P", "M")},
            "D_role": "locally evaluated deterministic baseline; no oracle score asserted",
            "deterministic_summary": report.shareable["summary"],
            "rows": [json.loads(row.model_dump_json()) for row in bundle.rows],
            "attempts": json.loads(bundle.attempts_json),
            "accounting": json.loads(bundle.accounting_json),
            "provenance": json.loads(bundle.provenance_json),
            "observations": json.loads(bundle.observations_json),
            "journal_summary": json.loads(result.journal_summary_json),
            # Hash/counts only: no private sink path or generated text in this artifact.
            "private_capture": capture_receipt,
        }
        destination = out / "plumbing.json"
        with destination.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(canonical(artifact) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
    return destination


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        # Do not echo arbitrary arguments/path/secret-looking values into logs.
        self.exit(3, "model_plumbing_invalid_arguments\n")


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(description=__doc__)
    parser.add_argument("--synthetic-plan", type=Path, required=True,
                        help="user-attested synthetic Terraform JSON only; no hidden corpus")
    parser.add_argument("--fake", action="store_true", required=True,
                        help="mandatory opt-in; no live mode exists")
    parser.add_argument("--out", type=Path, required=True, help="fresh local run directory")
    parser.add_argument("--max-requests", type=int, required=True)
    parser.add_argument("--max-input-tokens", type=int, required=True, help="total cap")
    parser.add_argument("--max-output-tokens", type=int, required=True, help="total cap")
    parser.add_argument("--max-usd", required=True, help="explicit mock accounting cap; 0 allowed")
    parser.add_argument("--request-input-tokens", type=int, default=65_536)
    parser.add_argument("--request-output-tokens", type=int, default=4_096)
    parser.add_argument("--max-input-bytes", type=int, default=65_536)
    parser.add_argument("--max-output-bytes", type=int, default=16_384)
    parser.add_argument("--timeout-seconds", type=float, default=30.0)
    parser.add_argument("--fake-scenario", choices=("valid", "invalid", "timeout", "error", "unknown-usage"),
                        default="valid")
    parser.add_argument("--capture-private-prose", type=Path,
                        help="Explicit separate fresh PRIVATE P artifact directory; disabled by default")
    parser.add_argument("--generator-actor-id", action="append",
                        help="Declared opaque generator actor ID; required only with private capture")
    args = parser.parse_args(argv)
    try:
        config = DriverConfig(
            synthetic_plan=args.synthetic_plan, out=args.out, fake=args.fake,
            max_requests=args.max_requests, max_input_tokens=args.max_input_tokens,
            max_output_tokens=args.max_output_tokens, max_usd=Decimal(args.max_usd),
            limits=Limits(args.request_input_tokens, args.request_output_tokens,
                          args.max_input_bytes, args.max_output_bytes,
                          args.timeout_seconds, args.max_requests), fake_scenario=args.fake_scenario,
            capture_private_prose=args.capture_private_prose,
            generator_actor_ids=tuple(args.generator_actor_id or ()),
        )
        run_driver(config)
    except (ValueError, OSError, InvalidOperation, ArithmeticError):
        sys.stderr.write("model_plumbing_failed_runtime_validation_required\n")
        return 3
    sys.stdout.write("Synthetic plumbing recorded; L/P/M NOT MEASURED, live-ineligible.\n")
    # This is still an incomplete model evaluation, even when the plumbing finished.
    return 2
