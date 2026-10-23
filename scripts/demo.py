"""Explicit synthetic/fake offline walkthrough; not measurement or acceptance."""
from __future__ import annotations

import argparse
from decimal import Decimal
from hashlib import sha256
from html import escape
import json
import os
from pathlib import Path
import sys
from time import monotonic

NAMES = ("public-ssh", "port-443", "unknown-port", "stateful-replacement")
ARMS = ("D", "L", "P", "M", "C", "C-custom", "T")


def _json(value) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")


def _write(path, payload):
    with path.open("xb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())


def run_demo(out: Path, *, fake: bool = False, synthetic: bool = False) -> dict:
    """Future invocation only. Fixed shipped development cases; no live mode."""
    if fake is not True or synthetic is not True:
        raise ValueError("explicit fake and synthetic flags required")
    from iac_review.attempts import AttemptJournal, Budget, PriceIdentity, Reservation
    from iac_review.explain import FakeSelector, build_capsule, validate_selection
    from iac_review.ingest import load_plan
    from iac_review.report import build_report, write_report
    from iac_review.rules import evaluate
    from iac_review.source_view import verify_report, view_evidence

    root = Path(__file__).resolve().parents[1]
    output = Path(out).absolute()
    if any(path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction())
           for path in (output, *output.parents)):
        raise ValueError("output must not traverse links")
    if output.exists() or not output.parent.is_dir() or output.is_relative_to(root / "fixtures"):
        raise ValueError("fresh demo output with existing parent required")
    output.mkdir(mode=0o700)
    _write(output / "demo-state.json", _json({"state": "ABORTED", "scope": "private_fake_demo"}))
    deadline = monotonic() + 120
    reports = {}
    cases = []
    fixture_pins = []
    for name in NAMES:
        if monotonic() > deadline:
            raise ValueError("demo deadline exceeded")
        plan = load_plan(root / "fixtures" / "demo" / f"{name}.json")
        report = build_report(plan, evaluate(plan))
        write_report(report, output / name, deadline=deadline)
        verification = verify_report(output / name, root / "fixtures" / "demo" / f"{name}.json", deadline=deadline)
        if not verification["run_manifest_bound"]:
            raise ValueError("demo requires bound core reports")
        reports[name] = report
        fixture_pins.append({"name": name, "raw_sha256": plan.identity.sha256})
        cases.append({"name": name, "exit_code": report.exit_code,
                      "status": report.shareable["summary"]["status"], "bound": True})
    report = reports["public-ssh"]
    row = next(row for row in report.shareable["evaluations"] if row["rule_id"] == "R1")
    capsule = build_capsule(report.shareable, row["finding_id"])
    original = _json(report.shareable)
    payload_hash = sha256(capsule.model_dump_json().encode("utf-8")).hexdigest()
    price = PriceIdentity(provider="mock", model="finite-fake", price_id="demo-zero-mock-only",
                          price_date="2026-10-23", input_usd_per_million=Decimal(0), output_usd_per_million=Decimal(0))
    budget = Budget(max_requests=2, max_input_tokens=131072, max_output_tokens=131072, max_usd=Decimal(0))
    local_instruction = "Offline finite FakeSelector demonstration; no provider."
    hashes = {
        "build": report.private["provenance"]["descriptor"]["run_manifest"]["build_sha256"],
        "corpus": sha256(_json(fixture_pins)).hexdigest(), "projection": payload_hash,
        "prompt": sha256(local_instruction.encode("ascii")).hexdigest(),
        "input": sha256(_json({"instruction": local_instruction, "capsule": capsule.model_dump(mode="json")})).hexdigest(),
        "model": sha256((root / "src" / "iac_review" / "explain" / "__init__.py").read_bytes()).hexdigest(),
        "config": sha256(_json({"mock_only": True, "budget": budget.model_dump(mode="json"),
                                  "price": price.model_dump(mode="json")})).hexdigest(),
    }
    # These pin the local fake convention/fixture bytes, not independent corpus
    # custody, real provider prompts/prices or model tokenization.
    with AttemptJournal(output / "fake-attempts.jsonl", budget, price) as journal:
        results = []
        for invalid in (False, True):
            started = monotonic()
            attempt = journal.start(Reservation(input_tokens_upper=65536, output_tokens_upper=65536,
                                                  request_usd_upper=Decimal(0), hashes=hashes))
            selection = FakeSelector().select(capsule).model_dump(mode="json")
            if invalid:
                selection["clauses"][1]["fact_ids"] = ["foreign-demo-fact"]
            result = validate_selection(capsule, selection)
            journal.terminal(attempt, "invalid" if not result.accepted else "ok",
                             int((monotonic() - started) * 1000), input_tokens=0, output_tokens=0,
                             known_usd=Decimal(0), response_sha256=sha256(_json(selection)).hexdigest())
            results.append({"finding_id": row["finding_id"], "accepted": result.accepted,
                            "source": result.source, "text": result.text})
        accounting = journal.summary()
    if not results[0]["accepted"] or results[1]["accepted"] or _json(report.shareable) != original:
        raise ValueError("demo finite-selector/invariance expectation failed")
    private_row = next(row for row in report.private["evaluations"] if row["finding_id"] == capsule.finding_id)
    fact = next(fact for fact in private_row["facts"] if fact["role"] == "decision")
    evidence = view_evidence(output / "public-ssh", root / "fixtures" / "demo" / "public-ssh.json",
                             capsule.finding_id, fact["fact_id"], deadline=deadline)
    _write(output / "private-evidence.json", _json(evidence))
    explanation = {"same_finding_id": capsule.finding_id, "valid": results[0], "invalid_fallback": results[1],
                   "rule_results_unchanged": True, "mock_only": True}
    _write(output / "finite-demo.json", _json(explanation))
    capabilities = [
        {"arm": "C", "declared": "Checkov built-in adapter source; transition mapping may be unavailable"},
        {"arm": "C-custom", "declared": "Action-aware custom source; delete-only callback gaps remain incomplete"},
        {"arm": "T", "declared": "Trivy adapter source; exact distribution/mapping compatibility unverified"},
    ]
    summary = {"private": True, "synthetic": True, "fake_only": True, "cases": cases,
               "finite_selection": explanation, "fake_accounting": accounting,
               "accounting_scope": "Mock counters only; zero mock cost/tokens are not provider measurements.",
               "scanner_capabilities": capabilities, "measurements": {arm: "NOT MEASURED" for arm in ARMS},
               "product_acceptance": False}
    _write(output / "demo.json", _json(summary))
    links = "".join(f'<li>{escape(case["name"])}: <a href="{escape(case["name"])}/private.html">PRIVATE evidence report</a> · '
                    f'<a href="{escape(case["name"])}/shareable.html">shareable projection</a> · scoped exit {case["exit_code"]}</li>'
                    for case in cases)
    html = ('<!doctype html><html><head><meta charset="utf-8">'
            '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; base-uri \'none\'; form-action \'none\'">'
            '<title>Private offline synthetic walkthrough</title></head><body>'
            '<h1>PRIVATE demo directory — never share this whole folder</h1>'
            '<p>Require demo-state.json COMPLETE. No benchmark or live model/scanner result is claimed.</p>'
            f'<ul>{links}</ul><h2>Same-finding finite fake and deliberately invalid fallback</h2>'
            f'<pre>{escape(json.dumps(explanation, indent=2))}</pre><h2>Mock accounting; not provider usage</h2>'
            f'<pre>{escape(json.dumps(accounting, indent=2))}</pre><h2>Declared scanner source only</h2>'
            f'<pre>{escape(json.dumps(capabilities, indent=2))}</pre>'
            '<p>D/L/P/M/C/C-custom/T: NOT MEASURED. No global security or productivity conclusion.</p></body></html>')
    _write(output / "index.html", html.encode("utf-8"))
    if monotonic() > deadline:
        raise ValueError("demo deadline exceeded before finalization")
    _write(output / ".demo-state.pending", _json({"state": "COMPLETE", "mock_only": True, "measurements_verified": False}))
    os.replace(output / ".demo-state.pending", output / "demo-state.json")
    return summary


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError("invalid explicit fake demo invocation")


def main(argv=None) -> int:
    parser = _Parser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True, help="fresh PRIVATE output; existing parent")
    parser.add_argument("--fake", action="store_true", required=True)
    parser.add_argument("--synthetic", action="store_true", required=True)
    try:
        args = parser.parse_args(argv)
        run_demo(args.out, fake=args.fake, synthetic=args.synthetic)
    except SystemExit as error:
        return 0 if error.code == 0 else 3
    except (Exception, KeyboardInterrupt):
        sys.stderr.write("offline_demo_aborted; partial output remains PRIVATE and unverified\n")
        return 3
    sys.stdout.write("offline_fake_demo_written; all arms NOT MEASURED; directory is PRIVATE\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
