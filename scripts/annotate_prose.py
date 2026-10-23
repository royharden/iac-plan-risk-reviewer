"""Explicit private offline curator/assessor workflow. Never emits prose to console."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

# Development script only; no application import or work occurs until main().


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError("invalid private assessment invocation")


def _main(argv: list[str] | None = None) -> int:
    root = Path(__file__).resolve().parents[1]
    for directory in (root, root / "src"):
        if str(directory) not in sys.path:
            sys.path.insert(0, str(directory))
    from eval.model.explanation_artifacts import (
        AdjudicationSheet, AssessorSheet, ClaimInventory, ExplanationArtifact, Rubric,
        ExplicitSpans, Wire, make_inventory,
    )
    from eval.model.annotation import (
        export_assessments, prepare_adjudication, prepare_sheet, read_wire,
        render_worksheet, write_private,
    )

    parser = _Parser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("inventory", "prepare", "adjudicate", "export"):
        command = commands.add_parser(name)
        command.add_argument("--artifact", type=Path, required=True)
        command.add_argument("--actor", required=True, help="declared opaque actor ID; external identity verification required")
        command.add_argument("--out", type=Path, required=True, help="fresh private actor-owned directory; existing parent")
        if name == "inventory":
            command.add_argument("--spans", type=Path, required=True, help="explicit HUMAN decomposition; no auto extraction")
            command.add_argument("--curation-receipt", help="optional external receipt SHA256, not identity proof")
        else:
            command.add_argument("--inventory", type=Path, required=True)
            command.add_argument("--rubric", type=Path, required=True)
        if name == "prepare":
            command.add_argument("--other-assessor", required=True)
        if name in ("adjudicate", "export"):
            command.add_argument("--first", type=Path, required=True)
            command.add_argument("--second", type=Path, required=True)
        if name == "export":
            command.add_argument("--adjudication", type=Path)
    try:
        args = parser.parse_args(argv)
    except SystemExit as error:
        return 0 if error.code == 0 else 3

    def encoded(value):
        value = value.model_dump(mode="json") if isinstance(value, Wire) else value
        return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")

    try:
        artifact = read_wire(args.artifact, ExplanationArtifact)
        if args.command == "inventory":
            specs = read_wire(args.spans, ExplicitSpans)
            inventory = make_inventory(artifact, specs.spans, args.actor,
                                       curation_receipt_sha256=args.curation_receipt)
            payloads = {"artifact.json": encoded(artifact), "inventory.json": encoded(inventory)}
        else:
            inventory = read_wire(args.inventory, ClaimInventory)
            rubric = read_wire(args.rubric, Rubric)
            payloads = {"artifact.json": encoded(artifact), "inventory.json": encoded(inventory), "rubric.json": encoded(rubric)}
            if args.command == "prepare":
                sheet = prepare_sheet(artifact, inventory, rubric, args.actor, args.other_assessor)
                payloads["sheet.json"] = encoded(sheet)
                payloads["worksheet.html"] = render_worksheet(artifact, inventory, rubric, sheet).encode("utf-8")
            else:
                first = read_wire(args.first, AssessorSheet)
                second = read_wire(args.second, AssessorSheet)
                payloads["first-sheet.json"] = encoded(first)
                payloads["second-sheet.json"] = encoded(second)
                if args.command == "adjudicate":
                    sheet = prepare_adjudication(artifact, inventory, rubric, first, second, args.actor)
                    payloads["adjudication.json"] = encoded(sheet)
                    payloads["worksheet.html"] = render_worksheet(artifact, inventory, rubric, sheet).encode("utf-8")
                else:
                    adjudication = read_wire(args.adjudication, AdjudicationSheet) if args.adjudication else None
                    if adjudication is not None:
                        payloads["adjudication.json"] = encoded(adjudication)
                    payloads["assessment.json"] = encoded(export_assessments(artifact, inventory, rubric, first, second, adjudication))
        write_private(args.out, args.actor, payloads)
        sys.stdout.write("private_assessment_packet_written; runtime_truth_and_live_eligibility_unverified\n")
        return 0
    except KeyboardInterrupt:
        sys.stderr.write("private_assessment_refused code=cancelled\n")
    except Exception:
        # Validation exceptions can contain private text, labels and local paths.
        sys.stderr.write("private_assessment_refused code=invalid_or_unwritable_packet\n")
    return 3


def main(argv: list[str] | None = None) -> int:
    try:
        return _main(argv)
    except KeyboardInterrupt:
        sys.stderr.write("private_assessment_refused code=cancelled\n")
    except Exception:
        sys.stderr.write("private_assessment_refused code=invalid_or_unwritable_packet\n")
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
