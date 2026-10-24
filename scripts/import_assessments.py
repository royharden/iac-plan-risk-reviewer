"""Import private D5/D7 assessment wires against externally supplied digests."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from eval.runner.assessment_import import AssessmentImportRequest, import_assessments  # noqa: E402
from eval.model.provenance import ExportBundle  # noqa: E402
from eval.runner.scoring import ArmRow  # noqa: E402

MAX_BYTES = 16 * 1024 * 1024


def _read(path: Path) -> bytes:
    if any(part.is_symlink() for part in (path, *path.parents)) or not path.is_file():
        raise ValueError("bounded regular input without symlink ancestors required")
    if path.stat().st_size > MAX_BYTES:
        raise ValueError("assessment import input exceeds byte cap")
    with path.open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("assessment import input grew beyond byte cap")
    return raw


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _finite(value):
    raise ValueError("nonfinite JSON number")


def _json(path: Path):
    return json.loads(_read(path), object_pairs_hook=_pairs, parse_constant=_finite)


def _bundle(path: Path) -> ExportBundle:
    raw = _json(path)
    if type(raw) is not dict or set(raw) != {
            "rows", "attempts_json", "provenance_json", "accounting_json", "observations_json",
            "live_eligible"} or raw["live_eligible"] is not False:
        raise ValueError("closed D5 ExportBundle wire required")
    rows = tuple(ArmRow.model_validate_json(json.dumps(value, allow_nan=False)) for value in raw["rows"])
    if any(type(raw[key]) is not str for key in (
            "attempts_json", "provenance_json", "accounting_json", "observations_json")):
        raise ValueError("D5 export JSON members must remain canonical strings")
    return ExportBundle(rows, raw["attempts_json"], raw["provenance_json"],
                        raw["accounting_json"], raw["observations_json"])


def _write_fresh(path: Path, value: dict) -> None:
    if path.exists() or any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("fresh output path without symlink ancestors required")
    raw = (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")
    if len(raw) > MAX_BYTES:
        raise ValueError("assessment result exceeds byte cap")
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--export-bundle", type=Path, required=True)
    parser.add_argument("--capture-directory", type=Path)
    parser.add_argument("--journal-links", type=Path)
    parser.add_argument("--authority-sha256", required=True)
    parser.add_argument("--export-sha256", required=True)
    parser.add_argument("--index-sha256")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        request_raw = _json(args.request)
        request_raw["authority_sha256"] = args.authority_sha256
        request_raw["expected_export_sha256"] = args.export_sha256
        request_raw["expected_index_sha256"] = args.index_sha256
        if args.journal_links is not None:
            request_raw["journal_links"] = _json(args.journal_links)
        request = AssessmentImportRequest.model_validate_json(json.dumps(request_raw, allow_nan=False))
        bundle = _bundle(args.export_bundle)
        result = import_assessments(request, bundle=bundle, capture_directory=args.capture_directory)
        _write_fresh(args.out, result)
        return 0 if result["capture_status"] == "verified" and not result["cases_missing_or_incomplete"] else 2
    except (OSError, ValueError, TypeError, KeyError) as error:
        print(f"ASSESSMENT_IMPORT_REJECTED: {type(error).__name__}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
