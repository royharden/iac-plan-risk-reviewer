"""Render a bounded, aggregate-only seven-arm result summary."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from eval.runner.results import ARMS, render_results  # noqa: E402

MAX_BYTES = 64 * 1024 * 1024


def _read(path: Path):
    if any(part.is_symlink() for part in (path, *path.parents)) or not path.is_file():
        raise ValueError("regular bounded input without symlink ancestors required")
    if path.stat().st_size > MAX_BYTES:
        raise ValueError("result input exceeds byte cap")
    with path.open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("result input grew beyond byte cap")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def invalid(_value):
        raise ValueError("nonfinite JSON number")

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def _write_new(path: Path, raw: bytes) -> None:
    if len(raw) > MAX_BYTES:
        raise ValueError("rendered output exceeds byte cap")
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def _state(path: Path, name: str) -> None:
    raw = (json.dumps({"state": name}, separators=(",", ":")) + "\n").encode("ascii")
    temporary = path.with_suffix(".tmp")
    with temporary.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--score", type=Path, required=True)
    parser.add_argument("--l-utility", type=Path)
    parser.add_argument("--assessment-import", type=Path)
    parser.add_argument("--producer-accounting", type=Path)
    parser.add_argument("--out", type=Path, required=True,
                        help="fresh output directory for aggregate results only")
    args = parser.parse_args(argv)
    try:
        score = _read(args.score)
        l_utility = _read(args.l_utility) if args.l_utility else None
        assessment = _read(args.assessment_import) if args.assessment_import else None
        accounting = _read(args.producer_accounting) if args.producer_accounting else None
        result = render_results(score, l_utility=l_utility,
                                assessment_import=assessment,
                                producer_accounting=accounting)
        if args.out.exists() or any(part.is_symlink() for part in (args.out, *args.out.parents)):
            raise ValueError("fresh output directory without symlink ancestors required")
        args.out.mkdir(parents=False, exist_ok=False)
        _state(args.out / "render-state.json", "ABORTED")
        _write_new(args.out / "results.md", result["markdown"].encode("utf-8"))
        rows = [{"schema_version": 1, "scope": "aggregate", "arm": arm,
                 **result["arms"][arm]} for arm in ARMS]
        rows.extend({"schema_version": 1, "scope": "failure_overlap", "arms": pair.split("|"),
                     "shared_failed_findings": count}
                    for pair, count in result["failure_overlap"].items())
        if result.get("assessment_batch") is not None:
            rows.append({"schema_version": 1, "scope": "assessment_batch",
                         **result["assessment_batch"]})
        jsonl = "".join(json.dumps(row, sort_keys=True, allow_nan=False) + "\n" for row in rows)
        _write_new(args.out / "results.jsonl", jsonl.encode("utf-8"))
        _state(args.out / "render-state.json", "COMPLETE")
        return 0
    except (OSError, ValueError, TypeError, KeyError) as error:
        print(f"RESULT_RENDER_REJECTED: {type(error).__name__}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
