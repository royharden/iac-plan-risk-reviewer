"""Commit or inspect a metadata-only, all-seven-arm exposure journal.

The record command never opens case input, oracle, outcome, prose, or measurement
payloads. A committed receipt records consumption and still grants no access.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from iac_review.contracts.manifest import RunManifest
from eval.runner.bundle import root_digest
from eval.runner.custody import metadata_digest
from eval.runner.exposure_journal import (
    ExposureCommitAuthorization, commit_exposure, exposure_status,
)
from eval.runner.preflight import PreflightPins

MAX_METADATA_BYTES = 4 * 1024 * 1024


def _read_pinned(path: Path, expected_sha256: str):
    absolute = path.absolute()
    for item in (absolute, *absolute.parents):
        if item.is_symlink() or (hasattr(item, "is_junction") and item.is_junction()):
            raise ValueError("metadata path link forbidden")
    if not path.is_file() or path.stat().st_size > MAX_METADATA_BYTES:
        raise ValueError("bounded regular metadata file required")
    raw = path.read_bytes()
    if len(raw) > MAX_METADATA_BYTES or hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("exact metadata SHA256/size mismatch")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate metadata JSON key")
            result[key] = value
        return result
    def invalid(_value):
        raise ValueError("nonfinite metadata JSON")
    return raw, json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def _root(path: Path, expected_sha256: str) -> Path:
    lexical = path.absolute()
    for item in (lexical, *lexical.parents):
        if item.is_symlink() or (hasattr(item, "is_junction") and item.is_junction()):
            raise ValueError("authorized root link/junction forbidden")
    root = path.resolve(strict=True)
    if not root.is_dir() or root_digest(root) != expected_sha256:
        raise ValueError("exact authorized source root mismatch")
    return root


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    record = commands.add_parser("record", help="durably commit seven metadata receipts")
    record.add_argument("--root", type=Path, required=True)
    record.add_argument("--root-sha256", required=True)
    record.add_argument("--manifest", type=Path, required=True)
    record.add_argument("--manifest-file-sha256", required=True,
                        help="exact source bytes pin, including final newline")
    record.add_argument("--run-manifest-sha256", required=True,
                        help="canonical typed RunManifest record pin")
    record.add_argument("--authorization", type=Path, required=True)
    record.add_argument("--authorization-file-sha256", required=True,
                        help="exact external authorization file bytes pin")
    record.add_argument("--authorization-sha256", required=True,
                        help="canonical typed authorization record pin")
    record.add_argument("--semantic-suite-sha256", required=True)
    record.add_argument("--eligibility-sha256", required=True)
    status = commands.add_parser("status", help="read-only journal recovery status")
    status.add_argument("--root", type=Path, required=True)
    status.add_argument("--root-sha256", required=True)
    status.add_argument("--authorization-sha256")
    args = parser.parse_args(argv)
    try:
        root = _root(args.root, args.root_sha256)
        if args.command == "status":
            print(exposure_status(root, args.authorization_sha256).model_dump_json())
            return 0
        manifest_raw, _manifest_wire = _read_pinned(args.manifest, args.manifest_file_sha256)
        manifest = RunManifest.model_validate_json(manifest_raw)
        if metadata_digest(manifest) != args.run_manifest_sha256:
            raise ValueError("canonical run manifest pin mismatch")
        _auth_raw, auth_wire = _read_pinned(args.authorization, args.authorization_file_sha256)
        authorization = ExposureCommitAuthorization.model_validate(auth_wire)
        pins = PreflightPins(run_manifest_sha256=args.run_manifest_sha256,
            authority_sha256=authorization.authority_sha256,
            semantic_suite_sha256=args.semantic_suite_sha256,
            eligibility_sha256=args.eligibility_sha256)
        if metadata_digest(authorization) != args.authorization_sha256:
            raise ValueError("authorization digest mismatch")
        result = commit_exposure(root, manifest, pins, authorization,
            expected_authorization_sha256=args.authorization_sha256)
        print(result.model_dump_json())
        return 0
    except (OSError, ValueError, TypeError, KeyError) as error:
        print(f"EXPOSURE_JOURNAL_REJECTED: {type(error).__name__}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
