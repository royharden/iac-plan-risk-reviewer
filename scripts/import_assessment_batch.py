"""Source-only CLI contract for importing an externally pinned assessment batch."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
from time import monotonic
from pydantic import TypeAdapter

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from eval.runner.assessment_batch import (AssessmentBatchRequest, _validate_batch,
    AssessmentBatchTransport, import_assessment_batch, reconstruct_export_bundle,
    resolve_private_reference)
from eval.runner.assessment_import import AssessmentSubmission

MAX_BYTES = 64 * 1024 * 1024
MAX_SECONDS = 120


def _parse_strict_json_bytes(raw: bytes):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("duplicate JSON key")
            value[key] = item
        return value
    def invalid(_value):
        raise ValueError("nonfinite JSON value")
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def _strict_json(path: Path, roots: tuple[Path, ...], expected_sha256: str):
    lexical = path.absolute()
    cursor = lexical
    while cursor != cursor.parent:
        if cursor.is_symlink():
            raise ValueError("symlink path component forbidden")
        cursor = cursor.parent
    resolved = lexical.resolve(strict=True)
    if not any(resolved == root or root in resolved.parents for root in roots):
        raise ValueError("input path outside explicitly authorized roots")
    if not resolved.is_file() or resolved.stat().st_size > MAX_BYTES:
        raise ValueError("bounded regular manifest required")
    raw = resolved.read_bytes()
    if len(raw) > MAX_BYTES:
        raise ValueError("manifest size or digest invalid")
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("manifest external digest mismatch")
    parsed = _parse_strict_json_bytes(raw)
    return raw, parsed


def _write_new(path: Path, value: dict) -> None:
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()
    if len(raw) > MAX_BYTES or path.exists() or path.is_symlink():
        raise ValueError("fresh bounded output file required")
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def _read_reference(root: Path, reference, started: float):
    if monotonic() - started > MAX_SECONDS:
        raise ValueError("assessment batch intake deadline exceeded")
    path = resolve_private_reference(root, reference.relative_path, must_exist=False)
    if not path.exists():
        return b"[]", []
    if not path.is_file() or path.stat().st_size > reference.max_bytes:
        raise ValueError("referenced private file exceeds declared byte cap")
    raw = path.read_bytes()
    if len(raw) > reference.max_bytes or hashlib.sha256(raw).hexdigest() != reference.sha256:
        raise ValueError("referenced private file hash/size mismatch")
    parsed = _parse_strict_json_bytes(raw)
    return raw, parsed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True,
                        help="bounded externally pinned batch wire")
    parser.add_argument("--out", type=Path, required=True,
                        help="fresh private output path")
    parser.add_argument("--authorized-root", type=Path, action="append", required=True,
                        help="explicit root for manifest and private capture references")
    parser.add_argument("--manifest-sha256", required=True,
                        help="independently supplied exact manifest digest")
    parser.add_argument("--root-id", required=True,
                        help="operator-bound identity of the authorized root")
    parser.add_argument("--root-sha256", required=True,
                        help="external SHA256 of the normalized authorized-root path")
    args = parser.parse_args(argv)
    started = monotonic()
    try:
        roots = tuple(root.resolve(strict=True) for root in args.authorized_root)
        if len(args.manifest_sha256) != 64 or any(c not in "0123456789abcdef" for c in args.manifest_sha256):
            raise ValueError("lowercase SHA256 manifest pin required")
        manifest_raw, _manifest_shape = _strict_json(args.manifest, roots, args.manifest_sha256)
        # Validate the exact pinned JSON bytes in JSON mode; do not coerce arrays
        # from json.loads dict/list objects into strict tuple fields.
        transport = AssessmentBatchTransport.model_validate_json(manifest_raw)
        if (transport.root_id != args.root_id or len(roots) != 1
                or hashlib.sha256(str(roots[0]).encode("utf-8")).hexdigest() != args.root_sha256
                or transport.root_sha256 != args.root_sha256):
            raise ValueError("transport root identity mismatch")
        root = roots[0]
        request = transport.request
        if request.authority_request.submissions:
            raise ValueError("assessment sheets must be supplied through pinned private references")
        # Authority, external pins, raw scenario selection, coordinator hash, spans,
        # and the single journal are checked before any capture-directory reads.
        _validate_batch(request)
        output_parent = args.out.parent.resolve(strict=True)
        if (not any(output_parent == root or root in output_parent.parents for root in roots)
                or args.out.exists() or args.out.is_symlink()):
            raise ValueError("fresh output must be within an authorized root")
        plan_ids = [row.invocation_case_id for row in transport.plans]
        if len(plan_ids) != len(set(plan_ids)):
            raise ValueError("duplicate invocation transport entry")
        if set(plan_ids) != {row.invocation_case_id for row in request.invocations}:
            raise ValueError("transport plan entries must cover each authorized invocation")
        bundles, captures, submissions = {}, {}, {}
        for plan in transport.plans:
            if monotonic() - started > MAX_SECONDS:
                raise ValueError("assessment batch intake deadline exceeded")
            case_id = plan.invocation_case_id
            wire = plan.bundle
            if wire is None:
                if plan.capture_directory is not None or plan.submissions is not None:
                    raise ValueError("missing export cannot carry capture or assessment files")
                captures[case_id] = None
                submissions[case_id] = ()
                continue
            bundle = reconstruct_export_bundle(wire)
            bundles[case_id] = bundle
            invocation = next(row for row in request.invocations
                              if row.invocation_case_id == case_id)
            if plan.capture_index_sha256 != invocation.index_sha256:
                raise ValueError("capture index pin differs from external invocation record")
            capture = (resolve_private_reference(root, plan.capture_directory, must_exist=False)
                       if plan.capture_directory else None)
            if capture is not None and not capture.exists():
                capture = None
            if capture is not None and not capture.is_dir():
                raise ValueError("regular capture directory required")
            captures[case_id] = capture
            if plan.submissions is not None:
                submissions_raw, submissions_shape = _read_reference(root, plan.submissions, started)
            else:
                submissions_raw, submissions_shape = b"[]", []
            if type(submissions_shape) is not list or len(submissions_shape) > 4096:
                raise ValueError("bounded submission list required")
            submissions[case_id] = TypeAdapter(tuple[AssessmentSubmission, ...]).validate_json(
                submissions_raw)
        result = import_assessment_batch(request, bundles=bundles,
            capture_directories=captures, submissions_by_invocation=submissions)
        if monotonic() - started > MAX_SECONDS:
            raise ValueError("assessment batch intake deadline exceeded")
        _write_new(args.out, result)
        return 0
    except (OSError, ValueError, TypeError, KeyError) as error:
        print(f"ASSESSMENT_BATCH_REJECTED: {type(error).__name__}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
