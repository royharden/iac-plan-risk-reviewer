"""Regenerate a detached safe report from a bound private bundle and explicit plan.

No stored HTML/prose is copied. Hash integrity is not producer authentication.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import sys
from time import monotonic

from iac_review.evidence import verify_unchanged
from iac_review.ingest import InputError, MAX_BYTES, MAX_SECONDS, decode_source, load_plan, read_source_bytes
from iac_review.provenance import DESCRIPTOR_FILE, ReportProvenance, installed_core_pins
from iac_review.report import _html, _json_bytes, build_report
from iac_review.rules import evaluate
from iac_review.source_view import verify_report

_OPAQUE = re.compile(r"[0-9a-f]{32}")
_ID_FIELDS = {"run_id", "case_id", "finding_id", "resource_id", "fact_id", "evaluation_id"}
_PUBLIC_FILES = frozenset({"shareable.json", "shareable.html", "manifest.json", "manifest.sha256"})


def _semantic(value, *, private=False, root=True):
    """Remove only per-run IDs/private descriptor; compare all other content strictly."""
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if key in _ID_FIELDS:
                if type(item) is not str or _OPAQUE.fullmatch(item) is None:
                    raise InputError("share_original_identity_invalid")
                continue
            if root and private and key == "provenance":
                continue
            result[key] = _semantic(item, private=private, root=False)
        return result
    if isinstance(value, list):
        return [_semantic(item, private=private, root=False) for item in value]
    return value


def _current_pins(check):
    return {row.path: row.sha256 for row in installed_core_pins(check)}


def _publish(payloads, out: Path, deadline, before_finalize, review_exit_code):
    """Core-style staged publication of SAFE bytes only; no private serialization."""
    if set(payloads) != _PUBLIC_FILES or any(len(raw) > MAX_BYTES for raw in payloads.values()):
        raise InputError("share_payload_limit_or_inventory")
    def check():
        if monotonic() > deadline:
            raise InputError("share_time_limit")
    out = Path(out).absolute()
    if (out.exists() or not out.parent.is_dir()
            or any(path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()) for path in (out, *out.parents))):
        raise InputError("share_fresh_safe_output_required")
    out.mkdir()
    state = out / "export-state.json"
    def write(path, data, owned):
        with path.open("xb") as stream:
            owned.append(path)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    write(state, _json_bytes({"state": "ABORTED", "projection": "shareable"}), [])
    pending = out / ".pending"
    staged, published = [], []
    try:
        check()
        pending.mkdir()
        for name, raw in payloads.items():
            check()
            write(pending / name, raw, staged)
        for path in staged:
            check()
            write(out / path.name, path.read_bytes(), published)
        for path in staged:
            path.unlink()
        pending.rmdir()
        temporary_state = out / ".export-state.pending"
        write(temporary_state, _json_bytes({"state": "COMPLETE", "projection": "shareable",
              "review_exit_code": review_exit_code, "source_resolvable": False}), staged)
        before_finalize()
        check()
        os.replace(temporary_state, state)
    except BaseException:
        for path in (*published, *staged):
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
        try:
            pending.rmdir()
        except OSError:
            pass
        # Cleanup refusal retains the authoritative ABORTED marker; all residual
        # payloads were safe projections, never private/source material.
        raise


def export_shareable(bundle: Path, original_plan: Path, out: Path, *, deadline=None) -> dict:
    """Preserve original policy/threshold or refuse; mint fresh unlinked safe IDs."""
    deadline = monotonic() + MAX_SECONDS if deadline is None else deadline
    def check():
        if monotonic() > deadline:
            raise InputError("share_time_limit")
    bundle, out = Path(bundle).absolute(), Path(out).absolute()
    if (".." in bundle.parts or ".." in out.parts
            or any(path.drive.startswith("\\\\") for path in (bundle, out, Path(original_plan).absolute()))):
        raise InputError("share_plain_local_paths_required")
    if out.is_relative_to(bundle):
        raise InputError("share_output_inside_private_bundle")
    verified = verify_report(bundle, original_plan, deadline=deadline)
    if not verified["run_manifest_bound"]:
        raise InputError("share_bound_bundle_required")
    private_raw = read_source_bytes(bundle / "private.json")
    shared_raw = read_source_bytes(bundle / "shareable.json")
    private_html = read_source_bytes(bundle / "private.html")
    shared_html = read_source_bytes(bundle / "shareable.html")
    descriptor_raw = read_source_bytes(bundle / DESCRIPTOR_FILE)
    if len(descriptor_raw) > 65_536:
        raise InputError("share_descriptor_limit")
    descriptor = ReportProvenance.model_validate_json(descriptor_raw)
    declared_pins = {row.path: row.sha256 for row in descriptor.source_files}
    if _current_pins(check) != declared_pins:
        raise InputError("share_installed_code_policy_mismatch")
    original_private = decode_source(private_raw)
    original_shared = decode_source(shared_raw)
    check()
    plan = load_plan(original_plan)
    if plan.identity.sha256 != verified["plan_sha256"]:
        raise InputError("share_source_pin_mismatch")
    rebuilt = build_report(plan, evaluate(plan), fail_on=descriptor.config.fail_on)
    check()
    for old, fresh, is_private in ((original_private, rebuilt.private, True),
                                   (original_shared, rebuilt.shareable, False)):
        if _json_bytes(_semantic(old, private=is_private)) != _json_bytes(_semantic(fresh, private=is_private)):
            raise InputError("share_canonical_review_mismatch")
    if private_html != _html(original_private) or shared_html != _html(original_shared):
        raise InputError("share_stored_html_not_canonical")
    # Fresh projection/renderer ONLY. Never write private, original source, stored
    # HTML, original IDs, raw-source hash or the descriptor under the output path.
    payloads = {"shareable.json": _json_bytes(rebuilt.shareable), "shareable.html": _html(rebuilt.shareable)}
    public_manifest = {
        "schema_version": "1.0.0", "projection": "shareable", "run_id": rebuilt.shareable["run_id"],
        "parser_version": rebuilt.shareable["parser_version"], "policy_version": rebuilt.shareable["policy_version"],
        "review_exit_code": rebuilt.exit_code, "source_resolvable": False,
        "artifacts": {name: sha256(raw).hexdigest() for name, raw in payloads.items()},
        "measurements": {arm: "NOT MEASURED" for arm in ("D", "L", "P", "M", "C", "C-custom", "T")},
        "integrity_notice": "Safe artifact integrity only; no source mapping, producer authentication or benchmark proof.",
    }
    payloads["manifest.json"] = _json_bytes(public_manifest)
    payloads["manifest.sha256"] = (sha256(payloads["manifest.json"]).hexdigest() + "\n").encode("ascii")
    expected_hashes = {name: sha256(raw).hexdigest() for name, raw in (
        ("private.json", private_raw), ("shareable.json", shared_raw), (DESCRIPTOR_FILE, descriptor_raw))}
    expected_hashes.update({"private.html": sha256(private_html).hexdigest(),
                            "shareable.html": sha256(shared_html).hexdigest()})
    def recheck():
        check()
        verify_unchanged(plan)
        verify_report(bundle, original_plan, deadline=deadline)
        if (_current_pins(check) != declared_pins or any(
                sha256(read_source_bytes(bundle / name)).hexdigest() != pin for name, pin in expected_hashes.items())):
            raise InputError("share_inputs_changed")
        check()
    recheck()
    _publish(payloads, out, deadline, recheck, rebuilt.exit_code)
    return {"status": "shareable_exported", "review_exit_code": rebuilt.exit_code,
            "source_resolvable": False, "private_mapping_retained": False, "product_acceptance": False}


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError("invalid share invocation")


def main(argv=None) -> int:
    parser = _Parser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    try:
        args = parser.parse_args(argv)
        result = export_shareable(args.bundle, args.plan, args.out)
    except SystemExit as error:
        return 0 if error.code == 0 else 3
    except (Exception, KeyboardInterrupt):
        sys.stderr.write("share_export_aborted code=validation_or_output\n")
        return 3
    try:
        sys.stdout.write(f"shareable_exported review_exit_code={result['review_exit_code']}; not source-resolvable\n")
    except (OSError, KeyboardInterrupt):
        pass
    return result["review_exit_code"]
