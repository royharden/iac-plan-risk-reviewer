"""Read-only verification of complete local bundles and explicitly pinned facts.

No report-supplied file path is opened. HTML is hashed as bytes, never rendered.
Exact addresses/pointers appear only in the explicitly private evidence result.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from datetime import datetime
from hashlib import sha256
import json
import math
from pathlib import Path
import re
import sys
from time import monotonic
from typing import Any, Sequence

from iac_review.contracts import PARSER_VERSION, POLICY_VERSION, ValueState
from iac_review.evidence import make_ref, resolve, verify_unchanged
from iac_review.ingest import InputError, MAX_BYTES, MAX_RESOURCES, MAX_SECONDS
from iac_review.ingest import decode_source, load_plan, read_source_bytes

_ARTIFACTS = frozenset({"private.json", "private.html", "shareable.json", "shareable.html"})
_FILES = _ARTIFACTS | {"manifest.json", "manifest.sha256", "export-state.json"}
_HASH = re.compile(r"[0-9a-f]{64}")
_ID = re.compile(r"[0-9a-f]{32}")
_ACTIONS = {"no-op", "create", "read", "update", "delete"}
_TYPES = {
    "aws_security_group_rule", "aws_security_group", "aws_vpc_security_group_ingress_rule",
    "aws_db_instance", "aws_ebs_volume", "aws_rds_cluster", "aws_dynamodb_table",
    "aws_s3_bucket", "aws_efs_file_system", "aws_elasticache_replication_group", "aws_instance",
}
_ENUMS = _ACTIONS | _TYPES | {
    "0.0.0.0/0", "::/0", "ingress", "egress", "tcp", "6", "-1", "udp", "17",
    "icmp", "1", "icmpv6", "58", "managed", "data", "registry.terraform.io/hashicorp/aws",
}
_ATTRIBUTES = {
    "type", "protocol", "from_port", "to_port", "cidr_blocks", "ipv6_cidr_blocks",
    "publicly_accessible", "storage_encrypted", "encrypted", "prefix_list_ids",
    "source_security_group_id", "self",
}


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise InputError(code)


def _check(deadline: float) -> None:
    _require(monotonic() <= deadline, "evidence_view_time_limit")


def _directory(path: Path) -> Path:
    path = Path(path).absolute()
    _require(not any(p.is_symlink() or (hasattr(p, "is_junction") and p.is_junction())
                     for p in (path, *path.parents)), "bundle_link_rejected")
    _require(path.is_dir(), "bundle_directory_required")
    # Check the closed v1 inventory without following or interpreting extra paths.
    names = set()
    for item in path.iterdir():
        names.add(item.name)
        _require(len(names) <= len(_FILES), "bundle_layout_invalid")
    _require(names == _FILES, "bundle_layout_invalid")
    return path


def _read(path: Path, deadline: float, limit: int = MAX_BYTES) -> bytes:
    _check(deadline)
    data = read_source_bytes(path)
    _require(len(data) <= limit, "bundle_file_byte_limit")
    _check(deadline)
    return data


def _json(data: bytes, deadline: float) -> dict[str, Any]:
    return decode_source(data, started=deadline - MAX_SECONDS)


@dataclass(frozen=True)
class _Bundle:
    path: Path
    run_id: str
    plan_sha256: str
    file_hashes: tuple[tuple[str, str], ...]
    private: dict[str, Any] = field(repr=False)
    shareable: dict[str, Any] = field(repr=False)


def _load_bundle(path: Path, deadline: float) -> _Bundle:
    path = _directory(path)
    state_bytes = _read(path / "export-state.json", deadline, 4096)
    state = _json(state_bytes, deadline)
    _require(set(state) == {"state", "exit_code"} and state.get("state") == "COMPLETE",
             "bundle_export_not_complete")
    _require(type(state["exit_code"]) is int and state["exit_code"] in range(4),
             "bundle_exit_invalid")
    manifest_bytes = _read(path / "manifest.json", deadline, 65_536)
    receipt = _read(path / "manifest.sha256", deadline, 128)
    _require(re.fullmatch(rb"[0-9a-f]{64}\n?", receipt) is not None,
             "bundle_manifest_hash_invalid")
    _require(sha256(manifest_bytes).hexdigest() == receipt.decode("ascii").strip(),
             "bundle_manifest_hash_mismatch")
    manifest = _json(manifest_bytes, deadline)
    _require(set(manifest) == {"schema_version", "run_id", "created_at", "plan_sha256",
                              "parser_version", "policy_version", "artifacts", "privacy"},
             "bundle_manifest_schema_invalid")
    _require(manifest["schema_version"] == "1.0.0"
             and manifest["parser_version"] == PARSER_VERSION
             and manifest["policy_version"] == POLICY_VERSION, "bundle_version_unsupported")
    _require(type(manifest["run_id"]) is str and _ID.fullmatch(manifest["run_id"]) is not None
             and type(manifest["plan_sha256"]) is str
             and _HASH.fullmatch(manifest["plan_sha256"]) is not None,
             "bundle_identity_invalid")
    try:
        created = datetime.fromisoformat(manifest["created_at"])
        _require(created.tzinfo is not None, "bundle_timestamp_invalid")
    except (ValueError, TypeError):
        raise InputError("bundle_timestamp_invalid") from None
    catalog = manifest["artifacts"]
    _require(type(catalog) is dict and set(catalog) == _ARTIFACTS,
             "bundle_artifact_catalog_invalid")
    hashes = {"export-state.json": sha256(state_bytes).hexdigest(),
              "manifest.json": sha256(manifest_bytes).hexdigest(),
              "manifest.sha256": sha256(receipt).hexdigest()}
    reports = {}
    for name in sorted(_ARTIFACTS):
        _require(type(catalog[name]) is str and _HASH.fullmatch(catalog[name]) is not None,
                 "bundle_artifact_hash_invalid")
        data = _read(path / name, deadline)
        hashes[name] = sha256(data).hexdigest()
        _require(hashes[name] == catalog[name], "bundle_artifact_hash_mismatch")
        if name.endswith(".json"):
            reports[name] = _json(data, deadline)
    private, shared = reports["private.json"], reports["shareable.json"]
    _require(private.get("projection") == "private" and private.get("sensitive") is True
             and shared.get("projection") == "shareable" and shared.get("sensitive") is False,
             "bundle_private_projection_required")
    for report in (private, shared):
        _require(report.get("schema_version") == "1.0.0"
                 and report.get("parser_version") == PARSER_VERSION
                 and report.get("policy_version") == POLICY_VERSION
                 and report.get("run_id") == manifest["run_id"], "bundle_report_identity_mismatch")
        summary = report.get("summary")
        _require(type(summary) is dict and type(summary.get("exit_code")) is int
                 and summary["exit_code"] == state["exit_code"], "bundle_exit_mismatch")
        rows = report.get("evaluations")
        _require(type(rows) is list and len(rows) <= MAX_RESOURCES * 4
                 and all(type(row) is dict for row in rows), "bundle_rows_invalid")
        ids = [row.get("finding_id") for row in rows]
        _require(all(type(value) is str and _ID.fullmatch(value) is not None for value in ids)
                 and len(set(ids)) == len(ids), "bundle_finding_ids_invalid")
    _require(type(private.get("plan")) is dict
             and private["plan"].get("sha256") == manifest["plan_sha256"],
             "bundle_plan_identity_mismatch")
    _require(private.get("case_id") == shared.get("case_id")
             and _ID.fullmatch(str(private.get("case_id"))) is not None,
             "bundle_case_identity_mismatch")
    _require([r["finding_id"] for r in private["evaluations"]]
             == [r["finding_id"] for r in shared["evaluations"]], "bundle_projection_join_mismatch")
    return _Bundle(path, manifest["run_id"], manifest["plan_sha256"],
                   tuple(sorted(hashes.items())), private, shared)


def _recheck(bundle: _Bundle, deadline: float) -> None:
    _directory(bundle.path)
    for name, expected in bundle.file_hashes:
        _require(sha256(_read(bundle.path / name, deadline)).hexdigest() == expected,
                 "bundle_changed_during_view")


def _plan(bundle: _Bundle, original_plan: Path, deadline: float):
    _require(sha256(_read(Path(original_plan), deadline)).hexdigest() == bundle.plan_sha256,
             "evidence_source_digest_mismatch")
    plan = load_plan(Path(original_plan))
    _require(plan.identity.sha256 == bundle.plan_sha256, "evidence_source_digest_mismatch")
    _check(deadline)
    return plan


def verify_report(bundle_path: Path, original_plan: Path | None = None,
                  *, deadline: float | None = None) -> dict[str, Any]:
    """Verify integrity only, optionally the supplied source pin; never a security verdict."""
    deadline = monotonic() + MAX_SECONDS if deadline is None else deadline
    bundle = _load_bundle(bundle_path, deadline)
    if original_plan is not None:
        plan = _plan(bundle, original_plan, deadline)
        verify_unchanged(plan)
    _recheck(bundle, deadline)
    if original_plan is not None:
        verify_unchanged(plan)
    _check(deadline)
    return {"status": "complete_bundle_integrity_verified", "run_id": bundle.run_id,
            "plan_sha256": bundle.plan_sha256, "artifacts_verified": len(_ARTIFACTS),
            "source_digest_verified": original_plan is not None,
            "raw_source_access_enabled": False, "producer_authenticated": False,
            "product_acceptance": False}


def _locator(pointer: Any, side: Any) -> tuple[int, tuple[str | int, ...], str]:
    _require(type(pointer) is str and len(pointer) <= 4096 and pointer.startswith("/")
             and re.search(r"~(?:[^01]|$)", pointer) is None, "evidence_pointer_invalid")
    parts = tuple(p.replace("~1", "/").replace("~0", "~") for p in pointer[1:].split("/"))
    _require(len(parts) >= 3 and parts[0] == "resource_changes"
             and re.fullmatch(r"0|[1-9][0-9]*", parts[1]) is not None,
             "evidence_pointer_anchor_invalid")
    index = int(parts[1])
    if side == "metadata":
        tokens = parts[2:]
        _require(tokens in (("provider_name",), ("mode",), ("type",), ("change", "replace_paths")),
                 "evidence_field_outside_view_scope")
        return index, tokens, tokens[-1]
    _require(side in ("before", "after", "actions")
             and len(parts) >= 4 and parts[2:4] == ("change", side),
             "evidence_pointer_side_invalid")
    tokens = parts[4:]
    if side == "actions":
        _require(not tokens, "evidence_field_outside_view_scope")
        return index, (), "actions"
    if not tokens:
        return index, (), side
    _require(tokens[0] in _ATTRIBUTES and len(tokens) <= 2, "evidence_field_outside_view_scope")
    if len(tokens) == 2:
        _require(tokens[0] in ("cidr_blocks", "ipv6_cidr_blocks")
                 and re.fullmatch(r"0|[1-9][0-9]*", tokens[1]) is not None,
                 "evidence_field_outside_view_scope")
        return index, (tokens[0], int(tokens[1])), tokens[0]
    return index, tokens, tokens[0]


def _safe_fact(state: ValueState) -> tuple[Any, str]:
    """Closed projection matching report v1; no recursive object/tag/string dump."""
    if state.sensitive:
        return None, "sensitive"
    if state.state != "known":
        return None, state.state
    value = state.value
    if type(value) is bool or type(value) is int and abs(value) <= 2**53:
        return value, "known"
    if type(value) is float and math.isfinite(value):
        return value, "known"
    if type(value) is str and value in _ENUMS:
        return value, "known"
    if isinstance(value, (list, tuple)) and all(type(v) is str and v in _ACTIONS for v in value):
        return list(value), "known"
    if isinstance(value, (dict, list, tuple)):
        return None, "present_container"
    return None, "privacy_omitted"


def view_evidence(bundle_path: Path, original_plan: Path, finding_id: str, fact_id: str,
                  *, deadline: float | None = None) -> dict[str, Any]:
    """Resolve one selected private fact. Model text/selections are never inputs."""
    deadline = monotonic() + MAX_SECONDS if deadline is None else deadline
    _require(type(finding_id) is str and _ID.fullmatch(finding_id) is not None
             and type(fact_id) is str and _ID.fullmatch(fact_id) is not None,
             "evidence_opaque_id_required")
    bundle = _load_bundle(bundle_path, deadline)
    private_rows = [r for r in bundle.private["evaluations"] if r["finding_id"] == finding_id]
    shared_rows = [r for r in bundle.shareable["evaluations"] if r["finding_id"] == finding_id]
    _require(len(private_rows) == len(shared_rows) == 1, "evidence_finding_not_found")
    row, public = private_rows[0], shared_rows[0]
    _require(row.get("rule_id") in ("R1", "R2", "R3", "R4")
             and row.get("outcome") in (None, "introduced_risk", "unchanged_risk", "clear", "indeterminate"),
             "evidence_finding_invalid")
    _require(all(row.get(k) == public.get(k) for k in (
        "resource_id", "rule_id", "rule_version", "severity", "applicability", "outcome")),
        "evidence_finding_projection_mismatch")
    for projection in (row, public):
        facts = projection.get("facts")
        _require(type(facts) is list and len(facts) <= 256
                 and all(type(fact) is dict for fact in facts), "evidence_facts_invalid")
        ids = [f.get("fact_id") for f in facts]
        _require(all(type(v) is str and _ID.fullmatch(v) is not None for v in ids)
                 and len(set(ids)) == len(ids), "evidence_fact_ids_invalid")
    facts = [f for f in row["facts"] if f["fact_id"] == fact_id]
    public_facts = [f for f in public["facts"] if f["fact_id"] == fact_id]
    _require(len(facts) == len(public_facts) == 1, "evidence_fact_not_found")
    fact, public_fact = facts[0], public_facts[0]
    _require(set(fact) == {"fact_id", "field", "side", "role", "state", "value", "pointer", "resolution"}
             and set(public_fact) == {"fact_id", "field", "side", "role", "state", "value"}
             and all(fact[k] == public_fact[k] for k in public_fact),
             "evidence_fact_projection_mismatch")
    _require(fact["role"] in ("decision", "supporting"), "evidence_role_invalid")
    index, tokens, expected_field = _locator(fact["pointer"], fact["side"])
    _require(fact["field"] == expected_field, "evidence_pointer_field_mismatch")
    # v1 stores the index in fact locators, not in the private row. Every locator
    # in the selected row must identify that same resource; opaque resource IDs
    # cannot be reused for a different index in another populated finding.
    _require(type(row.get("resource_id")) is str and _ID.fullmatch(row["resource_id"]) is not None,
             "evidence_resource_identity_mismatch")
    for other in bundle.private["evaluations"]:
        _check(deadline)
        other_facts = other.get("facts")
        _require(type(other_facts) is list and len(other_facts) <= 256,
                 "evidence_facts_invalid")
        anchors = set()
        for item in other_facts:
            _require(type(item) is dict, "evidence_facts_invalid")
            anchor, _, _ = _locator(item.get("pointer"), item.get("side"))
            anchors.add(anchor)
        _require(len(anchors) <= 1, "evidence_resource_binding_mismatch")
        if anchors:
            same_id = other.get("resource_id") == row["resource_id"]
            _require(same_id == (index in anchors), "evidence_resource_binding_mismatch")
    plan = _plan(bundle, original_plan, deadline)
    _require(index < len(plan.resources), "evidence_resource_index_invalid")
    resource = plan.resources[index]
    safe_actions = list(resource.actions) if all(a in _ACTIONS for a in resource.actions) else ["unsupported"]
    _require(resource.index == index and row.get("address") == resource.address
             and row.get("actions") == safe_actions, "evidence_resource_identity_mismatch")
    ref = make_ref(plan, resource, fact["side"], tokens, role=fact["role"])
    _require(ref.pointer == fact["pointer"], "evidence_pointer_not_canonical")
    resolved = resolve(plan, ref)
    _require(resolved.status in ("resolved", "unknown", "sensitive")
             and resolved.status == fact["resolution"], "evidence_resolution_mismatch")
    value, state = _safe_fact(resolved.value)
    # JSON encoding distinguishes bool/int and null; Python equality alone does not.
    encoded = lambda v: json.dumps(v, sort_keys=True, allow_nan=False, ensure_ascii=True)
    _require(state == fact["state"] and encoded(value) == encoded(fact["value"]),
             "evidence_value_or_mask_mismatch")
    verify_unchanged(plan)
    _recheck(bundle, deadline)
    verify_unchanged(plan)
    _check(deadline)
    return {
        "projection": "private_evidence", "sensitive": True,
        "privacy_notice": "Exact address and pointer are private; attribute values use a fixed allowlist.",
        "run_id": bundle.run_id, "finding_id": finding_id, "fact_id": fact_id,
        "rule_id": row["rule_id"], "finding_outcome": row["outcome"],
        "location": {"resource_index": index, "address": resource.address, "pointer": ref.pointer},
        "fact": {"field": expected_field, "side": fact["side"], "role": fact["role"],
                 "state": state, "value": value, "resolution": resolved.status},
        "source_digest_verified": True, "producer_authenticated": False,
        "decision_changed": False,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    verify = sub.add_parser("verify-report", help="Verify the COMPLETE bundle and exact artifact hashes")
    verify.add_argument("bundle", type=Path)
    verify.add_argument("--plan", type=Path, help="Optional explicitly supplied original plan")
    evidence = sub.add_parser("evidence", help="View one mask-safe fact at a clearly private exact location")
    evidence.add_argument("bundle", type=Path)
    evidence.add_argument("--plan", type=Path, required=True)
    evidence.add_argument("--finding", required=True)
    evidence.add_argument("--fact", required=True)
    try:
        args = parser.parse_args(argv)
    except SystemExit as error:
        return 0 if error.code == 0 else 3
    try:
        result = verify_report(args.bundle, args.plan) if args.command == "verify-report" else (
            view_evidence(args.bundle, args.plan, args.finding, args.fact))
        sys.stdout.write(json.dumps(result, ensure_ascii=True, allow_nan=False) + "\n")
        return 0
    except InputError as error:
        sys.stderr.write(f"evidence_view_aborted code={error}\n")
    except KeyboardInterrupt:
        sys.stderr.write("evidence_view_aborted code=cancelled\n")
    except Exception:
        sys.stderr.write("evidence_view_aborted code=invalid_bundle_or_source\n")
    return 3
