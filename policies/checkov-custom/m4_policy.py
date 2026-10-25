"""Independent raw-plan policy v1; no product detector, gold or scorer imports.

These are candidate scanner policies, not an independent oracle. Checkov callbacks
do not expose all before/mask facts, so the bridge reads the SAME pinned plan.
Missing callbacks (notably deletes) remain incomplete in the comparison driver.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import dataclass
from pathlib import Path

AWS = "registry.terraform.io/hashicorp/aws"
ACTIONS = {(v,) for v in ("no-op", "create", "read", "update", "delete")} | {
    ("create", "delete"), ("delete", "create")}
TYPES = {"R1": ("aws_security_group_rule",), "R2": ("aws_db_instance",),
         "R3": ("aws_db_instance", "aws_ebs_volume"),
         "R4": ("aws_db_instance", "aws_ebs_volume")}
MISSING = object()


@dataclass(frozen=True)
class Decision:
    rule_id: str
    applicability: str
    outcome: str | None
    reason: str
    coverage: tuple[str, ...] = ()


def unknown(rule: str, reason: str, coverage: tuple[str, ...] = ()) -> Decision:
    return Decision(rule, "supported", "indeterminate", reason, coverage)


def _masked(mask: object) -> bool:
    if mask is False:
        return False
    if isinstance(mask, dict):
        return any(_masked(value) for value in mask.values())
    if isinstance(mask, list):
        return any(_masked(value) for value in mask)
    return True  # True, null and malformed masks cannot assert known values.


def value(resource: dict, side: str, key: str) -> object:
    change = resource.get("change")
    if not isinstance(change, dict):
        return MISSING
    data = change.get(side)
    if not isinstance(data, dict):
        return MISSING
    for name in (f"{side}_sensitive",) + (("after_unknown",) if side == "after" else ()):
        mask = change.get(name, {})
        if mask is True or not isinstance(mask, (dict, bool)):
            return MISSING
        if isinstance(mask, dict) and _masked(mask.get(key, False)):
            return MISSING
    return data.get(key, MISSING)


def _exposures(resource: dict, side: str) -> tuple[frozenset, bool, tuple[str, ...]]:
    """Known non-world/egress/other protocols short-circuit unknown ports."""
    kind = value(resource, side, "type")
    if kind == "egress":
        return frozenset(), True, ()
    if kind != "ingress":
        return frozenset(), False, ()
    coverage = []
    for name in ("prefix_list_ids", "source_security_group_id", "self"):
        field = value(resource, side, name)
        if field is MISSING:
            # Missing optional sources are absent; masked/present sources are unknown.
            raw = resource.get("change", {}).get(side)
            mask = resource.get("change", {}).get(f"{side}_sensitive", {})
            after_mask = resource.get("change", {}).get("after_unknown", {}) if side == "after" else {}
            if (not isinstance(raw, dict) or name in raw
                    or (isinstance(mask, dict) and name in mask)
                    or (isinstance(after_mask, dict) and name in after_mask)):
                coverage.append("unsupported_exposure_source")
        elif field not in (None, False, "", []):
            coverage.append("unsupported_exposure_source")
    worlds = set()
    all_known = True
    for name, family in (("cidr_blocks", 4), ("ipv6_cidr_blocks", 6)):
        cidrs = value(resource, side, name)
        if not isinstance(cidrs, list):
            all_known = False
            continue
        for cidr in cidrs:
            try:
                if not isinstance(cidr, str):
                    raise ValueError("not a CIDR")
                network = ipaddress.ip_network(cidr, strict=True)
                if network.version != family:
                    raise ValueError("wrong IP family")
                if network.prefixlen == 0:
                    worlds.add(family)
            except ValueError:
                all_known = False
    limitations = tuple(sorted(set(coverage)))
    if not worlds and all_known:
        return frozenset(), True, limitations
    protocol = value(resource, side, "protocol")
    if protocol in ("-1", -1):
        ports = (22, 3389)
    elif protocol in ("tcp", "6", 6):
        lower, upper = value(resource, side, "from_port"), value(resource, side, "to_port")
        if type(lower) is not int or type(upper) is not int or not 0 <= lower <= upper <= 65535:
            return frozenset(), False, limitations
        ports = tuple(port for port in (22, 3389) if lower <= port <= upper)
    elif protocol is MISSING or protocol is None or type(protocol) is bool:
        return frozenset(), False, limitations
    elif (protocol in ("udp", "icmp", "icmpv6")
          or (type(protocol) is int and 0 <= protocol <= 255)
          or (isinstance(protocol, str) and len(protocol) <= 3
              and protocol.isascii() and protocol.isdecimal() and int(protocol) <= 255)):
        # A recognized non-TCP protocol proves this TCP predicate absent.
        return frozenset(), True, limitations
    else:
        return frozenset(), False, limitations
    return frozenset((family, port) for family in worlds for port in ports), all_known, limitations


def evaluate_change(resource: dict, rule: str) -> Decision:
    if rule not in TYPES:
        raise ValueError("unknown policy rule")
    if resource.get("mode") == "data":
        return Decision(rule, "not_applicable", None, "data_resource")
    if (resource.get("mode") != "managed" or resource.get("provider_name") != AWS
            or resource.get("type") not in TYPES[rule]):
        return Decision(rule, "unsupported_shape", None, "unsupported_provider_mode_type")
    change = resource.get("change")
    if not isinstance(change, dict):
        return unknown(rule, "missing_change")
    actions = change.get("actions")
    if (not isinstance(actions, list) or any(not isinstance(item, str) for item in actions)
            or tuple(actions) not in ACTIONS):
        return Decision(rule, "unsupported_shape", None, "unsupported_action_order")
    actions = tuple(actions)
    if actions == ("read",):
        return Decision(rule, "not_applicable", None, "read_action")
    if rule == "R4":
        if "delete" in actions:
            before = change.get("before", MISSING)
            if before is MISSING or before is None or not isinstance(before, dict):
                return unknown(rule, "contradictory_prior_existence")
            if change.get("before_sensitive") is True:
                return unknown(rule, "required_prior_unknown_or_invalid")
            return Decision(rule, "supported", "introduced_risk", "declared_stateful_destruction")
        return Decision(rule, "supported", "clear", "no_destructive_action")
    if actions == ("delete",):
        return Decision(rule, "not_applicable", None, "delete_only")
    if rule == "R1":
        after_kind = value(resource, "after", "type")
        if after_kind == "egress":
            return Decision(rule, "not_applicable", None, "egress")
        after, known, coverage = _exposures(resource, "after")
        if not known:
            return unknown(rule, "required_after_unknown_or_invalid", coverage)
        if not after:
            return Decision(rule, "supported", "clear", "no_public_admin_exposure", coverage)
        if actions == ("create",):
            return Decision(rule, "supported", "introduced_risk", "new_public_admin_exposure", coverage)
        before, prior_known, prior_coverage = _exposures(resource, "before")
        coverage = tuple(sorted(set(coverage + prior_coverage)))
        if not prior_known:
            return unknown(rule, "required_prior_unknown_or_invalid", coverage)
        outcome = "introduced_risk" if after - before else "unchanged_risk"
        return Decision(rule, "supported", outcome, "public_admin_exposure_set", coverage)
    field = "publicly_accessible" if rule == "R2" else (
        "storage_encrypted" if resource["type"] == "aws_db_instance" else "encrypted")
    after = value(resource, "after", field)
    if type(after) is not bool:
        return unknown(rule, "required_after_unknown_or_invalid")
    if rule == "R2" and after is False:
        return Decision(rule, "supported", "clear", "after_not_public")
    if actions == ("create",):
        return Decision(rule, "supported", "introduced_risk" if rule == "R2" else "clear",
                        "public_create" if rule == "R2" else "create_not_removal")
    before = value(resource, "before", field)
    if type(before) is not bool:
        return unknown(rule, "required_prior_unknown_or_invalid")
    if rule == "R2":
        return Decision(rule, "supported", "unchanged_risk" if before else "introduced_risk",
                        "public_boolean_transition")
    removed = (before is True and after is False
               and actions in {("update",), ("delete", "create"), ("create", "delete")})
    return Decision(rule, "supported", "introduced_risk" if removed else "clear",
                    "encryption_removed" if removed else "no_encryption_removal")


def _unique(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _nonfinite(_: str) -> object:
    raise ValueError("nonfinite JSON")


def load_resource(path: Path, expected_sha256: str, address: str) -> dict:
    """No fallback to Checkov's lossy conf and no secret-bearing diagnostics."""
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise ValueError("regular absolute raw-plan file required")
    with path.open("rb") as stream:
        raw = stream.read(16 * 1024 * 1024 + 1)
    if len(raw) > 16 * 1024 * 1024 or hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("raw-plan pin mismatch")
    plan = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique,
                      parse_constant=_nonfinite)
    if not isinstance(plan, dict) or plan.get("format_version") not in {"1.0", "1.1", "1.2"}:
        raise ValueError("unadmitted input format")
    resources = plan.get("resource_changes")
    if not isinstance(resources, list):
        raise ValueError("resource changes required")
    seen = set()
    found = None
    for resource in resources:
        if not isinstance(resource, dict) or not isinstance(resource.get("address"), str):
            raise ValueError("malformed identity")
        identity = resource["address"]
        if identity in seen or resource.get("deposed") is not None:
            raise ValueError("Checkov identity cannot represent this input")
        seen.add(identity)
        if identity == address:
            found = resource
    if found is None:
        raise ValueError("callback identity absent from pinned input")
    return found
