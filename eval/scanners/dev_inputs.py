"""Deterministic PUBLIC DEVELOPMENT-ONLY synthetic scanner-input recipes.

No expected risk/admission labels, detector outputs, oracle, randomness, clocks,
Terraform/provider invocation or hidden input. Construction did not run this code.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re

RECIPE_VERSION = "m4-public-scanner-dev-v1"
MAX_CASES = 96
MAX_CASE_BYTES = 64 * 1024
MAX_BUNDLE_BYTES = 2 * 1024 * 1024
AWS = "registry.terraform.io/hashicorp/aws"
ACTIONS = (("create",), ("update",), ("no-op",), ("read",), ("delete",),
           ("delete", "create"), ("create", "delete"))
HEX = re.compile(r"[0-9a-f]{64}\Z")


def _encode(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii") + b"\n"


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _values(kind: str) -> tuple[dict, dict]:
    if kind == "aws_security_group_rule":
        before = {"type": "ingress", "protocol": "tcp", "from_port": 22, "to_port": 22,
                  "cidr_blocks": ["10.42.0.0/16"], "ipv6_cidr_blocks": [],
                  "prefix_list_ids": [], "source_security_group_id": None, "self": False}
        return before, dict(before, cidr_blocks=["0.0.0.0/0"])
    if kind == "aws_db_instance":
        return ({"publicly_accessible": False, "storage_encrypted": True},
                {"publicly_accessible": True, "storage_encrypted": False})
    if kind == "aws_ebs_volume":
        return {"encrypted": True}, {"encrypted": False}
    if kind == "aws_security_group":
        return {"ingress": []}, {"ingress": [{"protocol": "tcp", "from_port": 22,
                "to_port": 22, "cidr_blocks": ["0.0.0.0/0"], "ipv6_cidr_blocks": []}]}
    if kind == "aws_vpc_security_group_ingress_rule":
        return ({"ip_protocol": "tcp", "from_port": 22, "to_port": 22,
                 "cidr_ipv4": "10.42.0.0/16"},
                {"ip_protocol": "tcp", "from_port": 22, "to_port": 22,
                 "cidr_ipv4": "0.0.0.0/0"})
    return {"synthetic_local_field": True}, {"synthetic_local_field": False}


def _resource(kind: str, actions: tuple[str, ...] = ("update",)) -> dict:
    before, after = _values(kind)
    if actions == ("create",):
        before = None
    elif actions == ("delete",):
        after = None
    elif actions in {("no-op",), ("read",)}:
        after = deepcopy(before)
    return {"address": kind + ".synthetic_dev", "mode": "data" if actions == ("read",) else "managed",
            "type": kind, "name": "synthetic_dev", "provider_name": AWS,
            "change": {"actions": list(actions), "before": before, "after": after,
                       "before_sensitive": {}, "after_sensitive": {}, "after_unknown": {}}}


def _plan(resources: list[dict], *, format_version: str = "1.2") -> dict:
    planned, prior, config = [], [], []
    for resource in resources:
        for side, target in (("after", planned), ("before", prior)):
            values = resource["change"].get(side)
            if isinstance(values, dict):
                target.append({key: resource[key] for key in ("address", "mode", "type", "name", "provider_name")}
                              | {"schema_version": 0, "values": deepcopy(values),
                                 "sensitive_values": deepcopy(resource["change"].get(side + "_sensitive", {}))})
        config.append({"address": resource["address"], "mode": resource["mode"],
                       "type": resource["type"], "name": resource["name"],
                       "provider_config_key": "aws", "expressions": {}})
    return {"format_version": format_version, "complete": True, "errored": False,
            "resource_changes": deepcopy(resources),
            "planned_values": {"root_module": {"resources": planned}},
            "prior_state": {"values": {"root_module": {"resources": prior}}},
            "configuration": {"provider_config": {"aws": {"name": "aws", "full_name": AWS}},
                              "root_module": {"resources": config}}}


@dataclass(frozen=True)
class DevInput:
    case_id: str
    payload: bytes
    usage: str
    dimensions: tuple[str, ...]
    configuration_lineage: str
    mutation_lineage: str
    mutation_ancestors: tuple[str, ...]
    resources: tuple[tuple[str, str], ...]

    @property
    def filename(self) -> str:
        return self.case_id + ".json"

    def metadata(self) -> dict:
        return {"case_id": self.case_id, "relative_path": "inputs/" + self.filename,
                "raw_json_sha256": _sha(self.payload), "raw_bytes": len(self.payload),
                "usage": self.usage, "dimensions": list(self.dimensions),
                "configuration_lineage": self.configuration_lineage,
                "mutation_lineage": self.mutation_lineage,
                "mutation_ancestors": list(self.mutation_ancestors),
                "development_only": True, "independent_gold": False,
                "heldout_eligible": False, "synthetic": True,
                "provenance": "implementation_authored_public_recipe_not_terraform_output"}


def build_inputs() -> tuple[DevInput, ...]:
    """Pure bounded recipe expansion. These are public inputs, never labels."""
    result = []

    def add(plan: dict | bytes, family: str, mutation: str, *dimensions: str,
            usage: str = "scanner_input_candidate") -> None:
        raw = plan if isinstance(plan, bytes) else _encode(plan)
        if len(raw) > MAX_CASE_BYTES or len(result) >= MAX_CASES:
            raise ValueError("public development recipe exceeds declared bounds")
        index = len(result) + 1
        resources = ()
        if isinstance(plan, dict):
            resources = tuple((f"sres_{index:04d}_{n:02d}", row["address"])
                              for n, row in enumerate(plan.get("resource_changes", []), 1))
        result.append(DevInput(f"sdev_{index:04d}", raw, usage, tuple(dimensions),
                               "cfg_" + family + "_v1", "mut_" + mutation + "_v1",
                               ("mut_public_recipe_base_v1",), resources))

    for kind in ("aws_security_group_rule", "aws_db_instance", "aws_ebs_volume"):
        for actions in ACTIONS:
            add(_plan([_resource(kind, actions)]), kind, "action_" + "_".join(actions),
                "listed_v1_resource", "ordered_actions", *actions)

    # Every mutation descends from the same explicitly named public SG configuration.
    mutations = (
        ("ipv6_world", {"cidr_blocks": [], "ipv6_cidr_blocks": ["::/0"]}),
        ("mixed_families", {"cidr_blocks": ["0.0.0.0/0"], "ipv6_cidr_blocks": ["::/0"]}),
        ("duplicate_cidr_order", {"cidr_blocks": ["10.42.0.0/16", "0.0.0.0/0", "0.0.0.0/0"]}),
        ("private_cidr", {"cidr_blocks": ["10.42.0.0/16"]}),
        ("numeric_tcp", {"protocol": 6}),
        ("all_protocol", {"protocol": "-1", "from_port": None, "to_port": None}),
        ("egress", {"type": "egress"}),
        ("port_443", {"from_port": 443, "to_port": 443}),
        ("reverse_interval", {"from_port": 3389, "to_port": 22}),
        ("prefix_list_source", {"prefix_list_ids": ["pl-synthetic-local"]}),
        ("null_cidr", {"cidr_blocks": None}),
    )
    for mutation, values in mutations:
        resource = _resource("aws_security_group_rule")
        resource["change"]["after"].update(values)
        add(_plan([resource]), "aws_security_group_rule", mutation, mutation)
    for side, mask_name, mask, dimension in (
            ("after", "after_unknown", {"from_port": True}, "unknown_leaf"),
            ("after", "after_unknown", True, "unknown_ancestor"),
            ("after", "after_sensitive", {"cidr_blocks": True}, "sensitive_leaf"),
            ("after", "after_sensitive", True, "sensitive_ancestor"),
            ("before", "before_sensitive", True, "prior_sensitive_ancestor")):
        resource = _resource("aws_security_group_rule")
        resource["change"][mask_name] = mask
        add(_plan([resource]), "aws_security_group_rule", dimension, dimension, side)
    resource = _resource("aws_security_group_rule")
    del resource["change"]["after"]["ipv6_cidr_blocks"]
    add(_plan([resource]), "aws_security_group_rule", "absent_ipv6_list", "absent")
    for mutation in ("after_unknown_boolean", "after_null_boolean", "before_absent_boolean"):
        resource = _resource("aws_db_instance")
        if mutation == "after_unknown_boolean":
            resource["change"]["after_unknown"] = {"publicly_accessible": True}
        elif mutation == "after_null_boolean":
            resource["change"]["after"]["publicly_accessible"] = None
        else:
            del resource["change"]["before"]["publicly_accessible"]
        add(_plan([resource]), "aws_db_instance", mutation, mutation)
    for kind in ("aws_security_group", "aws_vpc_security_group_ingress_rule", "aws_rds_cluster",
                 "aws_dynamodb_table", "aws_s3_bucket", "aws_efs_file_system",
                 "aws_elasticache_replication_group", "aws_instance"):
        add(_plan([_resource(kind, ("delete",) if kind not in {
            "aws_security_group", "aws_vpc_security_group_ingress_rule"} else ("update",))]),
            kind, "unlisted_shape", "outside_selected_v1_resource")
    resource = _resource("aws_db_instance")
    resource["change"]["actions"] = ["update", "create"]
    add(_plan([resource]), "aws_db_instance", "unlisted_action_order", "unsupported_action_shape")
    for version in ("1.0", "1.1"):
        add(_plan([_resource("aws_db_instance")], format_version=version),
            "aws_db_instance", "synthetic_format_" + version.replace(".", "_"), "format_tag_only")

    # Probes are listed separately; the ordinary driver batch is not made invalid
    # by concatenating malformed/ambiguous identities with comparison candidates.
    resource = _resource("aws_db_instance")
    resource["deposed"] = "synthetic_deposed_key"
    add(_plan([resource]), "aws_db_instance", "deposed", "deposed", usage="admission_probe")
    resource = _resource("aws_db_instance")
    add(_plan([resource, deepcopy(resource)]), "aws_db_instance", "duplicate_address",
        "duplicate_identity", usage="admission_probe")
    add(b'{"format_version":"1.2","resource_changes":[', "wire", "truncated_json",
        "malformed_json", usage="admission_probe")
    original = _encode(_plan([_resource("aws_db_instance")]))
    duplicate = original.replace(b'"format_version":"1.2"',
                                 b'"format_version":"1.1","format_version":"1.2"', 1)
    add(duplicate, "wire", "duplicate_json_key", "duplicate_json_key", usage="admission_probe")
    resource = _resource("aws_db_instance")
    resource["change"]["actions"] = "create"
    add(_plan([resource]), "aws_db_instance", "nonarray_actions", "malformed_actions",
        usage="admission_probe")
    if sum(len(case.payload) for case in result) > MAX_BUNDLE_BYTES:
        raise ValueError("public development bundle exceeds total byte bound")
    return tuple(result)


def write_bundle(output: Path, *, build_sha256: str) -> dict:
    """Later explicit local use only; never overwrite or erase partial output.

    All case bytes and portable bundle metadata are deterministic. The separate
    driver manifest intentionally contains this output directory's absolute paths.
    """
    if not HEX.fullmatch(build_sha256):
        raise ValueError("caller-declared actual build SHA256 required")
    target = output.absolute()
    if target.exists() or any(parent.is_symlink() for parent in (target, *target.parents)):
        raise ValueError("new nonsymlink output directory required")
    cases = build_inputs()
    bundle = {"schema_version": "m4-public-scanner-dev-bundle-v1", "recipe_version": RECIPE_VERSION,
              "development_only": True, "independent_gold": False, "heldout_eligible": False,
              "synthetic": True, "generated_by_terraform": False,
              "tested_terraform_version": None, "tested_aws_provider_version": None,
              "declared_build_sha256": build_sha256,
              "configuration_ancestry": "shared_cfg_id_is_shared_public_configuration_lineage",
              "mutation_ancestry": "shared_mut_id_or_ancestor_is_shared_public_recipe_lineage",
              "cases": [case.metadata() for case in cases],
              "limitations": ["Input recipes only; no expected risk or admission outcomes.",
                              "Not an independent oracle, holdout or measured compatibility corpus.",
                              "Synthetic schema/format tags are untested shape assumptions."]}
    candidates = [case for case in cases if case.usage == "scanner_input_candidate"]
    driver = {"schema_version": "m4-scanner-run-v1", "input_scope": "development_synthetic",
              "development_only": True, "independent_gold": False, "heldout_eligible": False,
              "build_sha256": build_sha256, "arms": {},
              "cases": [{"case_id": case.case_id, "plan_path": str(target / "inputs" / case.filename),
                         "plan_sha256": _sha(case.payload), "resources": [
                             {"resource_id": rid, "address": address} for rid, address in case.resources]}
                        for case in candidates]}
    target.mkdir(parents=True, exist_ok=False)
    # STARTED persists even on failure; COMPLETE is created only after all files.
    with (target / "STARTED").open("x", encoding="ascii") as stream:
        stream.write("PUBLIC DEVELOPMENT ONLY; no gold or execution evidence\n")
    (target / "inputs").mkdir()
    for case in cases:
        with (target / "inputs" / case.filename).open("xb") as stream:
            stream.write(case.payload)
    for filename, payload in (("bundle.json", bundle), ("driver-manifest.json", driver)):
        with (target / filename).open("xb") as stream:
            stream.write(_encode(payload))
    with (target / "COMPLETE").open("x", encoding="ascii") as stream:
        stream.write("INPUT BUNDLE WRITTEN; no compatibility claim\n")
    return bundle
