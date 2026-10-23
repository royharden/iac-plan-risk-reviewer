"""Explicit scanner capability metadata, never execution or measured correctness."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json

from .artifacts import Mapping

ARMS = ("C", "C-custom", "T")
ACTIONS = (("no-op",), ("create",), ("read",), ("update",), ("delete",),
           ("delete", "create"), ("create", "delete"))
SCOPED_TYPES = {"R1": ("aws_security_group_rule",), "R2": ("aws_db_instance",),
                "R3": ("aws_db_instance", "aws_ebs_volume"),
                "R4": ("aws_db_instance", "aws_ebs_volume")}
EXCLUDED_TYPES = {"R1": ("aws_security_group", "aws_vpc_security_group_ingress_rule"),
                  "R2": (), "R3": ("aws_instance",),
                  "R4": ("aws_instance", "aws_rds_cluster", "aws_dynamodb_table",
                         "aws_s3_bucket", "aws_efs_file_system", "aws_elasticache_replication_group")}
KNOWLEDGE_LIMITS = {
    "R1": ("necessary_unknown_or_sensitive_fact", "invalid_or_absent_required_cidr_or_port",
           "prefix_list_or_security_group_source_unsupported", "ports_outside_22_3389_excluded"),
    "R2": ("unknown_prior_with_public_after", "necessary_unknown_or_sensitive_boolean",
           "declared_accessibility_not_routing_proof"),
    "R3": ("necessary_unknown_or_sensitive_prior_or_after", "create_is_not_removal",
           "kms_or_algorithm_changes_out_of_scope"),
    "R4": ("destructive_action_requires_known_prior_existence", "tags_never_suppress",
           "no_actual_data_loss_or_backup_claim"),
}


def metadata_digest(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True, allow_nan=False).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def _candidate(contract: dict) -> dict[str, dict]:
    if (not isinstance(contract, dict)
            or contract.get("schema_version") != "m4-custom-policy-candidate-v1"
            or contract.get("arm") != "C-custom" or contract.get("scanner_name") != "checkov"
            or contract.get("source_enrichment") is not False
            or contract.get("input_kind") != "terraform-plan-json"
            or contract.get("target") != "introduced_risk"):
        raise ValueError("unsupported custom capability contract")
    values = contract.get("rules")
    if not isinstance(values, list) or len(values) != 4:
        raise ValueError("exactly four frozen rule declarations required")
    result = {}
    for row in values:
        if not isinstance(row, dict) or row.get("rule_id") not in SCOPED_TYPES:
            raise ValueError("unknown rule declaration")
        rule = row["rule_id"]
        if rule in result or row.get("types") != list(SCOPED_TYPES[rule]):
            raise ValueError("duplicate or widened rule scope")
        if row.get("check_ids") != ["CKV_M4_" + rule]:
            raise ValueError("unexpected custom check identity")
        candidates = row.get("candidate_actions")
        if (not isinstance(candidates, list) or any(not isinstance(action, list) for action in candidates)
                or any(any(not isinstance(value, str) for value in action) for action in candidates)):
            raise ValueError("ordered candidate action arrays required")
        ordered = [tuple(action) for action in candidates]
        if len(ordered) != len(set(ordered)) or any(action not in ACTIONS for action in ordered):
            raise ValueError("duplicate or unsupported candidate action")
        result[rule] = row
    return result


@dataclass(frozen=True)
class CapabilityCell:
    arm: str
    rule_id: str
    resource_type: str
    actions: tuple[str, ...]
    declaration_status: str
    check_ids: tuple[str, ...]
    reason_codes: tuple[str, ...]
    mapping_sha256: str | None = None
    declared_version: str | None = None
    declared_executable_sha256: str | None = None
    declared_policy_sha256: str | None = None
    declared_compatibility_evidence_sha256: str | None = None
    source_enrichment: bool = False
    measured_correctness: bool = False
    execution_eligible: bool = False


def inventory(contract: dict, mappings: tuple[Mapping, ...] = ()) -> dict:
    """Export a closed policy grid without probing/installing/running scanners.

    A verified Mapping is still only a supplied declaration in this inventory.
    It does not constitute execution eligibility or a correctness measurement.
    """
    candidates = _candidate(contract)
    if len(mappings) > 12:
        raise ValueError("scanner mapping inventory exceeds four rules per arm")
    index = {}
    for mapping in mappings:
        identity = mapping.arm, mapping.rule_id
        if identity in index:
            raise ValueError("duplicate arm/rule mapping")
        if (not set(mapping.supported_types) <= set(SCOPED_TYPES[mapping.rule_id])
                or any(action not in ACTIONS for action in mapping.supported_actions)):
            raise ValueError("mapping widens the selected predicate scope")
        index[identity] = mapping
    cells = []
    for arm in ARMS:
        for rule, types in SCOPED_TYPES.items():
            mapping = index.get((arm, rule))
            mapping_sha = metadata_digest(mapping.model_dump(mode="json")) if mapping else None
            for resource_type in types + EXCLUDED_TYPES[rule]:
                for actions in ACTIONS:
                    reasons = list(KNOWLEDGE_LIMITS[rule])
                    checks, status = (), "unmapped"
                    if resource_type not in types:
                        status = "unsupported_scope"
                        reasons.append("type_not_in_selected_v1_predicate")
                    elif actions == ("read",) or (actions == ("delete",) and rule != "R4"):
                        status = "target_not_applicable"
                        reasons.append("action_does_not_have_this_change_target")
                    elif arm == "C-custom" and rule == "R4" and actions == ("delete",):
                        status = "incomplete_callback"
                        reasons.append("delete_only_may_not_reach_planned_values_callback")
                    elif mapping is not None:
                        checks = mapping.check_ids
                        if (actions not in mapping.supported_actions
                                or resource_type not in mapping.supported_types):
                            reasons.append("mapping_excludes_action_type_cell")
                        elif mapping.compatibility == "incompatible":
                            status = "declared_incompatible"
                            reasons.append("external_incompatibility_claim_not_reexecuted")
                        elif mapping.compatibility == "verified" and checks:
                            status = "declared_compatible"
                            reasons.append("supplied_compatibility_declaration_only")
                        else:
                            status = "declared_unverified"
                            reasons.append("compatibility_not_verified")
                    elif arm == "C-custom" and list(actions) in candidates[rule]["candidate_actions"]:
                        status = "candidate_unverified"
                        checks = tuple(candidates[rule]["check_ids"])
                        reasons.extend(("scanner_installation_not_verified", "compatibility_not_verified",
                                        "raw_plan_bridge_not_exercised"))
                    else:
                        reasons.append("no_exact_transition_mapping_declared")
                    cells.append(CapabilityCell(arm, rule, resource_type, actions, status, checks,
                                                tuple(sorted(set(reasons))), mapping_sha,
                                                mapping.version if mapping else None,
                                                mapping.executable_sha256 if mapping else None,
                                                mapping.policy_sha256 if mapping else None,
                                                mapping.compatibility_evidence_sha256 if mapping else None))
    return {"schema_version": "m4-scanner-capabilities-v1", "kind": "capability_metadata_only",
            "measurement_status": "NOT_MEASURED", "product_acceptance": False,
            "source_enrichment": False, "candidate_contract_sha256": metadata_digest(contract),
            "arms": list(ARMS), "cells": [asdict(cell) for cell in cells],
            "limitations": ["No scanner installation, execution, compatibility or correctness is proven.",
                            "No outcome, gold label, eligibility or confusion count is emitted.",
                            "Unmapped/unknown/callback/deposed gaps cannot be counted as true negatives.",
                            "Duplicate/deposed raw identities remain unrepresentable by the current adapters.",
                            "Binary checks cannot recover exact unchanged-versus-clear or decision evidence."]}
