"""Four bounded AWS change predicates; no model, cloud or process effects.

This module consumes normalized input and creates evidence references. The report
stage must resolve every decision reference against the pinned source bytes before
displaying a determinate result. Rule results alone are not report acceptance.
"""

from dataclasses import dataclass, field
from ipaddress import ip_network
from typing import Literal
from uuid import uuid4

from iac_review.contracts import (
    AWS_PROVIDER,
    EvidenceRef,
    PlanDocument,
    ResourceChange,
    RuleEvaluation,
    ValueState,
)
from iac_review.evidence import make_ref, read_value

RuleId = Literal["R1", "R2", "R3", "R4"]
Side = Literal["before", "after", "actions", "metadata"]
Outcome = Literal["introduced_risk", "unchanged_risk", "clear", "indeterminate"]
Applicability = Literal["supported", "not_applicable", "unsupported_shape"]

SEVERITIES: dict[RuleId, int] = {"R1": 4, "R2": 3, "R3": 3, "R4": 4}
SENSITIVE_PORTS = frozenset({22, 3389})
SUPPORTED_TYPES = {
    "R1": frozenset({"aws_security_group_rule"}),
    "R2": frozenset({"aws_db_instance"}),
    "R3": frozenset({"aws_db_instance", "aws_ebs_volume"}),
    "R4": frozenset({"aws_db_instance", "aws_ebs_volume"}),
}
UNSUPPORTED_TYPES = {
    "R1": frozenset({"aws_security_group", "aws_vpc_security_group_ingress_rule"}),
    "R2": frozenset(),
    "R3": frozenset(),
    "R4": frozenset(
        {
            "aws_instance",
            "aws_rds_cluster",
            "aws_dynamodb_table",
            "aws_s3_bucket",
            "aws_efs_file_system",
            "aws_elasticache_replication_group",
        }
    ),
}
WRITE_ACTIONS = frozenset(
    {
        ("create",),
        ("update",),
        ("no-op",),
        ("delete",),
        ("delete", "create"),
        ("create", "delete"),
    }
)


@dataclass
class _Facts:
    plan: PlanDocument
    resource: ResourceChange
    decision: list[EvidenceRef] = field(default_factory=list)
    supporting: list[EvidenceRef] = field(default_factory=list)
    decision_pointers: set[str] = field(default_factory=set)
    supporting_pointers: set[str] = field(default_factory=set)
    coverage: set[str] = field(default_factory=set)

    def get(
        self,
        side: Side,
        tokens: tuple[str | int, ...] = (),
        *,
        supporting: bool = False,
    ) -> ValueState:
        value = read_value(self.resource, side, tokens)
        ref = make_ref(
            self.plan,
            self.resource,
            side,
            tokens,
            role="supporting" if supporting else "decision",
        )
        target = self.supporting if supporting else self.decision
        pointers = self.supporting_pointers if supporting else self.decision_pointers
        # Repeated use of one source fact is one reference, not extra evidence.
        if ref.pointer not in pointers:
            target.append(ref)
            pointers.add(ref.pointer)
        return value

    def require(self, refs: tuple[EvidenceRef, ...]) -> None:
        for ref in refs:
            if ref.pointer not in self.decision_pointers:
                self.decision.append(ref.model_copy(update={"role": "decision"}))
                self.decision_pointers.add(ref.pointer)

    def result(
        self,
        rule_id: RuleId,
        outcome: Outcome | None,
        reason: str,
        applicability: Applicability = "supported",
    ) -> RuleEvaluation:
        return RuleEvaluation(
            evaluation_id=uuid4().hex,
            resource_key=self.resource.key,
            rule_id=rule_id,
            severity=SEVERITIES[rule_id],
            applicability=applicability,
            outcome=outcome,
            reason_code=reason,
            decision_refs=tuple(self.decision),
            supporting_refs=tuple(
                ref
                for ref in self.supporting
                if ref.pointer not in self.decision_pointers
            ),
            coverage=tuple(sorted(self.coverage)),
        )


def _known(value: ValueState) -> bool:
    return value.state == "known" and not value.sensitive


def _boolean(value: ValueState) -> bool:
    return _known(value) and type(value.value) is bool


def _common(facts: _Facts, rule_id: RuleId) -> RuleEvaluation | None:
    """Classify domain and action applicability before reading rule attributes."""
    resource = facts.resource
    for token in ("mode", "provider_name", "type"):
        facts.get("metadata", (token,))
    facts.get("actions")
    if resource.mode == "data":
        return facts.result(rule_id, None, "data_resource_not_applicable", "not_applicable")
    related = resource.type in SUPPORTED_TYPES[rule_id] | UNSUPPORTED_TYPES[rule_id]
    if not related:
        return facts.result(rule_id, None, "resource_type_outside_policy", "not_applicable")
    if resource.mode != "managed":
        return facts.result(rule_id, None, "resource_mode_unsupported", "unsupported_shape")
    if resource.provider_name != AWS_PROVIDER:
        return facts.result(rule_id, None, "provider_not_supported", "unsupported_shape")
    if not resource.action_supported:
        return facts.result(rule_id, None, "action_sequence_unsupported", "unsupported_shape")
    if resource.type in UNSUPPORTED_TYPES[rule_id]:
        return facts.result(rule_id, None, "targeted_resource_shape_unsupported", "unsupported_shape")
    if resource.actions == ("read",):
        if rule_id == "R4":
            return facts.result(rule_id, "clear", "read_has_no_destructive_action")
        return facts.result(rule_id, None, "read_has_no_write_transition", "not_applicable")
    if resource.actions not in WRITE_ACTIONS:
        return facts.result(rule_id, None, "action_sequence_unsupported", "unsupported_shape")
    if resource.actions == ("delete",) and rule_id != "R4":
        return facts.result(rule_id, None, "delete_has_no_after_configuration", "not_applicable")
    return None


@dataclass
class _Exposure:
    members: set[tuple[str, int]] = field(default_factory=set)
    complete: bool = True
    reason: str = "exposure_known"
    egress: bool = False


def _source_coverage(facts: _Facts, side: Side) -> None:
    """Unsupported source kinds never acquire an invented private/clear label."""
    for key, code in (
        ("prefix_list_ids", "r1_prefix_list_source_unsupported"),
        ("source_security_group_id", "r1_security_group_source_unsupported"),
        ("self", "r1_security_group_source_unsupported"),
    ):
        value = facts.get(side, (key,), supporting=True)
        if value.sensitive or value.state == "unknown":
            facts.coverage.add("r1_source_coverage_unknown")
        elif value.state in {"absent", "null"}:
            continue
        elif not _known(value):
            facts.coverage.add("r1_source_coverage_unknown")
        elif key == "prefix_list_ids":
            if not isinstance(value.value, list):
                facts.coverage.add("r1_source_coverage_unknown")
            elif value.value:
                facts.coverage.add(code)
        elif key == "self":
            if type(value.value) is not bool:
                facts.coverage.add("r1_source_coverage_unknown")
            elif value.value:
                facts.coverage.add(code)
        elif value.value != "":
            facts.coverage.add(code)


def _world_families(facts: _Facts, side: Side) -> tuple[set[str], bool, str]:
    families: set[str] = set()
    complete = True
    reason = "cidr_lists_known"
    for field_name, family, expected_version in (
        ("cidr_blocks", "IPv4", 4),
        ("ipv6_cidr_blocks", "IPv6", 6),
    ):
        sequence = facts.get(side, (field_name,), supporting=True)
        if not _known(sequence) or not isinstance(sequence.value, list):
            complete = False
            reason = "required_cidr_list_indeterminate"
            continue
        for index in range(len(sequence.value)):
            item = facts.get(side, (field_name, index), supporting=True)
            if not _known(item) or not isinstance(item.value, str):
                complete = False
                reason = "cidr_entry_indeterminate"
                continue
            try:
                network = ip_network(item.value, strict=True)
            except ValueError:
                complete = False
                reason = "cidr_entry_invalid"
                continue
            if network.version != expected_version:
                complete = False
                reason = "cidr_family_mismatch"
            elif network.prefixlen == 0:
                families.add(family)
    return families, complete, reason


def _exposure(facts: _Facts, side: Side) -> _Exposure:
    direction = facts.get(side, ("type",))
    if _known(direction) and direction.value == "egress":
        return _Exposure(reason="egress_not_applicable", egress=True)
    if not _known(direction):
        return _Exposure(complete=False, reason="ingress_direction_indeterminate")
    if direction.value != "ingress":
        return _Exposure(complete=False, reason="ingress_direction_invalid")

    _source_coverage(facts, side)
    # Read without promoting an irrelevant unknown protocol to decision evidence:
    # a complete non-world CIDR set alone is a sufficient negative proof.
    protocol = read_value(facts.resource, side, ("protocol",))
    if _known(protocol):
        if not isinstance(protocol.value, str):
            facts.get(side, ("protocol",))
            return _Exposure(complete=False, reason="protocol_invalid")
        if protocol.value not in {"tcp", "6", "-1"}:
            facts.get(side, ("protocol",))
            if protocol.value in {"udp", "icmp", "icmpv6"} or (
                len(protocol.value) <= 3
                and protocol.value.isdecimal()
                and 0 <= int(protocol.value) <= 255
            ):
                return _Exposure(reason="non_tcp_protocol")
            return _Exposure(complete=False, reason="protocol_invalid")

    cidr_start = len(facts.supporting)
    families, cidrs_complete, cidr_reason = _world_families(facts, side)
    cidr_refs = tuple(facts.supporting[cidr_start:])
    # A wholly known, non-world source proves this predicate false even if its
    # irrelevant protocol/ports are unavailable. Unsupported source coverage is
    # separately retained, including when a known CIDR proves a bounded risk.
    if cidrs_complete and not families:
        facts.require(cidr_refs)
        return _Exposure(reason="no_world_cidr")
    facts.get(side, ("protocol",))
    if not _known(protocol):
        facts.require(cidr_refs)
        return _Exposure(complete=False, reason="protocol_indeterminate")
    if protocol.value == "-1":
        ports = SENSITIVE_PORTS
    else:
        start = facts.get(side, ("from_port",))
        end = facts.get(side, ("to_port",))
        if (
            not _known(start)
            or not _known(end)
            or type(start.value) is not int
            or type(end.value) is not int
        ):
            return _Exposure(complete=False, reason="required_port_range_indeterminate")
        if not 0 <= start.value <= end.value <= 65535:
            return _Exposure(complete=False, reason="port_range_invalid")
        ports = frozenset(port for port in SENSITIVE_PORTS if start.value <= port <= end.value)
        if not ports:
            return _Exposure(reason="no_sensitive_port")
    facts.require(cidr_refs)
    return _Exposure(
        members={(family, port) for family in families for port in ports},
        complete=cidrs_complete,
        reason="exposure_known" if cidrs_complete else cidr_reason,
    )


def _r1(facts: _Facts) -> RuleEvaluation:
    after = _exposure(facts, "after")
    if after.egress:
        return facts.result("R1", None, "egress_not_applicable", "not_applicable")
    if not after.complete:
        return facts.result("R1", "indeterminate", after.reason)
    if not after.members:
        return facts.result("R1", "clear", after.reason)
    if facts.resource.actions == ("create",):
        return facts.result("R1", "introduced_risk", "new_world_admin_exposure")
    before = _exposure(facts, "before")
    if not before.complete:
        return facts.result("R1", "indeterminate", "prior_exposure_indeterminate")
    if after.members - before.members:
        return facts.result("R1", "introduced_risk", "new_world_admin_exposure")
    return facts.result("R1", "unchanged_risk", "world_admin_exposure_remains")


def _r2(facts: _Facts) -> RuleEvaluation:
    after = facts.get("after", ("publicly_accessible",))
    if not _boolean(after):
        return facts.result("R2", "indeterminate", "public_access_after_indeterminate")
    if after.value is False:
        return facts.result("R2", "clear", "public_access_after_false")
    if facts.resource.actions == ("create",):
        return facts.result("R2", "introduced_risk", "public_access_on_create")
    before = facts.get("before", ("publicly_accessible",))
    if not _boolean(before):
        return facts.result("R2", "indeterminate", "public_access_prior_indeterminate")
    if before.value is False:
        return facts.result("R2", "introduced_risk", "public_access_false_to_true")
    return facts.result("R2", "unchanged_risk", "public_access_remains_true")


def _r3(facts: _Facts) -> RuleEvaluation:
    name = "storage_encrypted" if facts.resource.type == "aws_db_instance" else "encrypted"
    after = facts.get("after", (name,))
    if not _boolean(after):
        return facts.result("R3", "indeterminate", "encryption_after_indeterminate")
    if facts.resource.actions == ("create",):
        return facts.result("R3", "clear", "create_is_not_encryption_removal")
    before = facts.get("before", (name,))
    if not _boolean(before):
        return facts.result("R3", "indeterminate", "encryption_prior_indeterminate")
    if before.value is True and after.value is False:
        return facts.result("R3", "introduced_risk", "encryption_true_to_false")
    return facts.result("R3", "clear", "no_encryption_removal")


def _r4(facts: _Facts) -> RuleEvaluation:
    if "delete" not in facts.resource.actions:
        return facts.result("R4", "clear", "no_destructive_action")
    prior = facts.get("before")
    if prior.sensitive or prior.state == "unknown":
        return facts.result("R4", "indeterminate", "prior_existence_indeterminate")
    if prior.state in {"absent", "null"}:
        return facts.result("R4", "indeterminate", "contradictory_prior_existence")
    if not _known(prior) or not isinstance(prior.value, dict):
        return facts.result("R4", "indeterminate", "prior_shape_indeterminate")
    # replace_paths is supporting metadata only. Absent/unknown/bad optional
    # metadata must never erase proven destructive intent or become an after ref.
    facts.get("metadata", ("change", "replace_paths"), supporting=True)
    return facts.result("R4", "introduced_risk", "stateful_destructive_intent")


def evaluate(plan: PlanDocument) -> tuple[RuleEvaluation, ...]:
    """Evaluate the frozen v1 policy without reading labels or invoking tools."""
    results: list[RuleEvaluation] = []
    evaluators = {"R1": _r1, "R2": _r2, "R3": _r3, "R4": _r4}
    for resource in plan.resources:
        for rule_id, evaluator in evaluators.items():
            facts = _Facts(plan, resource)
            common_result = _common(facts, rule_id)
            results.append(common_result if common_result is not None else evaluator(facts))
    return tuple(results)


__all__ = ["SEVERITIES", "SENSITIVE_PORTS", "SUPPORTED_TYPES", "UNSUPPORTED_TYPES", "evaluate"]
