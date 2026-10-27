"""Canonical closed report v1 wire types. Pure validation, no file/client discovery.

This module is the single owner of the private/shareable report projection types
(seam S2). Public API, all pure and side-effect free:

- ``validate_projection(value, *, projection)`` -> PrivateProjection | ShareableProjection
- ``validate_private_projection(payload)`` / ``validate_shareable_projection(payload)`` -> dict
- ``validate_legacy_private_report(payload)`` -> dict (legacy unbound reports only)
- ``projection_dict(model)`` -> dict
- ``validate_report_pair(private, shareable, *, exit_code)`` -> (PrivateProjection, ShareableProjection)

Every rejection raises ``ValueError("report_projection_invalid")``; input values
never appear in errors. Extra fields are never dropped and report-level truth is never
filled in (nested provenance single-value defaults: see docs/REPORT-WIRE.md). Report provenance is reused, never reconstructed as approval/execution
authority. Import DAG: contracts (Wire) <- contracts.manifest <- provenance <- this
module; contracts/__init__ imports this module lazily, so there is no cycle.
"""
from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from hashlib import sha256
import json
import math
import re
from typing import Annotated, Literal

from pydantic import ConfigDict, Field, field_validator, model_validator

from iac_review.contracts import Wire
from iac_review.contracts.manifest import Digest
from iac_review.provenance import ReportProvenance, descriptor_bytes

REPORT_SCHEMA_VERSION = "1.0.0"
# Wire bounds exist to refuse unbounded input, not to shape well-formed reports.
# Byte limits alone do not bound producer output (a 16 MiB plan could in theory
# yield more); the producer's 30-second review budget (ingest.MAX_SECONDS, with one
# plan re-read per resolved fact) keeps real reports far below these caps. Beyond
# them build_report fails closed with report_projection_invalid; it never emits a
# truncated report.
MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_REPORT_BYTES = 256 * 1024 * 1024
MAX_REPORT_RESOURCES = 10000
MAX_REPORT_ROWS = 40000
MAX_FACTS = 65536
MAX_ACTIONS = MAX_INPUT_BYTES // 4  # each JSON action string costs at least 4 input bytes
MAX_DEPTH = 64
MAX_STRING_BYTES = 256 * 1024
ReportId = Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]
RuleId = Literal["R1", "R2", "R3", "R4"]
Outcome = Literal["introduced_risk", "unchanged_risk", "clear", "indeterminate"]
Applicability = Literal["supported", "not_applicable", "unsupported_shape"]
Action = Literal["no-op", "create", "read", "update", "delete"]
ResourceType = Literal[
    "aws_security_group_rule", "aws_security_group", "aws_vpc_security_group_ingress_rule",
    "aws_db_instance", "aws_ebs_volume", "aws_rds_cluster", "aws_dynamodb_table", "aws_s3_bucket",
    "aws_efs_file_system", "aws_elasticache_replication_group", "aws_instance", "unsupported_resource",
]
FactField = Literal[
    "type", "protocol", "from_port", "to_port", "cidr_blocks", "ipv6_cidr_blocks", "publicly_accessible",
    "storage_encrypted", "encrypted", "actions", "mode", "provider_name", "before", "after", "replace_paths",
    "prefix_list_ids", "source_security_group_id", "self", "source_fact",
]
SafeString = Literal[
    "no-op", "create", "read", "update", "delete", "0.0.0.0/0", "::/0", "ingress", "egress",
    "tcp", "6", "-1", "udp", "17", "icmp", "1", "icmpv6", "58", "managed", "data",
    "registry.terraform.io/hashicorp/aws", "aws_security_group_rule", "aws_security_group",
    "aws_vpc_security_group_ingress_rule", "aws_db_instance", "aws_ebs_volume", "aws_rds_cluster",
    "aws_dynamodb_table", "aws_s3_bucket", "aws_efs_file_system", "aws_elasticache_replication_group", "aws_instance",
]
FiniteValue = bool | Annotated[int, Field(ge=-(2**53), le=2**53)] | Annotated[float, Field(allow_inf_nan=False)] \
    | SafeString | Annotated[list[Action], Field(max_length=MAX_ACTIONS)]
LimitationId = Literal[
    "incomplete_plan", "errored_or_unknown", "unsupported_input", "unsupported_shape", "coverage_gap", "indeterminate",
    "decision_evidence_withheld", "supporting_evidence_omitted", "privacy_value_omitted", "missing_evaluation",
]
# Fixed policy 1.0.0 data mirrored from the installed producer; not a detector.
_SEVERITY = {"R1": 4, "R2": 3, "R3": 3, "R4": 4}
_ROW_LIMITS = frozenset({"decision_evidence_withheld", "indeterminate", "privacy_value_omitted",
                         "supporting_evidence_omitted"})
_NONBLOCKING = frozenset({"supporting_evidence_omitted", "privacy_value_omitted"})
_LIMITATION_TEXT = {
    "incomplete_plan": "Plan completeness is false or absent.",
    "errored_or_unknown": "The plan is errored or its error status is absent.",
    "unsupported_input": "The input includes unsupported parser or action coverage.",
    "unsupported_shape": "A targeted resource shape is unsupported by this policy.",
    "coverage_gap": "A rule reports an additional unsupported coverage component.",
    "indeterminate": "At least one predicate cannot be decided from available safe facts.",
    "decision_evidence_withheld": "A required decision reference failed verification.",
    "supporting_evidence_omitted": "Unverified optional supporting facts were omitted.",
    "privacy_value_omitted": "An attribute value was omitted by the fixed safe-value allowlist.",
    "missing_evaluation": "The supplied evaluations do not cover every resource and rule.",
}
_OUTCOME_TEXT = {
    "introduced_risk": "The supported change introduces this declared risk.",
    "unchanged_risk": "This declared risk remains present; introduction is not claimed.",
    "clear": "No risk was found for this named predicate and supported facts only.",
    "indeterminate": "Necessary facts or evidence could not establish this predicate.",
    None: "This resource is outside the supported predicate or is not applicable.",
}
_RULE_TEXT = {
    "R1": "World-open TCP administration exposure: ports 22 and 3389 only.",
    "R2": "Declared RDS public accessibility; routing is not established.",
    "R3": "Declared encryption removal; other encryption properties are outside scope.",
    "R4": "Declared stateful destructive intent; actual data loss or backups are not established.",
}
# A finite type constraint, not a prose renderer or a new policy evaluation.
ExplanationText = Annotated[str, Field(pattern="^(?:" + "|".join(
    re.escape(a + " " + b) for a in _OUTCOME_TEXT.values() for b in _RULE_TEXT.values()) + ")$")]
LimitationText = Annotated[str, Field(pattern="^(?:" + "|".join(map(re.escape, _LIMITATION_TEXT.values())) + ")$")]
_POINTER_FIELDS = frozenset({
    "type", "protocol", "from_port", "to_port", "cidr_blocks", "ipv6_cidr_blocks",
    "publicly_accessible", "storage_encrypted", "encrypted", "actions", "mode", "provider_name",
    "before", "after", "replace_paths", "prefix_list_ids", "source_security_group_id", "self",
})


class ReportWire(Wire):
    model_config = ConfigDict(hide_input_in_errors=True, revalidate_instances="always")


def _require(ok: bool, code: str) -> None:
    if not ok:
        raise ValueError(code)


class _FactIdentity(ReportWire):
    fact_id: ReportId
    field: FactField
    side: Literal["before", "after", "actions", "metadata"]
    role: Literal["decision", "supporting"]


class _KnownFact(_FactIdentity):
    state: Literal["known"]
    value: FiniteValue

    @field_validator("value", mode="before")
    @classmethod
    def finite_value(cls, value):
        # Integer bounds must run before a union could accept an int as a float.
        _require(type(value) in (bool, int, float, str, list), "report_known_value_type")
        if type(value) is int:
            _require(abs(value) <= 2**53, "report_integer_value_bound")
        if type(value) is float:
            _require(math.isfinite(value), "report_nonfinite_value")
        if type(value) is list:
            _require(all(type(v) is str for v in value), "report_action_value_type")
        return value


class _MaskedFact(_FactIdentity):
    state: Literal["null", "absent", "unknown", "sensitive", "present_container", "privacy_omitted"]
    value: None  # Required key; a mask can never carry a scalar/container payload.


class KnownPublicFact(_KnownFact):
    pass


class MaskedPublicFact(_MaskedFact):
    pass


PublicFact = Annotated[KnownPublicFact | MaskedPublicFact, Field(discriminator="state")]


def _private_locator(fact) -> int:
    pointer = fact.pointer
    _require(re.search(r"~(?:[^01]|$)", pointer) is None, "report_pointer_escape")
    parts = [v.replace("~1", "/").replace("~0", "~") for v in pointer.split("/")[1:]]
    _require(pointer.startswith("/") and len(parts) >= 3 and parts[0] == "resource_changes"
        and re.fullmatch(r"0|[1-9][0-9]*", parts[1]) is not None, "report_pointer_anchor")
    index = int(parts[1])
    _require(index < MAX_REPORT_RESOURCES, "report_resource_index_bound")
    if fact.side == "metadata":
        _require(parts[2:] in (["provider_name"], ["mode"], ["type"], ["change", "replace_paths"]),
                 "report_metadata_pointer")
    else:
        _require(parts[2:4] == ["change", fact.side], "report_pointer_side")
        if fact.side == "actions":
            _require(len(parts) == 4, "report_action_pointer")
    expected = "actions" if fact.side == "actions" else \
        next((v for v in reversed(parts) if v in _POINTER_FIELDS), "source_fact")
    _require(fact.field == expected, "report_pointer_field")
    return index


class KnownPrivateFact(_KnownFact):
    pointer: str = Field(min_length=1, max_length=4096)
    resolution: Literal["resolved"]

    @model_validator(mode="after")
    def locator(self):
        _private_locator(self)
        return self


class MaskedPrivateFact(_MaskedFact):
    pointer: str = Field(min_length=1, max_length=4096)
    resolution: Literal["resolved", "unknown", "sensitive"]

    @model_validator(mode="after")
    def locator_and_mask(self):
        _private_locator(self)
        # Resolver status and safe-value state are one mapping: sensitive and
        # unknown markers are their own statuses; every other state was resolved.
        expected = self.state if self.state in ("unknown", "sensitive") else "resolved"
        _require(self.resolution == expected, "report_mask_resolution")
        return self


PrivateFact = Annotated[KnownPrivateFact | MaskedPrivateFact, Field(discriminator="state")]


class _Evaluation(ReportWire):
    finding_id: ReportId
    resource_id: ReportId
    resource_type: ResourceType
    rule_id: RuleId
    rule_version: Literal["1.0.0"]
    severity: int = Field(ge=1, le=4)
    applicability: Applicability
    outcome: Outcome | None
    explanation: ExplanationText
    limitation_ids: list[LimitationId] = Field(max_length=len(_ROW_LIMITS))

    @model_validator(mode="after")
    def declared_labels(self):
        _require(self.severity == _SEVERITY[self.rule_id], "report_rule_severity")
        _require(self.explanation == _OUTCOME_TEXT[self.outcome] + " " + _RULE_TEXT[self.rule_id],
                 "report_explanation_label_mismatch")
        limits = set(self.limitation_ids)
        _require(len(limits) == len(self.limitation_ids) and self.limitation_ids == sorted(limits)
            and limits <= _ROW_LIMITS, "report_row_limitations")
        _require(self.outcome is not None or self.applicability != "supported", "report_supported_outcome_missing")
        _require((self.outcome == "indeterminate") == ("indeterminate" in limits), "report_indeterminate_limitation")
        # A withheld decision publishes no partial support for the finding.
        _require("decision_evidence_withheld" not in limits
            or self.outcome == "indeterminate" and not self.facts, "report_withheld_facts")
        _require(self.applicability != "supported" or self.outcome not in ("introduced_risk", "unchanged_risk", "clear")
            or any(f.role == "decision" for f in self.facts), "report_decision_fact_missing")
        # Unknown/sensitive markers only ever support an indeterminate outcome.
        _require(self.outcome == "indeterminate"
            or all(f.state not in ("unknown", "sensitive") for f in self.facts), "report_marker_outcome")
        _require("privacy_value_omitted" in limits
            or all(f.state != "privacy_omitted" for f in self.facts), "report_privacy_limitation")
        return self


class PublicEvaluation(_Evaluation):
    facts: list[PublicFact] = Field(max_length=MAX_FACTS)


class PrivateEvaluation(_Evaluation):
    # Sibling of PublicEvaluation: private model instances cannot bypass the
    # outward type through BaseModel subclass acceptance.
    address: str = Field(min_length=1, max_length=MAX_STRING_BYTES)
    actions: list[Action | Literal["unsupported"]] = Field(min_length=1, max_length=MAX_ACTIONS)
    reason_code: str = Field(pattern=r"^[a-z][a-z0-9_]{0,79}$")
    facts: list[PrivateFact] = Field(max_length=MAX_FACTS)

    @model_validator(mode="after")
    def local_fields(self):
        _require(len(self.address.encode("utf-8")) <= MAX_STRING_BYTES, "report_address_byte_bound")
        _require("unsupported" not in self.actions or self.actions == ["unsupported"], "report_unsupported_actions")
        _require(len({_private_locator(f) for f in self.facts}) <= 1, "report_row_resource_index_mismatch")
        return self


class Limitation(ReportWire):
    id: LimitationId
    text: LimitationText

    @model_validator(mode="after")
    def paired_text(self):
        _require(self.text == _LIMITATION_TEXT[self.id], "report_limitation_text_mismatch")
        return self


class Scope(ReportWire):
    rules: list[RuleId] = Field(min_length=4, max_length=4)
    provider: Literal["aws"]
    admin_ports: list[Literal[22, 3389]] = Field(min_length=2, max_length=2)
    claim: Literal["Supported declared predicates only; no global security or deployed-state conclusion."]

    @model_validator(mode="after")
    def fixed_scope(self):
        _require(self.rules == ["R1", "R2", "R3", "R4"] and self.admin_ports == [22, 3389], "report_scope_inventory")
        return self


class Measurements(ReportWire):
    D: Literal["NOT MEASURED"]
    L: Literal["NOT MEASURED"]
    P: Literal["NOT MEASURED"]
    M: Literal["NOT MEASURED"]
    C: Literal["NOT MEASURED"]
    C_custom: Literal["NOT MEASURED"] = Field(alias="C-custom")
    T: Literal["NOT MEASURED"]


class Summary(ReportWire):
    status: Literal["inconclusive", "no_changes", "evaluated_scope"]
    exit_code: int = Field(ge=0, le=2)
    risk_present: bool
    threshold_risk_present: bool
    fail_on: int = Field(ge=1, le=4)
    introduced_risks: int = Field(ge=0, le=MAX_REPORT_ROWS)
    unchanged_risks: int = Field(ge=0, le=MAX_REPORT_ROWS)
    clear: int = Field(ge=0, le=MAX_REPORT_ROWS)
    indeterminate: int = Field(ge=0, le=MAX_REPORT_ROWS)
    unsupported_shape: int = Field(ge=0, le=MAX_REPORT_ROWS)
    not_applicable: int = Field(ge=0, le=MAX_REPORT_ROWS)
    resource_count: int = Field(ge=0, le=MAX_REPORT_RESOURCES)


class _Projection(ReportWire):
    schema_version: Literal["1.0.0"]
    run_id: ReportId
    case_id: ReportId
    parser_version: Literal["1.0.0"]
    policy_version: Literal["1.0.0"]
    summary: Summary
    limitations: list[Limitation] = Field(max_length=len(_LIMITATION_TEXT))
    scope: Scope
    measurements: Measurements


def _projection_consistency(report):
    rows, summary = report.evaluations, report.summary
    ids = [r.finding_id for r in rows]
    keys = [(r.resource_id, r.rule_id) for r in rows]
    fact_ids = [f.fact_id for r in rows for f in r.facts]
    _require(len(set(ids)) == len(ids) and len(set(keys)) == len(keys)
        and len(set(fact_ids)) == len(fact_ids), "report_duplicate_identity")
    # Each opaque identity names exactly one thing in exactly one role.
    resource_ids = {r.resource_id for r in rows}
    roles = [set(ids), resource_ids, set(fact_ids), {report.run_id}, {report.case_id}]
    _require(sum(map(len, roles)) == len(set().union(*roles)), "report_identity_role_reuse")
    types: dict[str, str] = {}
    for row in rows:
        _require(types.setdefault(row.resource_id, row.resource_type) == row.resource_type, "report_resource_type_split")
    limits = [v.id for v in report.limitations]
    _require(limits == sorted(set(limits)), "report_global_limitations")
    for limit in _ROW_LIMITS:
        _require((limit in limits) == any(limit in r.limitation_ids for r in rows), "report_global_limitations")
    _require(("unsupported_shape" in limits) == any(r.applicability == "unsupported_shape" for r in rows),
             "report_unsupported_shape_limitation")
    counts = Counter(r.outcome or r.applicability for r in rows)
    for key, outcome in (("introduced_risks", "introduced_risk"), ("unchanged_risks", "unchanged_risk"),
        ("clear", "clear"), ("indeterminate", "indeterminate"), ("unsupported_shape", "unsupported_shape"),
        ("not_applicable", "not_applicable")):
        _require(getattr(summary, key) == counts[outcome], "report_summary_counts")
    _require(len(rows) <= summary.resource_count * 4 and len(resource_ids) <= summary.resource_count,
             "report_resource_count")
    _require((len(rows) != summary.resource_count * 4) == ("missing_evaluation" in limits), "report_missing_evaluation")
    risk = any(r.outcome in ("introduced_risk", "unchanged_risk") for r in rows)
    threshold = any(r.outcome in ("introduced_risk", "unchanged_risk") and r.severity >= summary.fail_on for r in rows)
    inconclusive = bool(set(limits) - _NONBLOCKING)
    expected_exit = 2 if inconclusive else 1 if threshold else 0
    _require(summary.risk_present == risk and summary.threshold_risk_present == threshold
        and summary.exit_code == expected_exit, "report_summary_exit_or_risk")
    _require((summary.status == "inconclusive") == inconclusive
        and (summary.status != "no_changes" or not risk and not inconclusive), "report_summary_status")
    return report


class ShareableProjection(_Projection):
    projection: Literal["shareable"]
    sensitive: Literal[False]
    privacy_notice: Literal["Opaque identities and safe facts only. Not source-resolvable without the separate private mapping."]
    evaluations: list[PublicEvaluation] = Field(max_length=MAX_REPORT_ROWS)

    @model_validator(mode="after")
    def consistency(self):
        return _projection_consistency(self)


class PrivatePlan(ReportWire):
    sha256: Digest
    format_version: str = Field(pattern=r"^1\.[0-9]+$", max_length=MAX_STRING_BYTES)
    terraform_version: Annotated[str, Field(pattern=r"^[0-9]+(?:\.[0-9]+){1,3}$",
                                            max_length=MAX_STRING_BYTES)] | None
    complete: bool | None
    applyable: bool | None
    errored: bool | None


class EvidenceFailure(ReportWire):
    evaluation_id: ReportId
    fact_id: ReportId
    role: Literal["decision"]
    status: Literal["unknown", "sensitive", "missing", "mismatch"]


class PrivateProvenanceBinding(ReportWire):
    descriptor: ReportProvenance
    descriptor_sha256: Digest

    @model_validator(mode="after")
    def exact_descriptor_digest(self):
        _require(sha256(descriptor_bytes(self.descriptor)).hexdigest() == self.descriptor_sha256,
                 "report_descriptor_digest")
        return self


class _PrivateBody(_Projection):
    projection: Literal["private"]
    sensitive: Literal[True]
    privacy_notice: Literal["Contains exact addresses and pointers. Treat as sensitive. Marked values are masked."]
    plan: PrivatePlan
    evaluations: list[PrivateEvaluation] = Field(max_length=MAX_REPORT_ROWS)
    evidence_failures: list[EvidenceFailure] = Field(max_length=MAX_REPORT_ROWS * MAX_FACTS)

    @model_validator(mode="after")
    def private_consistency(self):
        _projection_consistency(self)
        limits = {v.id for v in self.limitations}
        rows = self.evaluations
        _require(("incomplete_plan" in limits) == (self.plan.complete is not True)
            and ("errored_or_unknown" in limits) == (self.plan.errored is not False), "report_plan_limitations")
        _require("unsupported_input" in limits or all(r.actions != ["unsupported"] for r in rows),
                 "report_unsupported_input")
        _require(not self.evidence_failures or "decision_evidence_withheld" in limits, "report_evidence_failures")
        if not limits - _NONBLOCKING:
            no_changes = not self.summary.risk_present and all(r.actions == ["no-op"] for r in rows)
            _require((self.summary.status == "no_changes") == no_changes, "report_summary_status")
        indices: dict[str, int] = {}
        local: dict[str, tuple[str, list[str]]] = {}
        for row in rows:
            _require(local.setdefault(row.resource_id, (row.address, row.actions)) == (row.address, row.actions),
                     "report_resource_identity_split")
            for fact in row.facts:
                index = _private_locator(fact)
                _require(indices.setdefault(row.resource_id, index) == index, "report_resource_locator_mismatch")
        _require(len(set(indices.values())) == len(indices), "report_resource_locator_alias")
        return self


class PrivateProjection(_PrivateBody):
    """Current bound private report: schema 1.0.0 with typed provenance."""
    provenance: PrivateProvenanceBinding

    @model_validator(mode="after")
    def descriptor_binding(self):
        run = self.provenance.descriptor.run_manifest
        _require(len(run.cases) == 1 and run.run_id == self.run_id and run.cases[0].case_id == self.case_id
            and run.cases[0].raw_source_sha256 == self.plan.sha256
            and self.provenance.descriptor.config.fail_on == self.summary.fail_on, "report_private_descriptor_binding")
        return self


class LegacyPrivateReport(_PrivateBody):
    """Legacy unbound private report (schema 1.0.0, no provenance, manifest 1.0.0).

    A separate type: it is never promoted to, accepted as, or converted into a
    current PrivateProjection, and a current report is never accepted here.
    """


Projection = PrivateProjection | ShareableProjection
_MODELS = {"private": PrivateProjection, "shareable": ShareableProjection, "legacy_private": LegacyPrivateReport}


def _object(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, "report_duplicate_json_key")
        result[key] = value
    return result


def _nonfinite(_: str):
    raise ValueError("report_nonfinite_json")


def _plain(node: object, depth: int = 0) -> object:
    """Copy any Mapping/sequence input into plain dict/list for json.dumps."""
    _require(depth <= MAX_DEPTH, "report_wire_depth_limit")
    if isinstance(node, Mapping):
        # json.dumps would silently coerce non-string keys; refuse instead.
        _require(all(type(k) is str for k in node), "report_wire_key_type")
        return {k: _plain(v, depth + 1) for k, v in node.items()}
    if isinstance(node, (list, tuple)):
        return [_plain(v, depth + 1) for v in node]
    return node


def _depth(node: object) -> None:
    stack = [(node, 0)]
    while stack:
        item, depth = stack.pop()
        _require(depth <= MAX_DEPTH, "report_wire_depth_limit")
        if type(item) is dict:
            stack.extend((v, depth + 1) for v in item.values())
        elif type(item) is list:
            stack.extend((v, depth + 1) for v in item)


def _payload(value: bytes | str | Mapping[str, object]) -> bytes:
    if type(value) is bytes:
        raw = value
    elif type(value) is str:
        raw = value.encode("utf-8")
    elif isinstance(value, Mapping):
        raw = json.dumps(_plain(value), ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("utf-8")
    else:
        raise ValueError("report_wire_input_type")
    _require(len(raw) <= MAX_REPORT_BYTES, "report_wire_byte_limit")
    # Strict UTF-8 only: json.loads(bytes) would otherwise sniff UTF-16/32.
    parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=_object, parse_constant=_nonfinite)
    _require(type(parsed) is dict, "report_wire_object_required")
    _depth(parsed)
    return raw


_ERRORS = (ValueError, TypeError, UnicodeError, RecursionError, AttributeError, KeyError, IndexError)


def _validate(value: object, kind: str):
    try:
        _require(kind in _MODELS, "report_projection_kind")
        return _MODELS[kind].model_validate_json(_payload(value))
    except _ERRORS:
        raise ValueError("report_projection_invalid") from None


def validate_projection(value: bytes | str | Mapping[str, object], *,
                        projection: Literal["private", "shareable"]) -> Projection:
    """JSON-mode validation of a current projection; no I/O."""
    if projection not in ("private", "shareable"):
        raise ValueError("report_projection_invalid")
    return _validate(value, projection)


def projection_dict(value: Projection | LegacyPrivateReport) -> dict[str, object]:
    """Revalidated current-shape dictionary of a canonical model (aliases applied)."""
    kind = {PrivateProjection: "private", ShareableProjection: "shareable",
            LegacyPrivateReport: "legacy_private"}.get(type(value))
    if kind is None:
        raise ValueError("report_projection_invalid")
    try:
        # A model_construct()ed instance can fail serialization; normalize that too.
        dumped = value.model_dump_json(by_alias=True)
    except Exception:
        raise ValueError("report_projection_invalid") from None
    validated = _validate(dumped, kind)
    return json.loads(validated.model_dump_json(by_alias=True))


def validate_private_projection(payload: bytes | str | Mapping[str, object]) -> dict[str, object]:
    return projection_dict(validate_projection(payload, projection="private"))


def validate_shareable_projection(payload: bytes | str | Mapping[str, object]) -> dict[str, object]:
    return projection_dict(validate_projection(payload, projection="shareable"))


def validate_legacy_private_report(payload: bytes | str | Mapping[str, object]) -> dict[str, object]:
    """Legacy seven-file archives only; the result stays explicitly unbound."""
    return projection_dict(_validate(payload, "legacy_private"))


def validate_report_pair(private: bytes | str | Mapping[str, object], shareable: bytes | str | Mapping[str, object],
                         *, exit_code: int) -> tuple[PrivateProjection, ShareableProjection]:
    a = validate_projection(private, projection="private")
    b = validate_projection(shareable, projection="shareable")
    try:
        left, right = projection_dict(a), projection_dict(b)
        common = ("schema_version", "run_id", "case_id", "parser_version", "policy_version", "summary",
                  "limitations", "scope", "measurements")
        _require(all(left[k] == right[k] for k in common), "report_projection_common_mismatch")
        _require(type(exit_code) is int and exit_code == a.summary.exit_code == b.summary.exit_code,
                 "report_pair_exit_mismatch")
        outward = []
        for row in left["evaluations"]:
            public = {k: v for k, v in row.items() if k not in {"address", "actions", "reason_code", "facts"}}
            public["facts"] = [{k: v for k, v in f.items() if k not in {"pointer", "resolution"}} for f in row["facts"]]
            outward.append(public)
        _require(outward == right["evaluations"], "report_projection_row_or_fact_mismatch")
    except _ERRORS:
        raise ValueError("report_projection_invalid") from None
    return a, b
