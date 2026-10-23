"""Versioned strict wires. Raw input is deliberately excluded from report models."""
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field

PARSER_VERSION = "1.0.0"
POLICY_VERSION = "1.0.0"
AWS_PROVIDER = "registry.terraform.io/hashicorp/aws"

class Wire(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")

class ValueState(Wire):
    state: Literal["known", "null", "absent", "unknown"]
    value: Any = None
    sensitive: bool = False

class PlanIdentity(Wire):
    sha256: str
    format_version: str
    terraform_version: str | None = None
    parser_version: str = PARSER_VERSION
    complete: bool | None = None
    applyable: bool | None = None
    errored: bool | None = None
    limits: dict[str, int] = Field(default_factory=dict)

class ResourceChange(Wire):
    key: str
    index: int
    address: str
    deposed: str | None = None
    provider_name: str
    mode: str
    type: str
    name: str
    actions: tuple[str, ...]
    action_supported: bool = True
    before: Any = None
    after: Any = None
    before_sensitive: Any = False
    after_sensitive: Any = False
    after_unknown: Any = False

class PlanDocument(Wire):
    identity: PlanIdentity
    source_path: str
    raw: dict[str, Any] = Field(repr=False, exclude=True)
    resources: tuple[ResourceChange, ...]
    coverage: tuple[str, ...] = ()

class EvidenceRef(Wire):
    fact_id: str
    plan_sha256: str
    resource_key: str
    resource_index: int
    side: Literal["before", "after", "actions", "metadata"]
    pointer: str
    expected: ValueState
    role: Literal["decision", "supporting"] = "decision"

class ResolvedEvidence(Wire):
    ref: EvidenceRef
    status: Literal["resolved", "unknown", "sensitive", "missing", "mismatch"]
    value: ValueState
    reason: str = ""

class RuleEvaluation(Wire):
    evaluation_id: str
    resource_key: str
    rule_id: Literal["R1", "R2", "R3", "R4"]
    version: str = POLICY_VERSION
    severity: int
    applicability: Literal["supported", "not_applicable", "unsupported_shape"]
    outcome: Literal["introduced_risk", "unchanged_risk", "clear", "indeterminate"] | None
    reason_code: str
    decision_refs: tuple[EvidenceRef, ...] = ()
    supporting_refs: tuple[EvidenceRef, ...] = ()
    coverage: tuple[str, ...] = ()

class ReviewReport(Wire):
    private: dict[str, Any]
    shareable: dict[str, Any]
    exit_code: int
