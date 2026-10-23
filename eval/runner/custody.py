"""Metadata-only custody checks. No oracle loading, labels, inference or file effects.

These records attest external work; successful validation cannot authenticate authorship.
The custodian must pin the authority digest independently of submitted metadata.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Annotated, Literal

from pydantic import Field

from eval.runner.scoring import ARMS, Edition, Record

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Identity = Annotated[str, Field(min_length=1, max_length=160)]
MAX_ROWS = 4096

# Fixed v1 public cell identifiers; no case content or expected labels are present.
SEMANTIC_CELLS = (
    "create", "update", "delete", "no_op", "replace_delete_create",
    "replace_create_delete", "unknown_ancestor", "unknown_leaf", "sensitive_ancestor",
    "sensitive_leaf", "absent", "explicit_null", "multiple_cidrs", "ipv6",
    "all_protocol", "numeric_tcp", "non_ingress_short_circuit", "invalid_ranges",
    "unchanged_risk", "unknown_prior_risky_after", "partial_plan", "errored_plan",
    "deposed_identity", "address_collision", "moved_metadata", "pointer_escaping",
    "array_index_stability", "malformed_input", "duplicate_json_key", "oversized_input",
    "deeply_nested_input", "provider_mismatch", "type_mismatch", "data_mode",
    "r1_exposure_set_difference", "r1_cidr_reorder_duplicate", "r1_unsupported_sources",
    "r1_out_of_scope_ports", "r2_transition_table", "r3_transition_table",
    "r4_prior_contradiction", "r4_optional_replace_paths", "decision_ref_failure",
    "optional_ref_omission", "sensitive_value_masking", "private_address_exception",
    "shareable_canary_exclusion", "zero_rule_mutation", "zero_prohibited_effects",
)


def _unique(values: tuple[str, ...], label: str) -> None:
    if len(values) != len(set(values)) or any(not value.strip() for value in values):
        raise ValueError(f"duplicate or blank {label}")


def _time(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone-aware timestamp required")


def metadata_digest(record: Record) -> str:
    """Canonical metadata bytes only; never call on hidden input/label records."""
    raw = json.dumps(record.model_dump(mode="json"), sort_keys=True,
                     separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    return hashlib.sha256(raw.encode("ascii")).hexdigest()


class Actor(Record):
    # Qualified registry identity, not a bare registry-local callsign ID.
    actor_id: Identity
    session_id: Identity
    parent_id: Identity | None = None
    forked_from: Identity | None = None


class InventoryRow(Record):
    """Opaque inventory only: no source paths, raw input, labels or fact values."""
    case_id: Identity
    family_id: Identity
    configuration_lineage: Identity
    mutation_lineage: Identity
    split: Literal["dev", "validation", "heldout"]
    rule_id: Literal["R1", "R2", "R3", "R4"]
    action: Literal["no-op", "create", "read", "update", "delete",
                    "delete/create", "create/delete"]
    knowledge: Literal["known", "unknown", "sensitive", "unsupported"]
    semantic_cells: tuple[Identity, ...] = Field(min_length=1, max_length=128)
    explanation_eligible: bool = False
    public_example: bool = False
    input_sha256: Digest


class CustodyAuthority(Record):
    """INT-approved, externally pinned freeze made before hidden exposure."""
    edition_id: Identity
    policy_sha256: Digest
    frozen_build_sha256: Digest
    prompt_sha256: Digest
    rubric_sha256: Digest
    oracle_sha256: Digest
    inventory_sha256: Digest
    actors: tuple[Actor, ...] = Field(min_length=2, max_length=256)
    implementation_actors: tuple[Identity, ...] = Field(min_length=1, max_length=256)
    oracle_author: Identity
    oracle_checker: Identity
    custodian: Identity
    frozen_at: datetime
    required_cells: tuple[Identity, ...] = SEMANTIC_CELLS
    required_actions: tuple[str, ...] = (
        "create", "update", "delete", "no-op", "delete/create", "create/delete")
    required_knowledge: tuple[str, ...] = ("known", "unknown", "sensitive")
    minimum_explanations: Literal[24] = 24


class Seal(Record):
    edition: Edition
    authority_sha256: Digest
    inventory: tuple[InventoryRow, ...] = Field(min_length=1, max_length=MAX_ROWS)
    sealed_at: datetime
    custodian: Identity
    inference_exclusion_attested: bool
    no_detector_or_scanner_gold_attested: bool
    independent_source_review_attested: bool


def _actors(authority: CustodyAuthority) -> dict[str, Actor]:
    actors = {row.actor_id: row for row in authority.actors}
    if len(actors) != len(authority.actors):
        raise ValueError("duplicate qualified actor")
    if any(not row.actor_id.strip() or not row.session_id.strip() for row in actors.values()):
        raise ValueError("blank actor/session identity")
    for actor in actors.values():
        for edge in (actor.parent_id, actor.forked_from):
            if edge is not None and edge not in actors:
                raise ValueError("missing parent/fork actor")
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(name: str) -> None:
        if name in visiting:
            raise ValueError("cyclic actor lineage")
        if name in visited:
            return
        visiting.add(name)
        actor = actors[name]
        for edge in (actor.parent_id, actor.forked_from):
            if edge is not None:
                visit(edge)
        visiting.remove(name)
        visited.add(name)

    for name in actors:
        visit(name)
    return actors


def validate_independence(authority: CustodyAuthority) -> None:
    actors = _actors(authority)
    _unique(authority.implementation_actors, "implementation actors")
    participants = (*authority.implementation_actors, authority.oracle_author,
                    authority.oracle_checker, authority.custodian)
    if any(name not in actors for name in participants):
        raise ValueError("unregistered custody participant")
    # Fork personas and parent/child links are one connected lineage, transitively.
    adjacency: dict[str, set[str]] = {name: set() for name in actors}
    for row in actors.values():
        for edge in (row.parent_id, row.forked_from):
            if edge is not None:
                adjacency[row.actor_id].add(edge)
                adjacency[edge].add(row.actor_id)
        for other in actors.values():
            if other.session_id == row.session_id:
                adjacency[row.actor_id].add(other.actor_id)

    def related(a: str, b: str) -> bool:
        seen = {a}
        pending = [a]
        while pending:
            name = pending.pop()
            for neighbor in adjacency[name] - seen:
                seen.add(neighbor)
                pending.append(neighbor)
        return b in seen or bool(
            {actors[name].session_id for name in seen} & {actors[b].session_id})

    independent = (authority.oracle_author, authority.oracle_checker)
    if related(*independent):
        raise ValueError("oracle author/checker share session or implementation lineage")
    for actor in independent:
        if any(related(actor, impl) for impl in authority.implementation_actors):
            raise ValueError("oracle lineage overlaps implementation")
    if any(related(authority.custodian, impl) for impl in authority.implementation_actors):
        raise ValueError("custodian lineage overlaps implementation")


def validate_seal(authority: CustodyAuthority, seal: Seal,
                  expected_authority_sha256: str) -> dict:
    """Structural eligibility only; caller supplies trusted authority pin separately."""
    if (metadata_digest(authority) != expected_authority_sha256
            or seal.authority_sha256 != expected_authority_sha256):
        raise ValueError("unapproved authority edition")
    validate_independence(authority)
    _time(authority.frozen_at)
    _time(seal.sealed_at)
    if seal.sealed_at < authority.frozen_at:
        raise ValueError("seal precedes build/prompt/rubric freeze")
    edition = seal.edition
    pairs = (
        (edition.edition_id, authority.edition_id),
        (edition.policy_sha256, authority.policy_sha256),
        (edition.frozen_build_sha256, authority.frozen_build_sha256),
        (edition.oracle_sha256, authority.oracle_sha256),
        (edition.lineage_inventory_sha256, authority.inventory_sha256),
        (edition.oracle_author, authority.oracle_author),
        (edition.oracle_checker, authority.oracle_checker),
        (seal.custodian, authority.custodian),
    )
    if any(a != b for a, b in pairs):
        raise ValueError("seal/authority pin or identity mismatch")
    if set(edition.detector_authors) != set(authority.implementation_actors):
        raise ValueError("edition omits implementation lineage")
    _unique(edition.detector_authors, "edition implementation actors")
    if not all((edition.independent_custody_attested, edition.inference_exclusion_attested,
                seal.inference_exclusion_attested, seal.no_detector_or_scanner_gold_attested,
                seal.independent_source_review_attested)):
        raise ValueError("missing independent custody attestation")
    # Hash list serialization without reading a single case or expected outcome.
    raw = json.dumps([row.model_dump(mode="json") for row in seal.inventory],
                     sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    if hashlib.sha256(raw.encode("ascii")).hexdigest() != authority.inventory_sha256:
        raise ValueError("inventory hash mismatch")
    _unique(authority.required_cells, "required cells")
    if set(authority.required_cells) != set(SEMANTIC_CELLS):
        raise ValueError("v1 mandatory semantic scope changed")
    if (set(authority.required_actions) != {
            "create", "update", "delete", "no-op", "delete/create", "create/delete"}
            or set(authority.required_knowledge) != {"known", "unknown", "sensitive"}):
        raise ValueError("v1 balance dimensions changed")
    _unique(tuple(row.case_id for row in seal.inventory), "case ids")
    partitions: dict[tuple[str, str], str] = {}
    cells: dict[str, set[str]] = {split: set() for split in ("dev", "validation", "heldout")}
    eligible = []
    for row in seal.inventory:
        _unique(row.semantic_cells, "semantic cells")
        if not set(row.semantic_cells) <= set(SEMANTIC_CELLS):
            raise ValueError("unknown semantic cell")
        if row.public_example and row.split != "dev":
            raise ValueError("public/upstream example outside development")
        for kind, value in (("family", row.family_id), ("configuration", row.configuration_lineage),
                            ("mutation", row.mutation_lineage), ("input", row.input_sha256)):
            if not value.strip():
                raise ValueError("blank lineage")
            identity = kind, value
            if identity in partitions and partitions[identity] != row.split:
                raise ValueError("shared ancestry or identical input crosses splits")
            partitions[identity] = row.split
        cells[row.split].update(row.semantic_cells)
        if row.split == "heldout" and row.explanation_eligible:
            eligible.append(row)
    missing = {split: sorted(set(SEMANTIC_CELLS) - cells[split]) for split in ("dev", "heldout")}
    if any(missing.values()):
        raise ValueError(f"missing required semantic inventory: {missing}")
    if len({row.input_sha256 for row in eligible}) != len(eligible):
        raise ValueError("duplicate eligible explanation inputs")
    if (len(eligible) < 24 or edition.eligible_heldout_explanations != len(eligible)
            or {row.rule_id for row in eligible} != {"R1", "R2", "R3", "R4"}
            or any(sum(row.rule_id == rule for row in eligible) < 6
                   for rule in ("R1", "R2", "R3", "R4"))
            or not set(authority.required_actions) <= {row.action for row in eligible}
            or not set(authority.required_knowledge) <= {row.knowledge for row in eligible}):
        raise ValueError("24-case heldout explanation inventory/balance incomplete")
    if edition.state == "development":
        raise ValueError("development edition is not sealed holdout evidence")
    return {"structurally_eligible": True, "authorship_authenticated": False,
            "product_acceptance": False, "eligible_explanations": len(eligible),
            "fresh_holdout": edition.state == "sealed"}


class SemanticReceipt(Record):
    authority_sha256: Digest
    build_sha256: Digest
    suite_sha256: Digest
    actor_id: Identity
    origin: Literal["executed", "mock", "not_run"]
    cells: tuple[Identity, ...] = Field(max_length=128)
    discovered: int = Field(ge=0, le=100000)
    passed: int = Field(ge=0, le=100000)
    failed: int = Field(ge=0, le=100000)
    skipped: int = Field(ge=0, le=100000)
    exact_mismatches: int = Field(ge=0)
    certainty_errors: int = Field(ge=0)
    invalid_displayed_facts: int = Field(ge=0)
    rule_mutations: int = Field(ge=0)
    prohibited_effects: int = Field(ge=0)
    canary_leaks: int = Field(ge=0)


def validate_semantics(authority: CustodyAuthority, receipt: SemanticReceipt,
                       expected_authority_sha256: str, expected_suite_sha256: str) -> None:
    if (metadata_digest(authority) != expected_authority_sha256
            or receipt.authority_sha256 != expected_authority_sha256
            or receipt.build_sha256 != authority.frozen_build_sha256
            or receipt.suite_sha256 != expected_suite_sha256):
        raise ValueError("semantic receipt pin mismatch")
    validate_independence(authority)
    if receipt.actor_id != authority.oracle_checker:
        raise ValueError("semantic receipt requires appointed independent checker")
    _unique(receipt.cells, "receipt cells")
    if (receipt.origin != "executed" or set(receipt.cells) != set(SEMANTIC_CELLS)
            or receipt.discovered < len(SEMANTIC_CELLS)
            or receipt.passed != receipt.discovered or receipt.failed or receipt.skipped
            or any((receipt.exact_mismatches, receipt.certainty_errors,
                    receipt.invalid_displayed_facts, receipt.rule_mutations,
                    receipt.prohibited_effects, receipt.canary_leaks))):
        raise ValueError("mandatory exact semantic execution incomplete or failed")


class ExposureReceipt(Record):
    edition_id: Identity
    authority_sha256: Digest
    seal_sha256: Digest
    build_sha256: Digest
    oracle_sha256: Digest
    measurements_sha256: Digest
    arm: Literal["D", "L", "P", "M", "C", "C-custom", "T"]
    state: Literal["consumed_holdout"] = "consumed_holdout"
    custodian: Identity
    exposed_at: datetime
    # Durable pre-access receipt identity supplied by the external custody controller.
    durable_receipt_id: Identity
    durable_before_access_attested: bool


def validate_exposure(authority: CustodyAuthority, seal: Seal,
                      receipts: tuple[ExposureReceipt, ...],
                      expected_authority_sha256: str, *,
                      requested_fresh: bool = False) -> dict:
    validate_seal(authority, seal, expected_authority_sha256)
    if not receipts:
        raise ValueError("heldout access requires a durable exposure receipt")
    if len(receipts) > len(ARMS):
        raise ValueError("too many exposure receipts")
    _unique(tuple(row.arm for row in receipts), "exposed arms")
    _unique(tuple(row.durable_receipt_id for row in receipts), "durable receipt ids")
    for row in receipts:
        _time(row.exposed_at)
        if (row.edition_id != authority.edition_id
                or row.authority_sha256 != expected_authority_sha256
                or row.seal_sha256 != metadata_digest(seal)
                or row.build_sha256 != authority.frozen_build_sha256
                or row.oracle_sha256 != authority.oracle_sha256
                or row.custodian != authority.custodian
                or row.exposed_at < seal.sealed_at
                or not row.durable_before_access_attested):
            raise ValueError("invalid or stale exposure receipt")
    if requested_fresh:
        raise ValueError("any exposure consumes the edition for all later tuning")
    return {"state": "consumed_holdout", "fresh_holdout": False,
            "authorship_authenticated": False, "product_acceptance": False,
            "exposed_arms": [row.arm for row in receipts]}
