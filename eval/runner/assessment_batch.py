"""Per-plan assessment intake with one externally frozen raw-scenario denominator.

This is structural private intake only. It cannot authenticate actors, labels, or
live measurements. Coordinator and producer receipts remain separate evidence.
"""
from __future__ import annotations

from pathlib import Path, PurePosixPath
import hashlib
from typing import Literal

from pydantic import Field

from eval.model.provenance import ExportBundle
from eval.model.experiment import canonical
from eval.model.capture_index import export_digest
from eval.model.experiment import digest as producer_digest
from eval.runner.assessment_import import (
    AssessmentImportRequest, _validate_authority, import_assessments,
)
from eval.runner.custody import Digest, Identity, Record, metadata_digest
from eval.runner.model_bridge import JournalLink, _json, bridge_bundle, links_for_bundle
from eval.runner.scoring import ArmRow
from eval.runner.utility import PObservation, p_utility


class BatchScenario(Record):
    """External frozen selection: raw plan and case-record identity are distinct."""
    scenario_id: Identity
    raw_plan_sha256: Digest
    case_record_sha256: Digest
    producer_provenance_sha256: Digest | None = None


class PlanInvocation(Record):
    """One coordinator invocation and its exact per-plan D5 export pin."""
    invocation_case_id: Identity
    scenario_id: Identity
    raw_plan_sha256: Digest
    case_record_sha256: Digest
    export_sha256: Digest | None = None
    index_sha256: Digest | None = None


class AssessmentBatchRequest(Record):
    authority_request: AssessmentImportRequest
    scenario_inventory: tuple[BatchScenario, ...] = Field(min_length=1, max_length=4096)
    scenario_inventory_sha256: Digest
    invocations: tuple[PlanInvocation, ...] = Field(min_length=1, max_length=4096)
    coordinator_provenance_sha256: Digest
    coordinator_provenance_json: str = Field(max_length=16 * 1024 * 1024)
    execution_authority_sha256: Digest | None = None
    global_journal_sha256: Digest
    global_journal_json: str = Field(max_length=16 * 1024 * 1024)
    journal_links: tuple[JournalLink, ...] = Field(max_length=10000)


class PrivateFileReference(Record):
    """Manifest-relative private file; never an absolute path or a glob."""
    relative_path: str = Field(min_length=1, max_length=512)
    sha256: Digest
    max_bytes: int = Field(ge=1, le=16 * 1024 * 1024)


class BatchD5Export(Record):
    """Typed nested producer object; JSON-mode validation preserves array tuples."""
    rows: tuple[ArmRow, ...] = Field(max_length=160000)
    attempts: tuple[dict, ...] = Field(max_length=10000)
    accounting: dict
    provenance: dict
    observations: tuple[dict, ...] = Field(max_length=10000)


class BatchPlanTransport(Record):
    invocation_case_id: Identity
    bundle: BatchD5Export | None
    capture_directory: str | None = Field(default=None, max_length=512)
    capture_index_sha256: Digest | None = None
    submissions: PrivateFileReference | None = None


class AssessmentBatchTransport(Record):
    schema_version: Literal["m4-assessment-batch-transport-v1"]
    root_id: Identity
    root_sha256: Digest
    request: AssessmentBatchRequest
    plans: tuple[BatchPlanTransport, ...] = Field(min_length=1, max_length=4096)


def resolve_private_reference(root: Path, relative_path: str, *, must_exist: bool = True) -> Path:
    relative = PurePosixPath(relative_path)
    if (relative.is_absolute() or ".." in relative.parts or "\\" in relative_path
            or not relative.parts or any(part in ("", ".") for part in relative.parts)):
        raise ValueError("private reference must be a normalized root-relative path")
    candidate = root.joinpath(*relative.parts)
    cursor = candidate
    while cursor != root and root in cursor.parents:
        if cursor.is_symlink():
            raise ValueError("symlink in private reference path")
        cursor = cursor.parent
    resolved = candidate.resolve(strict=must_exist)
    if resolved != root and root not in resolved.parents:
        raise ValueError("private reference escapes authorized root")
    return resolved


def reconstruct_export_bundle(wire: dict) -> ExportBundle:
    """Recreate D5's immutable bundle from D4's nested canonical-object wire."""
    if isinstance(wire, BatchD5Export):
        wire = wire.model_dump(mode="json")
    expected = {"rows", "attempts", "accounting", "provenance", "observations"}
    if type(wire) is not dict or set(wire) != expected:
        raise ValueError("unexpected nested D5 export fields")
    if (type(wire["rows"]) is not list or type(wire["attempts"]) is not list
            or type(wire["accounting"]) is not dict or type(wire["provenance"]) is not dict
            or type(wire["observations"]) is not list):
        raise ValueError("D4 nested producer object has invalid shape")
    from eval.runner.scoring import ArmRow
    return ExportBundle(
        tuple(ArmRow.model_validate_json(canonical(row)) for row in wire["rows"]),
        canonical(wire["attempts"]), canonical(wire["provenance"]),
        canonical(wire["accounting"]), canonical(wire["observations"]))


def validate_coordinator_wire(raw: str, expected_sha256: str) -> dict:
    provenance = _json(raw)
    if (type(provenance) is not dict or canonical(provenance) != raw
            or hashlib.sha256(raw.encode("utf-8")).hexdigest() != expected_sha256
            or provenance.get("schema_version") != "m4-seven-arm-benchmark-provenance-v1"):
        raise ValueError("coordinator canonical provenance pin/schema mismatch")
    return provenance


def validate_execution_mode(provenance: dict, expected_authority_sha256: str | None) -> str:
    mode = provenance.get("execution_mode")
    if mode is None:
        return "development_fake_only"
    if mode != "approved_synthetic_unverified":
        raise ValueError("unsupported coordinator execution mode")
    if (expected_authority_sha256 is None
            or provenance.get("execution_authority_sha256") != expected_authority_sha256):
        raise ValueError("synthetic execution authority pin mismatch")
    return mode


def validate_export_pins(bundle: ExportBundle, provenance_sha256: str,
                         whole_export_sha256: str) -> None:
    provenance = _json(bundle.provenance_json)
    if producer_digest(canonical(provenance)) != provenance_sha256:
        raise ValueError("D5 canonical provenance pin mismatch")
    if export_digest(bundle) != whole_export_sha256:
        raise ValueError("D5 whole ExportBundle pin mismatch")


def validate_scenario_inventory(scenarios: tuple[BatchScenario, ...]) -> int:
    if len({row.scenario_id for row in scenarios}) != len(scenarios):
        raise ValueError("duplicate frozen scenario identity")
    if len({row.raw_plan_sha256 for row in scenarios}) != len(scenarios):
        raise ValueError("independent denominator requires distinct raw plan hashes")
    if len(scenarios) < 24:
        raise ValueError("fewer than 24 externally selected raw scenarios")
    return len(scenarios)


def validate_span_partition(spans: list[dict], total_attempts: int) -> None:
    cursor = 0
    seen = set()
    for row in spans:
        case_id, start, stop = row.get("case_id"), row.get("start_index"), row.get("stop_index")
        if case_id in seen or type(start) is not int or type(stop) is not int:
            raise ValueError("duplicate case or malformed half-open span")
        if start != cursor or stop < start or stop > total_attempts:
            raise ValueError("attempt spans must be a contiguous half-open partition")
        seen.add(case_id)
        cursor = stop
    if cursor != total_attempts:
        raise ValueError("attempt spans do not cover the global journal")


def reconcile_attempt_ids(per_invocation_ids: tuple[tuple[str, ...], ...],
                          journal_ids: tuple[str, ...]) -> tuple[str, ...]:
    flat = [attempt_id for group in per_invocation_ids for attempt_id in group]
    if len(flat) != len(set(flat)):
        raise ValueError("duplicate attempt identity across plan exports")
    if len(journal_ids) != len(set(journal_ids)):
        raise ValueError("duplicate global journal attempt identity")
    if not set(flat) <= set(journal_ids):
        raise ValueError("per-plan attempt absent from global journal")
    return tuple(sorted(set(journal_ids) - set(flat)))


def cost_scope_record(global_journal: dict, invocation_accounting: list[dict]) -> dict:
    """Retain one cumulative boundary and invocation details without summing."""
    return {"scope": "one global cumulative journal; invocation accounting is detail only",
            "global_journal": global_journal,
            "invocation_accounting": invocation_accounting,
            "invocation_totals_added_to_global": False}


def _validate_batch(request: AssessmentBatchRequest) -> tuple[dict, dict]:
    """Check all public authorities and raw-source joins before private payload reads."""
    authority = request.authority_request.authority
    _validate_authority(authority, request.authority_request.authority_sha256)
    scenarios = request.scenario_inventory
    if metadata_digest(scenarios) != request.scenario_inventory_sha256:
        raise ValueError("externally pinned scenario inventory digest mismatch")
    validate_scenario_inventory(scenarios)
    scenario_map = {row.scenario_id: row for row in scenarios}
    cases_by_scenario: dict[str, list] = {}
    for row in authority.cases:
        case = row.expected_case
        selected = scenario_map.get(case.case_id)
        if selected is None or case.input_sha256 != selected.raw_plan_sha256:
            raise ValueError("authorized finding does not bind to frozen raw scenario")
        cases_by_scenario.setdefault(case.case_id, []).append(row)
    if set(cases_by_scenario) != set(scenario_map):
        raise ValueError("frozen scenario and eligible finding inventory differ")
    invocations = request.invocations
    if len({row.invocation_case_id for row in invocations}) != len(invocations):
        raise ValueError("duplicate coordinator invocation identity")
    if len({row.scenario_id for row in invocations}) != len(invocations):
        raise ValueError("one raw scenario must have one coordinator invocation")
    invocation_map = {row.scenario_id: row for row in invocations}
    if set(invocation_map) != set(scenario_map):
        raise ValueError("coordinator invocations do not cover frozen scenarios")
    for scenario_id, invocation in invocation_map.items():
        frozen = scenario_map[scenario_id]
        if (invocation.raw_plan_sha256 != frozen.raw_plan_sha256
                or invocation.case_record_sha256 != frozen.case_record_sha256):
            raise ValueError("coordinator invocation raw/case-record binding mismatch")

    provenance = validate_coordinator_wire(request.coordinator_provenance_json,
                                           request.coordinator_provenance_sha256)
    if provenance.get("live_eligible") is not False:
        raise ValueError("unsupported or live coordinator provenance")
    execution_mode = validate_execution_mode(provenance, request.execution_authority_sha256)
    spans = provenance.get("attempt_case_spans")
    records = provenance.get("case_records")
    bindings = provenance.get("case_bindings")
    exports = provenance.get("model_exports")
    if (type(spans) is not list or type(records) is not list
            or type(bindings) is not list or type(exports) is not list):
        raise ValueError("coordinator case records, bindings, spans, and nested exports required")
    span_by_id = {row.get("case_id"): row for row in spans if type(row) is dict}
    record_by_id = {row.get("case_id"): row for row in records if type(row) is dict}
    binding_by_id = {row.get("case_id"): row for row in bindings if type(row) is dict}
    export_by_id = {row.get("case_id"): row for row in exports if type(row) is dict}
    if (len(span_by_id) != len(spans) or len(record_by_id) != len(records)
            or len(binding_by_id) != len(bindings) or len(export_by_id) != len(exports)):
        raise ValueError("duplicate or malformed coordinator case record/binding/span/export")
    snapshot = provenance.get("journal_snapshot")
    if type(snapshot) is not dict or snapshot.get("journal_sha256") != request.global_journal_sha256:
        raise ValueError("coordinator journal snapshot identity mismatch")
    if canonical(snapshot) != canonical(_json(request.global_journal_json)):
        raise ValueError("supplied global journal differs from coordinator's one snapshot")
    journal_attempts = snapshot.get("attempts")
    if type(journal_attempts) is not list:
        raise ValueError("coordinator snapshot attempts missing")
    validate_span_partition(spans, len(journal_attempts))
    previous_stop = 0
    for invocation in invocations:
        span = span_by_id.get(invocation.invocation_case_id)
        record = record_by_id.get(invocation.invocation_case_id)
        binding = binding_by_id.get(invocation.invocation_case_id)
        exported = export_by_id.get(invocation.invocation_case_id)
        if span is None or record is None or binding is None:
            raise ValueError("missing coordinator invocation binding/span/raw case record")
        start, stop = span.get("start_index"), span.get("stop_index")
        if (type(start) is not int or type(stop) is not int or start != previous_stop
                or stop < start or stop > len(journal_attempts)):
            raise ValueError("coordinator attempt spans must be contiguous bounded half-open ranges")
        previous_stop = stop
        if (record.get("raw_input_sha256") != invocation.raw_plan_sha256
                or record.get("case_record_sha256") != invocation.case_record_sha256):
            raise ValueError("coordinator raw/case-record identity mismatch")
        if binding.get("raw_source_sha256") != invocation.raw_plan_sha256:
            raise ValueError("typed coordinator case binding raw source mismatch")
        if exported is None:
            if invocation.export_sha256 is not None:
                raise ValueError("external export pin exists without coordinator export binding")
            continue
        if exported.get("raw_input_sha256") != invocation.raw_plan_sha256:
            raise ValueError("export raw source mismatch")
        if (not isinstance(exported.get("attempts"), list)
                or [row.get("attempt_id") for row in journal_attempts[start:stop]]
                   != [row.get("attempt_id") for row in exported["attempts"]]):
            raise ValueError("per-plan export attempts differ from its half-open journal span")
        if (type(exported.get("provenance")) is not dict
                or (invocation.producer_provenance_sha256 is not None
                    and producer_digest(canonical(exported["provenance"]))
                       != invocation.producer_provenance_sha256)):
            raise ValueError("D5 provenance pin mismatch (distinct from whole-bundle export pin)")
    if previous_stop != len(journal_attempts):
        raise ValueError("coordinator spans do not cover every global journal attempt")
    journal = _json(request.global_journal_json)
    if (type(journal) is not dict or journal.get("journal_sha256") != request.global_journal_sha256
            or journal.get("read_only") is not True):
        raise ValueError("global read-only journal pin mismatch")
    attempts = journal.get("attempts")
    if type(attempts) is not list or len(attempts) > 10000:
        raise ValueError("bounded global attempt snapshot required")
    attempt_ids = [row.get("attempt_id") for row in attempts if type(row) is dict]
    if len(attempt_ids) != len(attempts) or len(set(attempt_ids)) != len(attempt_ids):
        raise ValueError("duplicate or malformed global journal attempt identity")
    return provenance, journal


def import_assessment_batch(
    request: AssessmentBatchRequest, *,
    bundles: dict[str, ExportBundle], capture_directories: dict[str, Path | None],
    submissions_by_invocation: dict[str, tuple],
) -> dict:
    """Import each independently pinned plan capture; retain one global cost scope.

    ``bundles`` is keyed by coordinator invocation case ID. This function never
    folds cumulative per-case journal totals; it emits the pinned journal once and
    preserves every invocation accounting/snapshot record in its own list.
    """
    provenance, journal = _validate_batch(request)
    expected_ids = {row.invocation_case_id for row in request.invocations}
    if set(capture_directories) != expected_ids or not set(bundles) <= expected_ids:
        raise ValueError("bundle/capture inputs differ from externally pinned exports")
    invocation_by_id = {row.invocation_case_id: row for row in request.invocations}
    if any(bundles.get(key) is None and invocation_by_id[key].export_sha256 is not None
           for key in expected_ids):
        raise ValueError("pinned export bundle is missing")
    producers = {}
    attempt_owner = {}
    failures = []
    for invocation in request.invocations:
        bundle = bundles.get(invocation.invocation_case_id)
        if bundle is None:
            failures.append({"invocation_case_id": invocation.invocation_case_id,
                             "scenario_id": invocation.scenario_id,
                             "reason": "export_missing_or_withheld; global attempts retained"})
            continue
        producer = bridge_bundle(bundle, request.authority_request.authority.producer_pins,
                                 links_for_bundle(bundle, request.journal_links))
        if (invocation.export_sha256 is not None
                and invocation.producer_provenance_sha256 is not None):
            validate_export_pins(bundle, invocation.producer_provenance_sha256,
                                 invocation.export_sha256)
        source_export = next(row for row in provenance["model_exports"]
                             if row["case_id"] == invocation.invocation_case_id)
        if (source_export.get("raw_input_sha256") != invocation.raw_plan_sha256
                or source_export.get("rows") != [row.model_dump(mode="json") for row in bundle.rows]
                or source_export.get("attempts") != _json(bundle.attempts_json)
                or source_export.get("accounting") != _json(bundle.accounting_json)
                or source_export.get("provenance") != _json(bundle.provenance_json)
                or source_export.get("observations") != _json(bundle.observations_json)):
            raise ValueError("nested coordinator model export differs from supplied D5 bundle")
        for snapshot in producer.snapshots:
            if snapshot.attempt_id in attempt_owner:
                raise ValueError("attempt ID duplicated across plan exports")
            attempt_owner[snapshot.attempt_id] = invocation.invocation_case_id
        producers[invocation.invocation_case_id] = producer
    batch_attempts = tuple(attempt for producer in producers.values()
                           for attempt in producer.attempts)
    rows = []
    snapshots = []
    accounting = []
    observations = []
    invocation_attempt_ids = []
    for invocation in request.invocations:
        producer = producers.get(invocation.invocation_case_id)
        if producer is None:
            continue
        bundle = bundles[invocation.invocation_case_id]
        invocation_attempt_ids.append(tuple(row.attempt_id for row in producer.snapshots))
        snapshots.extend(row.model_dump(mode="json") for row in producer.snapshots)
        accounting.append({"invocation_case_id": invocation.invocation_case_id,
                           "scenario_id": invocation.scenario_id,
                           "accounting": producer.authoritative_accounting.model_dump(mode="json"),
                           "scope": "invocation only; not summed with cumulative journal"})
        if (invocation.export_sha256 is None
                or invocation.producer_provenance_sha256 is None
                or invocation.index_sha256 is None):
            failures.append({"invocation_case_id": invocation.invocation_case_id,
                             "scenario_id": invocation.scenario_id,
                             "reason": "export_provenance_or_index_pin_missing; attempts retained"})
            continue
        local_request = request.authority_request.model_copy(update={
            "expected_export_sha256": invocation.export_sha256,
            "expected_index_sha256": invocation.index_sha256,
            "scenario_case_id": invocation.scenario_id,
            "include_utility_summary": False,
            "submissions": submissions_by_invocation.get(invocation.invocation_case_id, ()),
            "journal_links": request.journal_links,
            "batch_attempts": batch_attempts,
        })
        local = import_assessments(local_request, bundle=bundle,
            capture_directory=capture_directories[invocation.invocation_case_id])
        observations.extend(local["observations"])
        failures.extend(local["cases_missing_or_incomplete"])
        rows.append({"invocation_case_id": invocation.invocation_case_id,
                     "scenario_id": invocation.scenario_id, "result": local})
    journal_ids = {row["attempt_id"] for row in journal["attempts"]}
    snapshot_ids = set(attempt_owner)
    if not snapshot_ids <= journal_ids:
        raise ValueError("per-plan attempts absent from pinned global journal")
    missing_attempt_ids = reconcile_attempt_ids(tuple(invocation_attempt_ids), tuple(journal_ids))
    authority = request.authority_request.authority
    try:
        batch_p_utility = p_utility(
            tuple(row.expected_case for row in authority.cases),
            tuple(PObservation.model_validate_json(canonical(row)) for row in observations),
            authority.global_pin, tuple(row for row in batch_attempts if row.arm == "P"),
            authority.global_pin_sha256, set(authority.generator_authors),
            authority.appointed_assessors, authority.appointed_adjudicator)
    except (ValueError, TypeError, KeyError):
        batch_p_utility = {"arm": "P", "measurement_status": "INCOMPLETE",
                           "expected_explanations": len(authority.cases),
                           "successful_explanations": 0,
                           "cases": [], "product_acceptance": False}
        failures.append({"reason": "batch_p_utility_incomplete; attempts or observation joins unresolved"})
    return {
        "schema_version": 1, "private": True, "batch": True,
        "authority_sha256": request.authority_request.authority_sha256,
        "scenario_inventory_sha256": request.scenario_inventory_sha256,
        "eligible_raw_scenarios": len(request.scenario_inventory),
        "eligible_findings": len(request.authority_request.authority.cases),
        "coordinator_provenance_sha256": request.coordinator_provenance_sha256,
        "execution_mode": execution_mode,
        "execution_authority_sha256": provenance.get("execution_authority_sha256"),
        "global_journal_sha256": request.global_journal_sha256,
        "cost_accounting": cost_scope_record(journal, accounting),
        "invocations": rows,
        "attempt_snapshots": snapshots, "unmatched_global_attempt_ids": missing_attempt_ids,
        "cases_missing_or_incomplete": failures,
        "observations": observations, "live_eligible": False,
        "p_utility": batch_p_utility,
        "identity_authenticated": False, "semantic_assessment_complete": False,
        "product_acceptance": False,
    }
