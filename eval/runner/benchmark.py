"""Fixed seven-arm PUBLIC DEVELOPMENT coordinator; source construction only.

No gold/scorer/heldout accessor, provider adapter, plugin loader or worker system.
Local producer code is trusted; the inference boundary receives Request only.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import json
import math
import os
from pathlib import Path
import re
from typing import Callable

from iac_review.attempts import AttemptJournal, Budget, JournalError
from iac_review.contracts import PlanDocument
from iac_review.explain import ExplanationCapsule, build_capsule
from eval.model.experiment import (Context, FindingLink, Limits as ModelLimits, ResourceLink,
                                   Result as ModelResult, canonical, digest, run_experiments)
from eval.model.provenance import ExportBundle, export_bundle
from eval.model.protocol import ModelOnlyRequest, model_only_input
from eval.model.transport import INSTRUCTIONS, Reply, Request, Transport
from eval.runner.scoring import ARMS, ArmRow
from eval.scanners.driver import compare as scanner_compare
from eval.scanners.runner import CHECK_ID, SHA256, bounded_read, strict_json
from eval.scanners.run_manifest import ScannerRunContext, adapt_scanner_report
from eval.scanners.scoring_bridge import report_digest
from iac_review.contracts.manifest import (ArtifactRef, AttemptMetadata, CaseBinding,
    EvaluationEligibility, InvocationMetadata, RunManifest)

FIXED_ARMS = ("D", "L", "P", "M", "C", "C-custom", "T")
RULES = ("R1", "R2", "R3", "R4")
OPAQUE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}\Z")


@dataclass(frozen=True)
class CaseSpec:
    case_id: str
    plan_path: Path = field(repr=False)
    plan_sha256: str
    configuration_id: str
    family_id: str
    mutation_lineage: str
    # Exact external case RECORD pin, never derived from raw/request/projection.
    case_record_sha256: str | None = None


@dataclass(frozen=True)
class BenchmarkConfig:
    run_id: str
    edition_id: str
    build_sha256: str
    cases: tuple[CaseSpec, ...]
    budget: Budget
    model_limits: ModelLimits = ModelLimits()
    scanner_arms_json: str = "{}"
    input_scope: str = "development_synthetic"
    fake_only: bool = True
    synthetic_input_attested: bool = False


@dataclass(frozen=True)
class ProductResult:
    plan: PlanDocument = field(repr=False)
    shareable_json: str = field(repr=False)
    baseline: tuple[ArmRow, ...]
    links: tuple[FindingLink, ...]
    resource_links: tuple[ResourceLink, ...]
    # Only consumed by the local scanner adapter; never passed to inference.
    scanner_resources: tuple[tuple[str, str], ...] = field(repr=False)
    mock: bool = False


def product_adapter(case: CaseSpec, build_sha256: str) -> ProductResult:
    """Actual parser/rules/report path; no model/scanner/gold dependency."""
    from iac_review.ingest import load_plan
    from iac_review.rules import evaluate
    from iac_review.report import build_report

    plan = load_plan(case.plan_path)
    evaluations = evaluate(plan)
    report = build_report(plan, evaluations)
    shared, private = report.shareable, report.private
    baseline, links, resources = [], [], {}
    limits = {row["id"] for row in shared["limitations"]}
    reference = "sha256:" + digest(canonical(shared))
    for evaluation, public, local in zip(evaluations, shared["evaluations"], private["evaluations"], strict=True):
        if public["rule_id"] != evaluation.rule_id or local["finding_id"] != public["finding_id"]:
            raise ValueError("product_report_join_invalid")
        previous = resources.setdefault(evaluation.resource_key, public["resource_id"])
        if previous != public["resource_id"]:
            raise ValueError("product_resource_join_invalid")
        row = ArmRow(schema_version=2, measurement_kind="unverified", case_id=case.case_id,
                     resource_id=public["resource_id"], rule_id=evaluation.rule_id, arm="D", status="ok",
                     applicability=public["applicability"], outcome=public["outcome"], reason_code=local["reason_code"],
                     decision_fact_ids=tuple(f["fact_id"] for f in public["facts"] if f["role"] == "decision"),
                     required_limitation_ids=tuple(sorted(limits | set(public["limitation_ids"]))),
                     source_sha256=case.plan_sha256, build_sha256=build_sha256, measurement_ref=reference)
        baseline.append(row)
        if row.applicability == "supported" and row.outcome is not None:
            links.append(FindingLink(public["finding_id"], row.case_id, row.resource_id, row.rule_id))
    bindings = tuple((resources[r.key], r.address) for r in plan.resources)
    return ProductResult(plan, canonical(shared), tuple(baseline), tuple(links),
                         tuple(ResourceLink(public, local) for local, public in resources.items()), bindings)


@dataclass(frozen=True)
class ArmStatus:
    case_id: str
    arm: str
    status: str
    reason_code: str
    provenance_ref: str | None = None
    live_eligible: bool = False


@dataclass(frozen=True)
class BenchmarkResult:
    rows: tuple[ArmRow, ...]
    statuses: tuple[ArmStatus, ...]
    model_exports: tuple[ExportBundle, ...]
    # Allowlisted metadata only. Never serialize ProductResult or ModelResult.
    private_provenance_json: str
    manifest_candidate_json: str
    public_summary_json: str
    live_eligible: bool = field(default=False, init=False)


def validate_config(config: BenchmarkConfig) -> None:
    """Run before reading any raw case: hidden scope has no construction accessor."""
    if (tuple(ARMS) != FIXED_ARMS or config.input_scope != "development_synthetic"
            or config.fake_only is not True or config.synthetic_input_attested is not True):
        raise ValueError("development_fake_only_scope_required_before_payload_access")
    for value in (config.run_id, config.edition_id):
        if not OPAQUE.fullmatch(value):
            raise ValueError("opaque_run_identity_required")
    if not SHA256.fullmatch(config.build_sha256) or not 0 < len(config.cases) <= 256:
        raise ValueError("bounded_pinned_case_inventory_required")
    if len({case.case_id for case in config.cases}) != len(config.cases):
        raise ValueError("duplicate_case_identity")
    for case in config.cases:
        if (not case.plan_path.is_absolute() or not SHA256.fullmatch(case.plan_sha256)
                or any(not OPAQUE.fullmatch(value) for value in (case.case_id, case.configuration_id,
                                                               case.family_id, case.mutation_lineage))):
            raise ValueError("invalid_case_metadata")
        if case.case_record_sha256 is not None and not SHA256.fullmatch(case.case_record_sha256):
            raise ValueError("invalid_external_case_record_pin")
    for value in (config.budget.max_requests, config.budget.max_input_tokens, config.budget.max_output_tokens):
        if type(value) is not int or value <= 0:
            raise ValueError("positive_run_wide_caps_required")
    if not config.budget.max_usd.is_finite() or config.budget.max_usd < 0:
        raise ValueError("finite_run_wide_exposure_cap_required")
    if config.budget.max_requests > 10_000:
        raise ValueError("run_request_inventory_bound")
    for name in ("input_tokens_upper", "output_tokens_upper", "max_input_bytes", "max_output_bytes", "max_attempts"):
        count = getattr(config.model_limits, name)
        if type(count) is not int or not 0 < count <= 1_000_000:
            raise ValueError("bounded_positive_model_limits_required")
    if (type(config.model_limits.timeout_seconds) not in {int, float}
            or not math.isfinite(config.model_limits.timeout_seconds)
            or not 0 < config.model_limits.timeout_seconds <= 300):
        raise ValueError("bounded_finite_model_deadline_required")
    arms = strict_json(config.scanner_arms_json.encode())
    if not isinstance(arms, dict) or set(arms) - {"C", "C-custom", "T"}:
        raise ValueError("fixed_scanner_arms_only")
    for settings in arms.values():
        if not isinstance(settings, dict) or set(settings) - {"check_ids", "fake_fixtures"}:
            raise ValueError("fake_fixture_scanner_configuration_only")
        checks = settings.get("check_ids", [])
        fixtures = settings.get("fake_fixtures", {})
        if (not isinstance(checks, list) or len(checks) > 256
                or any(not isinstance(check, str) or not CHECK_ID.fullmatch(check) for check in checks)
                or len(checks) != len(set(checks)) or not isinstance(fixtures, dict)
                or set(fixtures) - {case.case_id for case in config.cases}):
            raise ValueError("bounded_matched_fake_fixture_configuration_required")
        for fixture in fixtures.values():
            if (not isinstance(fixture, dict) or not {"stdout_path", "stdout_sha256"} <= set(fixture)
                    or set(fixture) - {"stdout_path", "stdout_sha256", "exit_code", "timed_out"}
                    or not isinstance(fixture["stdout_path"], str) or not Path(fixture["stdout_path"]).is_absolute()
                    or not isinstance(fixture["stdout_sha256"], str) or not SHA256.fullmatch(fixture["stdout_sha256"])
                    or type(fixture.get("exit_code", 0)) is not int or type(fixture.get("timed_out", False)) is not bool):
                raise ValueError("closed_pinned_fake_fixture_required")


def verify_case(case: CaseSpec) -> None:
    if digest(bounded_read(case.plan_path, 16 * 1024 * 1024)) != case.plan_sha256:
        raise ValueError("raw_case_changed")


def source_build_digest() -> str:
    """Read fixed application source only, with agent/private containers pruned."""
    root = Path(__file__).resolve().parents[2]
    files = []
    for relative in ("src/iac_review", "eval/model", "eval/scanners", "eval/runner", "scripts"):
        for current, directories, names in os.walk(root / relative, followlinks=False):
            directories[:] = [name for name in directories if not name.startswith(".")
                and name not in {"__pycache__", "node_modules"}
                and not (Path(current) / name).is_symlink()
                and not (hasattr(Path(current) / name, "is_junction") and (Path(current) / name).is_junction())]
            files.extend(Path(current) / name for name in names if name.endswith(".py"))
    files.append(root / "pyproject.toml")
    return digest(canonical([(path.relative_to(root).as_posix(), digest(bounded_read(path, 2 * 1024 * 1024)))
                              for path in sorted(set(files))]))


def _manifest_scope(config: BenchmarkConfig, context: RunManifest | None, expected_pin: str | None) -> None:
    if (context is None) != (expected_pin is None):
        raise ValueError("typed_manifest_context_and_external_pin_required_together")
    if context is None:
        return
    if not isinstance(context, RunManifest):
        raise ValueError("actual_shared_RunManifest_context_required")
    if (digest(canonical(context.model_dump(mode="json"))) != expected_pin
            or context.run_id != config.run_id or context.edition_id != config.edition_id
            or context.build_sha256 != config.build_sha256 or context.split != "dev"
            or context.edition_state != "development" or context.invocations or context.attempts or context.eligibility):
        raise ValueError("external_manifest_context_scope_or_receipt_mismatch")
    expected = {(case.case_id, case.plan_sha256, case.configuration_id, case.family_id, case.mutation_lineage)
                for case in config.cases}
    actual = {(case.case_id, case.raw_source_sha256, case.configuration_id, case.family_id, case.mutation_lineage)
              for case in context.cases if case.split == "dev"}
    if actual != expected or len(context.cases) != len(expected):
        raise ValueError("manifest_context_case_inventory_mismatch")
    if any(ref.visibility != "private" or not ref.path.startswith("private/")
           or ref.role in {"oracle", "private_map", "report_shareable"} for ref in context.artifacts):
        raise ValueError("manifest_context_must_not_import_hidden_or_public_payload_references")


def _joined_attempts(snapshot: dict, spans: list[dict], exports: list[ExportBundle], cases: tuple[CaseSpec, ...]):
    """Preserve all journal attempts, including aborted/unmatched producer calls."""
    receipts, duplicates, result, missing = {}, set(), [], set()
    by_case = {case.case_id: case for case in cases}
    for bundle in exports:
        for receipt in json.loads(bundle.attempts_json):
            key = receipt["attempt_id"]
            if key in receipts:
                duplicates.add(key)
            receipts[key] = receipt
    for index, attempt in enumerate(snapshot.get("attempts", [])):
        owners = [span["case_id"] for span in spans if span["start_index"] <= index < span["stop_index"]]
        receipt = receipts.get(attempt["attempt_id"]) if attempt["attempt_id"] not in duplicates else None
        case = by_case.get(owners[0]) if len(owners) == 1 else None
        if receipt is None or case is None or receipt.get("arm") not in {"L", "P", "M"}:
            missing.add("model_attempt_arm_or_case_unmatched")
        hashes = receipt.get("hashes", {}) if receipt else {}
        result.append({"attempt_id": attempt["attempt_id"], "case_id": case.case_id if case else None,
            "arm": receipt["arm"] if receipt else None, "snapshot": attempt, "producer": receipt,
            "raw_input_sha256": case.plan_sha256 if case else None,
            "case_record_sha256": case.case_record_sha256 if case else None,
            "request_input_sha256": hashes.get("input"), "safe_projection_sha256": hashes.get("projection")})
    if duplicates:
        missing.add("duplicate_model_export_attempt")
    if snapshot.get("snapshot_unavailable"):
        missing.add("journal_snapshot_unavailable")
    return result, missing


def _typed_candidate(context: RunManifest | None, *, source: dict, statuses: list[ArmStatus],
                     rows: list[ArmRow], model_attempts: list[dict], missing: set[str]) -> tuple[RunManifest | None, set[str]]:
    missing = set(missing)
    if context is None:
        missing.add("externally_pinned_typed_manifest_context_missing")
        return None, missing
    components = {component.component_id: component for component in context.components}
    if len(components) != len(context.components):
        raise ValueError("duplicate_manifest_component_id")
    for arm in FIXED_ARMS:
        version_kind = "source" if arm == "D" else "model" if arm in {"L", "P", "M"} else "scanner"
        if (f"{arm}_version" not in components or f"{arm}_config" not in components
                or components[f"{arm}_config"].kind != "config"
                or components[f"{arm}_version"].kind != version_kind):
            missing.add("fixed_arm_component_bindings_missing")
    invocations, attempts, evaluations = [], [], []
    cases = {case.case_id: case for case in context.cases}
    invocation_ids = {(status.case_id, status.arm): "bench_" + digest(canonical([status.case_id, status.arm]))
                      for status in statuses}
    grouped = {key: [] for key in invocation_ids}
    for entry in model_attempts:
        key = entry["case_id"], entry["arm"]
        if key not in grouped or entry["producer"] is None:
            continue  # Missing recorded above; no invented arm/receipt.
        receipt, snapshot = entry["producer"], entry["snapshot"]
        state = "pending" if snapshot["status"] == "interrupted" else snapshot["status"]
        attempts.append(AttemptMetadata(attempt_id=entry["attempt_id"], invocation_id=invocation_ids[key],
            arm=entry["arm"], status=state, kind="mock" if source["transport_kind"] == "mock" else "unverified",
            raw_source_sha256=entry["raw_input_sha256"], safe_projection_sha256=entry["safe_projection_sha256"],
            prompt_sha256=receipt["hashes"].get("prompt"), price_sha256=receipt["price_sha256"],
            known_usd=snapshot["known_usd"], billing_known=not snapshot["requires_reconciliation"],
            unresolved_usd_upper=receipt["unresolved_usd_upper"], elapsed_ms=receipt["duration_ms"],
            input_tokens=snapshot["input_tokens"], output_tokens=snapshot["output_tokens"]))
        grouped[key].append(entry["attempt_id"])
    for export in source["scanner_exports"]:
        for capture in export["normalized_report"]["capture_receipts"]:
            if capture["execution_kind"] != "fake" or capture["elapsed_seconds"] is None:
                continue  # not_run/pre-admission is not a fabricated scanner attempt.
            key = export["case_id"], capture["arm"]
            attempt_id = "scanmock_" + digest(canonical([key, capture["capture_sha256"]]))
            attempts.append(AttemptMetadata(attempt_id=attempt_id, invocation_id=invocation_ids[key], arm=capture["arm"],
                status=capture["status"], kind="mock", raw_source_sha256=cases[key[0]].raw_source_sha256,
                elapsed_ms=int(capture["elapsed_seconds"] * 1000)))
            grouped[key].append(attempt_id)
    for status in statuses:
        key = status.case_id, status.arm
        state = status.status if status.status in {"ok", "invalid", "timeout", "error", "cancelled", "not_run"} else "not_run"
        invocations.append(InvocationMetadata(invocation_id=invocation_ids[key], arm=status.arm, status=state,
            kind="unverified" if status.arm == "D" else "mock" if source["transport_kind"] == "mock" or status.arm in {"C", "C-custom", "T"} else "unverified",
            case_ids=(status.case_id,), config_component_id=f"{status.arm}_config", version_component_id=f"{status.arm}_version",
            attempt_ids=tuple(grouped[key]), all_attempts_attested=False))
    seen = set()
    for row in rows:
        key = row.case_id, row.arm
        signature = key, row.measurement_ref
        if key not in invocation_ids:
            missing.add("scorer_case_binding_unmatched")
            continue
        if signature in seen:
            continue
        seen.add(signature)
        evaluations.append(EvaluationEligibility(arm=row.arm, invocation_id=invocation_ids[key],
            measurement_ref=row.measurement_ref, raw_source_sha256=row.source_sha256,
            eligibility_ref=None, claimed_eligible=False))
    raw = (canonical(source) + "\n").encode()
    if len(raw) > 16 * 1024 * 1024:
        missing.add("provenance_artifact_exceeds_manifest_bound")
        return None, missing
    if len(attempts) > 10000 or len(invocations) > 4096 or len(evaluations) > 100000:
        missing.add("shared_manifest_inventory_bound_exceeded")
        return None, missing
    references = list(context.artifacts)
    proposed = ArtifactRef(artifact_id="benchmark_provenance", role="producer", path="private/provenance.json",
                           sha256=digest(raw), bytes_upper=len(raw))
    if any(ref.path == proposed.path or ref.artifact_id == proposed.artifact_id for ref in references):
        missing.add("provenance_artifact_reference_conflict")
    else:
        references.append(proposed)
    if missing:
        return None, missing
    manifest = RunManifest(run_id=context.run_id, edition_id=context.edition_id, edition_state="development", split="dev",
        build_sha256=context.build_sha256, policy_sha256=context.policy_sha256, authority_sha256=context.authority_sha256,
        semantic_suite_sha256=context.semantic_suite_sha256, eligibility_sha256=context.eligibility_sha256,
        components=context.components, cases=context.cases, invocations=tuple(invocations), attempts=tuple(attempts),
        artifacts=tuple(references), eligibility=tuple(evaluations))
    return manifest, missing


class CheckedTransport:
    """Request-only guard; no case metadata, gold, splits or scanner records forwarded."""
    def __init__(self, transport: Transport, case: CaseSpec,
                 journal: AttemptJournal | None = None, budget: Budget | None = None,
                 *, plan: PlanDocument | None = None, shareable_json: str | None = None,
                 links: tuple[FindingLink, ...] = (), limits: ModelLimits = ModelLimits()) -> None:
        if transport.identity.kind not in {"mock", "protocol"}:
            raise ValueError("live_model_adapter_not_authorized")
        self._transport, self._case = transport, case
        self._journal, self._budget = journal, budget
        self._limits = limits
        shared = json.loads(shareable_json) if shareable_json is not None else None
        self._capsules = {digest(canonical(build_capsule(shared, link.finding_id).model_dump(mode="json")))
                          for link in links} if shared is not None else set()
        expected, private_map = model_only_input(plan) if plan is not None else (None, None)
        self._m_semantics = self._semantics(expected) if expected is not None else None
        del private_map

    @staticmethod
    def _semantics(value: ModelOnlyRequest) -> str:
        # IDs are freshly opaque per projection. Compare all facts/policy/actions
        # to the producer's safe RAW projection, never to D findings or labels.
        resources = []
        for resource in value.model_dump(mode="json")["resources"]:
            resource.pop("resource_id")
            for fact in resource["facts"]:
                fact.pop("fact_id")
            resources.append(resource)
        return digest(canonical({"policy": value.policy, "policy_version": value.policy_version,
                                  "resources": resources}))

    @property
    def identity(self):
        return self._transport.identity

    def complete(self, request: Request) -> Reply:
        verify_case(self._case)
        if self._journal is not None and self._journal.budget != self._budget:
            raise ValueError("run_wide_budget_changed")
        if not isinstance(request, Request) or request.arm not in {"L", "P", "M"}:
            raise ValueError("fixed_model_request_required")
        if request.instruction != INSTRUCTIONS[request.arm]:
            raise ValueError("fixed_model_instructions_required")
        if (len(request.payload_json.encode("utf-8")) > self._limits.max_input_bytes
                or not 0 <= request.input_tokens_upper <= self._limits.input_tokens_upper
                or not 0 <= request.output_tokens_upper <= self._limits.output_tokens_upper
                or request.timeout_seconds != self._limits.timeout_seconds):
            raise ValueError("fixed_model_request_bounds_required")
        if request.arm == "M":
            parsed = ModelOnlyRequest.model_validate_json(request.payload_json)
            ids = [parsed.case_id, *(resource.resource_id for resource in parsed.resources),
                   *(fact.fact_id for resource in parsed.resources for fact in resource.facts)]
            if (self._m_semantics is None or self._semantics(parsed) != self._m_semantics
                    or any(not re.fullmatch(r"[0-9a-f]{32}", value) for value in ids)):
                raise ValueError("M_projection_not_the_safe_raw_input")
        else:
            parsed = ExplanationCapsule.model_validate_json(request.payload_json)
            if digest(canonical(parsed.model_dump(mode="json"))) not in self._capsules:
                raise ValueError("L_P_capsule_not_the_frozen_safe_D_projection")
        reply = self._transport.complete(request)
        verify_case(self._case)
        if self._journal is not None and self._journal.budget != self._budget:
            raise ValueError("run_wide_budget_changed")
        return reply


def _missing_rows(product: ProductResult, arms: tuple[str, ...], reason: str) -> tuple[ArmRow, ...]:
    return tuple(ArmRow(schema_version=2, measurement_kind="mock", case_id=base.case_id,
                        resource_id=base.resource_id, rule_id=base.rule_id, arm=arm, status="not_run",
                        reason_code=reason, source_sha256=base.source_sha256, build_sha256=base.build_sha256,
                        measurement_ref="sha256:" + digest(canonical([arm, reason, base.measurement_ref])))
                 for base in product.baseline for arm in arms)


def _validate_export(bundle: ExportBundle, product: ProductResult, expected_context: Context) -> None:
    if bundle.live_eligible or tuple(bundle.rows[:len(product.baseline)]) != product.baseline:
        raise ValueError("model_export_changed_D_or_eligibility")
    provenance = json.loads(bundle.provenance_json)
    if any(provenance.get(name) != getattr(expected_context, name) for name in Context.__dataclass_fields__):
        raise ValueError("model_export_context_hash_meaning_mismatch")
    keys = {(base.case_id, base.resource_id, base.rule_id) for base in product.baseline}
    seen = set()
    for row in bundle.rows[len(product.baseline):]:
        key = row.case_id, row.resource_id, row.rule_id
        if (row.arm not in {"L", "P", "M"} or key not in keys or (row.arm, key) in seen
                or row.status != "not_run" or row.eligibility_ref is not None
                or row.source_sha256 != expected_context.source_sha256
                or row.build_sha256 != expected_context.build_sha256
                or row.measurement_kind not in {"mock", "unverified"}):
            raise ValueError("model_export_foreign_or_promoted_row")
        seen.add((row.arm, key))
    if len(seen) != len(keys) * 3:
        raise ValueError("model_export_missing_required_rows")


def coordinate(config: BenchmarkConfig, *, journal: AttemptJournal, transport: Transport,
               product: Callable = product_adapter, models: Callable = run_experiments,
               scanners: Callable = scanner_compare, manifest_context: RunManifest | None = None,
               expected_manifest_context_sha256: str | None = None,
               build_verifier: Callable[[], str] | None = None,
               operator_config_sha256: str | None = None) -> BenchmarkResult:
    """One owned journal across all cases. Fixed producers, no scorer/gold phase.

    Injected local implementations are trusted fake test seams, not plugin paths.
    Actual model Transport identity remains mock/protocol and always ineligible.
    """
    validate_config(config)
    _manifest_scope(config, manifest_context, expected_manifest_context_sha256)
    if operator_config_sha256 is not None and not SHA256.fullmatch(operator_config_sha256):
        raise ValueError("invalid_operator_config_file_pin")
    if build_verifier is not None and build_verifier() != config.build_sha256:
        raise ValueError("source_build_mismatch_before_payload_access")
    if type(journal) is not AttemptJournal or journal.budget != config.budget:
        raise ValueError("one_actual_run_wide_journal_required")
    if transport.identity.kind not in {"mock", "protocol"}:
        raise ValueError("live_model_adapter_not_authorized")
    rows, statuses, exports, scanner_parts, scanner_exports, spans = [], [], [], [], [], []
    export_cases, export_admission_missing = [], set()
    case_bindings = [CaseBinding(case_id=case.case_id, split="dev", configuration_id=case.configuration_id,
                                 family_id=case.family_id, mutation_lineage=case.mutation_lineage,
                                 raw_source_sha256=case.plan_sha256) for case in config.cases]
    bindings_by_id = {binding.case_id: binding for binding in case_bindings}
    aborted, last_count = False, journal.summary()["requests"]
    frozen_price, public_cases = journal.price, set()
    model_halt, verified_raw_inputs = False, set()
    corpus = digest(canonical([(case.case_id, case.plan_sha256, case.configuration_id,
                                case.family_id, case.mutation_lineage) for case in config.cases]))
    config_sha = digest(canonical({"run": config.run_id, "budget": json.loads(config.budget.model_dump_json()),
                                   "price": journal.price.model_dump(mode="json"),
                                   "model_limits": config.model_limits.__dict__, "scanner_arms": json.loads(config.scanner_arms_json)}))
    for case in config.cases:
        if aborted:
            statuses.extend(ArmStatus(case.case_id, arm, "not_run", "run_aborted_before_case_access") for arm in FIXED_ARMS)
            continue
        local_rows, local_status = [], {}
        start_count = journal.summary()["requests"]
        if start_count < last_count or journal.budget != config.budget or journal.price != frozen_price:
            raise ValueError("run_wide_budget_reset_detected")
        produced = None
        try:
            verify_case(case)
            verified_raw_inputs.add(case.plan_sha256)
            produced = product(case, config.build_sha256)
            verify_case(case)
            if (produced.plan.identity.sha256 != case.plan_sha256
                    or not produced.baseline or len(produced.baseline) * 7 + len(rows) > 100_000
                    or any(row.arm != "D" or row.source_sha256 != case.plan_sha256
                           or row.build_sha256 != config.build_sha256 or row.eligibility_ref is not None
                           or row.measurement_kind not in {"mock", "unverified"}
                           for row in produced.baseline)):
                raise ValueError("deterministic_source_join_invalid")
            expected_cells = {(link.resource_id, rule) for link in produced.resource_links for rule in RULES}
            if ({row.case_id for row in produced.baseline} != {case.case_id}
                    or {(row.resource_id, row.rule_id) for row in produced.baseline} != expected_cells
                    or len(produced.baseline) != len(expected_cells)):
                raise ValueError("deterministic_required_cells_missing")
            baseline_sha = digest(canonical([row.model_dump(mode="json") for row in produced.baseline]))
            local_rows.extend(produced.baseline)
            local_status["D"] = ArmStatus(case.case_id, "D", "mock" if produced.mock else "ok",
                                          "local_D_without_external_admission", baseline_sha)
            public_case = produced.baseline[0].case_id
            if public_case in public_cases:
                raise ValueError("duplicate_public_case_identity")
            public_cases.add(public_case)
            if journal.budget != config.budget:
                raise ValueError("run_wide_budget_changed")
            if model_halt or journal.summary()["new_requests_blocked"]:
                local_rows.extend(_missing_rows(produced, ("L", "P", "M"), "run_wide_liability_blocks_models"))
                for arm in ("L", "P", "M"):
                    local_status[arm] = ArmStatus(case.case_id, arm, "not_run", "run_wide_liability_blocks_models")
            else:
                try:
                    verify_case(case)
                    model_context = Context(config.build_sha256, case.plan_sha256, corpus, config_sha)
                    result: ModelResult = models(plan=produced.plan, shareable=json.loads(produced.shareable_json),
                        baseline=produced.baseline, links=produced.links, resource_links=produced.resource_links,
                        context=model_context,
                        transport=CheckedTransport(transport, case, journal, config.budget, plan=produced.plan,
                            shareable_json=produced.shareable_json, links=produced.links, limits=config.model_limits),
                        journal=journal, limits=config.model_limits,
                        capture_private_prose=False)
                    bundle = export_bundle(result)
                    del result  # Transient P prose/private model maps never enter coordinator output.
                    # Keep original safe exports, including zero-row/rejected ones.
                    # Case identity belongs to this invocation, never rows[0].
                    exports.append(bundle)
                    export_cases.append(case)
                    _validate_export(bundle, produced, model_context)
                    local_rows.extend(bundle.rows[len(produced.baseline):])
                    observations = json.loads(bundle.observations_json)
                    for arm in ("L", "P", "M"):
                        seen = [o for o in observations if o["arm"] == arm]
                        state = "not_run" if not seen or all(o["status"] == "not_run" for o in seen) else "mock"
                        for failed in ("timeout", "error", "invalid", "cancelled"):
                            if any(o["status"] == failed for o in seen):
                                state = failed
                                break
                        local_status[arm] = ArmStatus(case.case_id, arm, state, "mock_or_protocol_not_measured",
                                                      digest(bundle.provenance_json))
                except (ValueError, OSError, TypeError, KeyError, RuntimeError):
                    export_admission_missing.add("model_export_admission_incomplete")
                    model_halt = True
                    local_rows.extend(_missing_rows(produced, ("L", "P", "M"), "model_producer_incomplete"))
                    for arm in ("L", "P", "M"):
                        local_status[arm] = ArmStatus(case.case_id, arm, "not_run", "model_producer_incomplete")
            verify_case(case)
            if digest(canonical([row.model_dump(mode="json") for row in produced.baseline])) != baseline_sha:
                raise ValueError("D_baseline_changed")
            # Scanner results are created only AFTER model inference has returned.
            settings = json.loads(config.scanner_arms_json)
            for setting in settings.values():
                if "fake_fixtures" in setting:
                    fixture = setting["fake_fixtures"].get(case.case_id)
                    setting["fake_fixtures"] = {public_case: fixture} if fixture is not None else {}
            scanner_manifest = {"schema_version": "m4-scanner-run-v1", "input_scope": "development_synthetic",
                "build_sha256": config.build_sha256, "cases": [{"case_id": public_case,
                "plan_path": str(case.plan_path), "plan_sha256": case.plan_sha256,
                "resources": [{"resource_id": rid, "address": address} for rid, address in produced.scanner_resources]}],
                "arms": settings}
            try:
                scan = scanners(scanner_manifest, fake_only=True)
                if scan.get("fake_only") is not True or any(
                        receipt.get("execution_kind") not in {"fake", "none"} for receipt in scan["capture_receipts"]):
                    raise ValueError("scanner_fake_mode_cannot_promote_execution")
                context = ScannerRunContext("scanner_" + case.case_id, config.edition_id,
                                             cases=(bindings_by_id[case.case_id],))
                adapted = adapt_scanner_report(scan, expected_report_sha256=report_digest(scan), context=context)
                scan_keys = {(row.arm, row.case_id, row.resource_id, row.rule_id) for row in adapted.bridge.rows}
                expected_scan_keys = {(arm, row.case_id, row.resource_id, row.rule_id)
                                      for arm in ("C", "C-custom", "T") for row in produced.baseline}
                if (scan_keys != expected_scan_keys or len(adapted.bridge.rows) != len(expected_scan_keys)
                        or any(row.source_sha256 != case.plan_sha256 or row.build_sha256 != config.build_sha256
                               for row in adapted.bridge.rows)):
                    raise ValueError("scanner_foreign_or_missing_required_cells")
                scanner_parts.append(json.loads(adapted.public_summary_json))
                scanner_exports.append({"case_id": case.case_id, "normalized_report": scan})
                local_rows.extend(adapted.bridge.rows)
                for arm in ("C", "C-custom", "T"):
                    local_status[arm] = ArmStatus(case.case_id, arm, "not_run", "scanner_fake_or_missing_not_measured",
                                                  adapted.bridge.source_report_sha256)
            except (ValueError, OSError, TypeError, KeyError, RuntimeError):
                local_rows.extend(_missing_rows(produced, ("C", "C-custom", "T"), "scanner_admission_incomplete"))
                for arm in ("C", "C-custom", "T"):
                    local_status[arm] = ArmStatus(case.case_id, arm, "not_run", "scanner_admission_incomplete")
            verify_case(case)
            rows.extend(local_rows)
        except (ValueError, OSError, TypeError, KeyError, RuntimeError, KeyboardInterrupt) as error:
            changed = False
            try:
                verify_case(case)
            except (ValueError, OSError):
                changed = True
            cancelled = isinstance(error, KeyboardInterrupt)
            aborted |= changed or cancelled
            local_status = {arm: ArmStatus(case.case_id, arm, "invalid" if changed else "cancelled" if cancelled else "not_run",
                                           "input_identity_abort" if changed else "operator_cancelled" if cancelled else "case_admission_failed")
                            for arm in FIXED_ARMS}
        end_count = journal.summary()["requests"]
        if end_count < start_count or journal.budget != config.budget or journal.price != frozen_price:
            raise ValueError("run_wide_budget_reset_detected")
        spans.append({"case_id": case.case_id, "start_index": start_count, "stop_index": end_count})
        last_count = end_count
        statuses.extend(local_status.get(arm, ArmStatus(case.case_id, arm, "not_run", "required_arm_missing"))
                        for arm in FIXED_ARMS)
    build_changed = build_verifier is not None and build_verifier() != config.build_sha256
    if build_changed:
        aborted = True
        statuses = [ArmStatus(s.case_id, s.arm, "invalid", "source_build_changed") for s in statuses]
    try:
        snapshot = AttemptJournal.snapshot(journal.path)
    except (JournalError, OSError):
        snapshot = {"summary": journal.summary(), "attempts": [], "snapshot_unavailable": True,
                    "all_attempts_retained": False, "reason_code": "journal_snapshot_unavailable"}
    model_attempts, provenance_missing = _joined_attempts(snapshot, spans, exports, config.cases)
    provenance_missing.update(export_admission_missing)
    if build_changed:
        provenance_missing.add("source_build_changed")
    source = {"schema_version": "m4-seven-arm-benchmark-provenance-v1", "run_id": config.run_id,
              "build_sha256": config.build_sha256, "corpus_metadata_sha256": corpus, "config_sha256": config_sha,
              "operator_config_file_sha256": operator_config_sha256,
              "transport_kind": transport.identity.kind,
              "source_build_check": "not_performed" if build_verifier is None else "mismatch" if build_changed else "matched",
              "case_records": [{"case_id": case.case_id, "raw_input_sha256": case.plan_sha256,
                                "case_record_sha256": case.case_record_sha256} for case in config.cases],
              "case_bindings": [binding.model_dump(mode="json") for binding in case_bindings],
              "model_exports": [{"case_id": case.case_id,
                                 "raw_input_sha256": case.plan_sha256,
                                 "rows": [row.model_dump(mode="json") for row in e.rows],
                                 "attempts": json.loads(e.attempts_json), "accounting": json.loads(e.accounting_json),
                                 "provenance": json.loads(e.provenance_json), "observations": json.loads(e.observations_json)}
                                for case, e in zip(export_cases, exports, strict=True)],
              "attempt_case_spans": spans, "journal_snapshot": snapshot, "scanner_manifest_parts": scanner_parts,
              "scanner_exports": scanner_exports,
              "model_attempts": model_attempts,
              "run_accounting": {"basis": "single cumulative journal; per-invocation exports not added again",
                                 "summary": snapshot["summary"], "complete_snapshot": not snapshot.get("snapshot_unavailable", False)},
              "aborted": aborted, "product_acceptance": False, "live_eligible": False}
    typed, manifest_missing = _typed_candidate(manifest_context, source=source, statuses=statuses,
                                               rows=rows, model_attempts=model_attempts, missing=provenance_missing)
    candidate = {"schema_version": "m4-seven-arm-run-manifest-candidate-v1", "status": "DRAFT_INCOMPLETE" if typed is None else "METADATA_ONLY",
                 "required_arms": list(FIXED_ARMS), "run_id": config.run_id, "edition_id": config.edition_id,
                 "build_sha256": config.build_sha256, "case_bindings": source["case_bindings"],
                 "provenance_sha256": digest(canonical(source)),
                 "typed_manifest": typed.model_dump(mode="json") if typed is not None else None,
                 "missing": sorted(manifest_missing), "product_acceptance": False,
                 "genuine_all_arm_admission": False}
    public = {"schema_version": "m4-seven-arm-benchmark-summary-v1", "run_id": config.run_id,
              "mode": "development_fake_only", "required_arms": list(FIXED_ARMS), "case_count": len(config.cases),
              "case_record_count": len(config.cases),
              "declared_distinct_raw_inputs": len({case.plan_sha256 for case in config.cases}),
              "verified_distinct_raw_byte_identities": len(verified_raw_inputs),
              "eligible_scenario_count": None, "scenario_coverage_gate": "EXTERNAL_FROZEN_INVENTORY_REQUIRED",
              "statuses": [{"case_id": s.case_id, "arm": s.arm, "status": s.status, "reason_code": s.reason_code}
                           for s in statuses], "requests": snapshot["summary"]["requests"],
              "new_model_requests_blocked": snapshot["summary"]["new_requests_blocked"],
              "aborted": aborted, "measurement_status": "NOT_MEASURED", "product_acceptance": False,
              "information_asymmetry": "scanners raw synthetic JSON; models allowlisted safe projections"}
    return BenchmarkResult(tuple(rows), tuple(statuses), tuple(exports), canonical(source),
                            canonical(candidate), canonical(public))
