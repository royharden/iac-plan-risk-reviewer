"""Opt-in finite SelectorPort adapter; no core imports this optional eval module.

Source only under Dirty Mode. No provider/model measurement or authority is asserted.
Failures return an empty finite response so core validate_selection supplies D text.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
import json
import re

from iac_review.attempts import AttemptJournal
from iac_review.contracts import ReviewReport
from iac_review.explain import (
    ExplanationCapsule, ExplanationResponse, SelectionResult, build_capsule, validate_selection,
)
from eval.model.experiment import Attempt, Context, Limits, canonical, digest, execute_attempt
from eval.model.transport import Transport
from eval.runner.scoring import ArmRow


def _require(ok: bool, code: str) -> None:
    if not ok:
        raise ValueError(code)


def _sha(value: str) -> bool:
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _opaque(value: str) -> bool:
    return type(value) is str and re.fullmatch(r"[0-9a-f]{32}", value) is not None


def _fresh_capsule(capsule: ExplanationCapsule) -> ExplanationCapsule:
    """Re-run the actual finite core fact filter; frozen models can contain lists."""
    _require(isinstance(capsule, ExplanationCapsule), "selector_capsule_type")
    # Reject nonfinite/nonscalar nested values before model JSON serialization
    # could normalize them (e.g. NaN -> null) and conceal a mutated value.
    canonical(capsule.model_dump(mode="python"))
    serialized = capsule.model_dump_json()
    _require(len(serialized.encode("utf-8")) <= 65536, "selector_capsule_byte_limit")
    detached = ExplanationCapsule.model_validate_json(serialized)
    rebuilt = build_capsule({"projection": "shareable", "evaluations": [{
        "finding_id": detached.finding_id, "rule_id": detached.rule_id, "outcome": detached.outcome,
        "facts": [f.model_dump(mode="json") for f in detached.facts],
        "limitation_ids": list(detached.required_limitation_ids)}], "limitations": []}, detached.finding_id)
    _require(rebuilt.model_dump_json() == serialized, "selector_capsule_not_exact_finite_projection")
    return rebuilt


@dataclass(frozen=True)
class SelectorBinding:
    """Frozen finite capsule/D metadata, pinned by an external approval owner."""

    capsule_json: str = field(repr=False)
    baseline_json: str = field(repr=False)
    context: Context
    shareable_sha256: str
    baseline_sha256: str
    authority_sha256: str


def binding_digest(binding: SelectorBinding) -> str:
    return digest(canonical({"capsule_sha256": digest(binding.capsule_json),
        "baseline_sha256": binding.baseline_sha256, "baseline_wire_sha256": digest(binding.baseline_json),
        "context": asdict(binding.context), "shareable_sha256": binding.shareable_sha256,
        "authority_sha256": binding.authority_sha256}))


def _baseline_binding(capsule: ExplanationCapsule, baseline: ArmRow, context: Context) -> None:
    _require(all(_sha(v) for v in asdict(context).values()), "selector_context_pins_required")
    _require(_opaque(baseline.case_id) and _opaque(baseline.resource_id)
        and baseline.arm == "D" and baseline.status == "ok" and baseline.applicability == "supported"
        and baseline.rule_id == capsule.rule_id and baseline.outcome == capsule.outcome
        and baseline.source_sha256 == context.source_sha256 and baseline.build_sha256 == context.build_sha256
        and baseline.decision_fact_ids == capsule.required_fact_ids
        and tuple(sorted(baseline.required_limitation_ids)) == capsule.required_limitation_ids,
        "selector_D_context_or_fact_binding_mismatch")


def make_binding(*, shareable: dict, finding_id: str, baseline: ArmRow, context: Context,
                 expected_shareable_sha256: str, expected_baseline_sha256: str,
                 authority_sha256: str) -> SelectorBinding:
    """Pure construction from an actual report projection and externally pinned D row.

    No detector, raw input, private map or inferred gold is consumed. Supplied pins
    identify records; an external owner must authenticate approval and baseline origin.
    """
    _require(all(_sha(v) for v in (expected_shareable_sha256, expected_baseline_sha256, authority_sha256)),
             "selector_external_pins_required")
    _require(type(shareable) is dict and len(canonical(shareable).encode("utf-8")) <= 16 * 1024 * 1024
             and digest(canonical(shareable)) == expected_shareable_sha256, "selector_report_pin_mismatch")
    capsule = _fresh_capsule(build_capsule(shareable, finding_id))
    frozen = ArmRow.model_validate_json(baseline.model_dump_json())
    _require(digest(canonical(frozen.model_dump(mode="json"))) == expected_baseline_sha256,
             "selector_baseline_pin_mismatch")
    _baseline_binding(capsule, frozen, context)
    row = next(r for r in shareable["evaluations"] if r.get("finding_id") == finding_id)
    _require(shareable.get("case_id") == frozen.case_id and row.get("resource_id") == frozen.resource_id
        and row.get("applicability") == frozen.applicability, "selector_report_D_join_mismatch")
    return SelectorBinding(capsule.model_dump_json(), frozen.model_dump_json(), context,
        expected_shareable_sha256, expected_baseline_sha256, authority_sha256)


@dataclass(frozen=True)
class SelectorReceipt:
    """Payload-free attempt metadata; the existing journal remains authoritative."""

    finding_id: str
    baseline_sha256: str
    attempt: Attempt
    live_eligible: bool = field(default=False, init=False)


class AdmittedSelector:
    """Actual SelectorPort.select(capsule)->ExplanationResponse, default disabled.

    No discovery, journal creation, callback, key access or network on construction.
    Enabling this adapter never supplies a provider's external activation/permit;
    the injected journal-bound transport must enforce those separately.
    """

    def __init__(self, *, enabled: bool = False, binding: SelectorBinding | None = None,
                 expected_binding_sha256: str | None = None, transport: Transport | None = None,
                 journal: AttemptJournal | None = None, limits: Limits = Limits(max_attempts=1)) -> None:
        self.enabled, self.binding, self.expected_binding_sha256 = enabled, binding, expected_binding_sha256
        self.transport, self.journal = transport, journal
        self.limits = replace(limits, max_attempts=1, max_input_bytes=min(limits.max_input_bytes, 65536),
                              max_output_bytes=min(limits.max_output_bytes, 16384))
        self._receipts: list[SelectorReceipt] = []
        self.last_reason = "disabled"
        self.unrecorded_attempt_possible = False

    @property
    def receipts(self) -> tuple[SelectorReceipt, ...]:
        return tuple(self._receipts)

    def select(self, capsule: ExplanationCapsule) -> ExplanationResponse:
        # This strict wire intentionally fails the core clause-count check. Only
        # core validate_selection renders deterministic fallback, never this port.
        fallback = ExplanationResponse(clauses=(), limitation_ids=())
        self.last_reason = "disabled"
        if self.enabled is not True:
            return fallback
        try:
            b = self.binding
            _require(b is not None and _sha(self.expected_binding_sha256)
                and all(_sha(v) for v in (b.shareable_sha256, b.baseline_sha256, b.authority_sha256))
                and binding_digest(b) == self.expected_binding_sha256, "selector_binding_pin_required")
            _require(self.transport is not None and isinstance(self.journal, AttemptJournal),
                     "selector_explicit_transport_and_journal_required")
            identity = self.transport.identity
            _require(identity.kind in ("mock", "protocol") and (
                self.journal.price.provider, self.journal.price.model) == (identity.provider, identity.model),
                "selector_transport_price_identity_mismatch")
            frozen = _fresh_capsule(ExplanationCapsule.model_validate_json(b.capsule_json))
            incoming = _fresh_capsule(capsule)
            _require(incoming.model_dump_json() == frozen.model_dump_json(), "selector_foreign_or_changed_capsule")
            baseline = ArmRow.model_validate_json(b.baseline_json)
            _require(digest(canonical(baseline.model_dump(mode="json"))) == b.baseline_sha256,
                     "selector_changed_baseline")
            _baseline_binding(frozen, baseline, b.context)
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
            self.last_reason = "binding_or_capsule_denied"
            return fallback
        candidate = None

        def validate(value):
            nonlocal candidate
            selected = validate_selection(frozen, value)
            if selected.accepted:
                candidate = ExplanationResponse.model_validate_json(canonical(value))
            return selected, (), ()

        try:
            observation = execute_attempt(arm="L", payload=frozen.model_dump_json(),
                finding_id=frozen.finding_id, context=b.context, transport=self.transport,
                journal=self.journal, limits=self.limits, validator=validate)
        except Exception:
            # A durable terminal append can fail after start. Never invent a receipt
            # or retry; retain the journal's pending liability for operator recovery.
            self.unrecorded_attempt_possible = True
            self.last_reason = "attempt_path_unavailable"
            return fallback
        self.last_reason = observation.reason
        if observation.attempt is not None:
            self._receipts.append(SelectorReceipt(frozen.finding_id, b.baseline_sha256, observation.attempt))
        if observation.status != "ok" or candidate is None or observation.selection is None \
                or not observation.selection.accepted or not validate_selection(frozen, candidate).accepted:
            return fallback
        return candidate


@dataclass(frozen=True)
class ExplainedFinding:
    finding_id: str
    rule_id: str
    outcome: str
    selection: SelectionResult
    report_sha256: str
    exit_code: int
    receipt: SelectorReceipt | None
    live_eligible: bool = field(default=False, init=False)


def explain_with_admitted_selector(report: ReviewReport, finding_id: str, *,
                                   selector: AdmittedSelector | None = None) -> ExplainedFinding:
    """Pure optional product composition; no CLI, detector, raw plan or P/M call.

    Default is exact core fallback. Only an exact externally bound report/finding
    may reach the adapter; its single attempt uses the caller's existing journal.
    Report/exit changes by trusted injected code are refused, never adopted as D.
    """
    _require(isinstance(report, ReviewReport), "selector_actual_report_required")
    original = canonical(report.shareable)
    _require(len(original.encode("utf-8")) <= 16 * 1024 * 1024, "selector_report_byte_limit")
    pinned_report, exit_code = digest(original), report.exit_code
    capsule = _fresh_capsule(build_capsule(json.loads(original), finding_id))
    response = ExplanationResponse(clauses=(), limitation_ids=())
    receipt = None
    if isinstance(selector, AdmittedSelector) and selector.binding is not None \
            and selector.binding.shareable_sha256 == pinned_report:
        before = len(selector.receipts)
        response = selector.select(capsule)
        after = selector.receipts
        _require(len(after) in (before, before + 1), "selector_multiple_attempts_refused")
        if len(after) == before + 1:
            receipt = after[-1]
    selection = validate_selection(capsule, response)
    _require(canonical(report.shareable) == original and report.exit_code == exit_code,
             "selector_report_or_exit_changed")
    return ExplainedFinding(capsule.finding_id, capsule.rule_id, capsule.outcome,
        selection, pinned_report, exit_code, receipt)
