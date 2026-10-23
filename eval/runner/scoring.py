"""No detectors, generators, providers, scanner execution or hidden labels at inference."""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

ARMS = ("D", "L", "P", "M", "C", "C-custom", "T")
Outcome = Literal["introduced_risk", "unchanged_risk", "clear", "indeterminate"]
Applicability = Literal["supported", "not_applicable", "unsupported_shape"]


class Record(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class OracleRow(Record):
    case_id: str
    resource_id: str
    rule_id: Literal["R1", "R2", "R3", "R4"]
    family_id: str
    configuration_lineage: str
    mutation_lineage: str
    split: Literal["dev", "validation", "heldout"]
    applicability: Applicability
    outcome: Outcome | None
    reason_code: str
    decision_fact_ids: tuple[str, ...] = ()
    required_limitation_ids: tuple[str, ...] = ()


class ArmRow(Record):
    schema_version: Literal[1, 2] = 1
    measurement_kind: Literal["unverified", "mock", "executed", "live", "replay"] = "unverified"
    eligibility_ref: str | None = None
    prediction_target: Literal["full_outcome", "introduced_risk"] = "full_outcome"
    introduced_prediction: bool | None = None
    case_id: str
    resource_id: str
    rule_id: Literal["R1", "R2", "R3", "R4"]
    arm: Literal["D", "L", "P", "M", "C", "C-custom", "T"]
    status: Literal["ok", "invalid", "timeout", "error", "not_run", "unmapped"]
    applicability: Applicability | None = None
    outcome: Outcome | None = None
    reason_code: str | None = None
    decision_fact_ids: tuple[str, ...] = ()
    required_limitation_ids: tuple[str, ...] = ()
    invalid_displayed_refs: int = Field(default=0, ge=0)
    certainty_errors: int = Field(default=0, ge=0)
    canary_leaks: int = Field(default=0, ge=0)
    prohibited_effects: int = Field(default=0, ge=0)
    rule_mutations: int = Field(default=0, ge=0)
    known_usd: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    unresolved_usd_upper: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    billing_known: bool = False
    elapsed_seconds: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    source_sha256: str
    build_sha256: str
    measurement_ref: str

    @model_validator(mode="after")
    def prediction_shape(self) -> ArmRow:
        if self.prediction_target == "introduced_risk" and self.outcome is not None:
            raise ValueError("binary introduced prediction must not invent a full outcome")
        if self.prediction_target == "full_outcome" and self.introduced_prediction is not None:
            raise ValueError("binary value requires explicit introduced-risk target")
        return self


class Edition(Record):
    edition_id: str
    state: Literal["development", "sealed", "consumed_holdout"]
    oracle_author: str
    oracle_checker: str
    detector_authors: tuple[str, ...]
    policy_sha256: str
    oracle_sha256: str
    frozen_build_sha256: str
    lineage_inventory_sha256: str
    inference_exclusion_attested: bool = False
    independent_custody_attested: bool = False
    eligible_heldout_explanations: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def independent(self) -> Edition:
        if not self.oracle_author or not self.oracle_checker:
            raise ValueError("independent oracle author and checker are required")
        if self.oracle_author == self.oracle_checker:
            raise ValueError("oracle author and checker must differ")
        if set(self.detector_authors) & {self.oracle_author, self.oracle_checker}:
            raise ValueError("oracle custody must be independent of detector authors")
        return self


class EligibleMeasurement(Record):
    arm: Literal["D", "L", "P", "M", "C", "C-custom", "T"]
    measurement_ref: str = Field(min_length=1, max_length=256)
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    build_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    kind: Literal["executed", "live", "replay", "mock"]
    provenance_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    original_live_receipt_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    actual_execution_attested: bool


class EligibilityManifest(Record):
    schema_version: Literal[2] = 2
    edition_id: str = Field(min_length=1, max_length=160)
    rows: tuple[EligibleMeasurement, ...] = Field(max_length=100000)


def record_digest(record: Record) -> str:
    raw = json.dumps(record.model_dump(mode="json"), sort_keys=True,
                     separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    return hashlib.sha256(raw.encode("ascii")).hexdigest()


def measurement_eligible(row: ArmRow, manifest: EligibilityManifest | None) -> bool:
    """Eligibility is a pinned attestation, never authentication of real execution."""
    if manifest is None or row.schema_version != 2 or not row.eligibility_ref:
        return False
    matches = [m for m in manifest.rows if m.arm == row.arm
               and m.measurement_ref == row.measurement_ref
               and m.source_sha256 == row.source_sha256 and m.build_sha256 == row.build_sha256]
    if len(matches) != 1:
        return False
    meta = matches[0]
    if (record_digest(meta) != row.eligibility_ref or row.measurement_kind != meta.kind
            or not meta.actual_execution_attested or meta.kind == "mock"):
        return False
    if row.arm in {"L", "P", "M"}:
        return meta.kind == "live" or (meta.kind == "replay" and meta.original_live_receipt_sha256 is not None)
    return meta.kind == "executed"


def key(row: OracleRow | ArmRow) -> tuple[str, str, str]:
    return row.case_id, row.resource_id, row.rule_id


def validate_partition(rows: list[OracleRow]) -> None:
    """Connected shared family/configuration/mutation ancestry cannot cross splits."""
    seen: set[tuple[str, str, str]] = set()
    partitions: dict[tuple[str, str], str] = {}
    for row in rows:
        if key(row) in seen:
            raise ValueError("duplicate oracle identity")
        seen.add(key(row))
        for kind, value in (("family", row.family_id),
                            ("config", row.configuration_lineage),
                            ("mutation", row.mutation_lineage)):
            if not value:
                raise ValueError("lineage identifiers cannot be empty")
            label = (kind, value)
            if label in partitions and partitions[label] != row.split:
                raise ValueError("shared lineage crosses evaluation splits")
            partitions[label] = row.split
        if (row.applicability == "supported") != (row.outcome is not None):
            raise ValueError("oracle applicability/outcome disagree")


def ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def score(oracle: list[OracleRow], measured: list[ArmRow], split: str, *,
          eligibility: EligibilityManifest | None = None,
          expected_eligibility_sha256: str | None = None) -> dict:
    if len(oracle) > 100000 or len(measured) > 700000:
        raise ValueError("scoring inventory exceeds row bound")
    if eligibility is not None and (
            expected_eligibility_sha256 is None
            or record_digest(eligibility) != expected_eligibility_sha256):
        raise ValueError("eligibility manifest lacks externally pinned approval")
    if eligibility is not None:
        identities = [(m.arm, m.measurement_ref, m.source_sha256, m.build_sha256)
                      for m in eligibility.rows]
        if len(identities) != len(set(identities)):
            raise ValueError("duplicate eligibility provenance")
    eligible_signatures = set()
    if eligibility is not None:
        for meta in eligibility.rows:
            model = meta.arm in {"L", "P", "M"}
            allowed = (meta.kind == "live" or (meta.kind == "replay"
                       and meta.original_live_receipt_sha256 is not None)) if model else meta.kind == "executed"
            if meta.actual_execution_attested and allowed:
                eligible_signatures.add((meta.arm, meta.measurement_ref, meta.source_sha256,
                                         meta.build_sha256, meta.kind, record_digest(meta)))

    def eligible_row(row: ArmRow) -> bool:
        return row.schema_version == 2 and (
            row.arm, row.measurement_ref, row.source_sha256, row.build_sha256,
            row.measurement_kind, row.eligibility_ref) in eligible_signatures
    validate_partition(oracle)
    selected = [row for row in oracle if row.split == split]
    if not selected:
        raise ValueError("no independently supplied oracle rows for selected split")
    predictions: dict[tuple[str, tuple[str, str, str]], ArmRow] = {}
    oracle_keys = {key(row) for row in oracle}
    for row in measured:
        identity = row.arm, key(row)
        if identity in predictions:
            raise ValueError("duplicate arm result")
        if key(row) not in oracle_keys:
            raise ValueError("measurement has no matching oracle identity")
        predictions[identity] = row
    results = {}
    for arm in ARMS:
        per_rule = {}
        failures = []
        cost_rows = []
        for rule in ("R1", "R2", "R3", "R4"):
            counts = Counter({name: 0 for name in (
                "total", "supported_decidable", "tp", "fp", "fn", "tn", "abstentions",
                "missing", "unmapped", "gold_indeterminate", "unsupported", "not_applicable",
                "certainty_errors", "exact_failures", "invalid_displayed_refs", "canary_leaks",
                "prohibited_effects", "rule_mutations", "ineligible", "binary_predictions",
                "decidable_abstentions", "unknown_gold_abstentions")})
            for gold in (row for row in selected if row.rule_id == rule):
                counts["total"] += 1
                actual = predictions.get((arm, key(gold)))
                eligible = actual is not None and eligible_row(actual)
                failed = []
                if actual is None or actual.status == "not_run":
                    counts["missing"] += 1
                    failed.append("missing_measurement")
                elif actual.status == "unmapped":
                    counts["unmapped"] += 1
                    failed.append("unmapped")
                else:
                    cost_rows.append(actual)
                    for field in ("invalid_displayed_refs", "canary_leaks", "prohibited_effects",
                                  "rule_mutations", "certainty_errors"):
                        counts[field] += getattr(actual, field)
                if actual is not None and actual.status != "not_run" and not eligible:
                    counts["ineligible"] += 1
                    failed.append("ineligible_measurement")
                usable = actual is not None and actual.status == "ok" and eligible
                predicted = actual.outcome if usable and actual.applicability == "supported" else None
                binary = actual is not None and actual.prediction_target == "introduced_risk"
                introduced = None
                if usable and actual.applicability == "supported":
                    if binary:
                        introduced = actual.introduced_prediction
                        counts["binary_predictions"] += introduced is not None
                    elif predicted in ("introduced_risk", "unchanged_risk", "clear"):
                        introduced = predicted == "introduced_risk"
                if gold.applicability != "supported":
                    counts["unsupported" if gold.applicability == "unsupported_shape"
                           else "not_applicable"] += 1
                elif gold.outcome == "indeterminate":
                    counts["gold_indeterminate"] += 1
                    if introduced is not None:
                        counts["certainty_errors"] += 1
                        failed.append("certainty_error")
                    else:
                        counts["abstentions"] += 1
                        counts["unknown_gold_abstentions"] += 1
                else:
                    counts["supported_decidable"] += 1
                    positive = gold.outcome == "introduced_risk"
                    if introduced is None:
                        counts["abstentions"] += 1
                        counts["decidable_abstentions"] += 1
                        if positive:
                            counts["fn"] += 1
                        failed.append("abstention")
                    elif introduced is True:
                        counts["tp" if positive else "fp"] += 1
                        if not positive:
                            failed.append("false_positive")
                    else:
                        counts["fn" if positive else "tn"] += 1
                        if positive:
                            failed.append("false_negative")
                if arm == "D":
                    exact = usable and (
                        actual.prediction_target == "full_outcome"
                        and actual.introduced_prediction is None
                        and
                        actual.applicability == gold.applicability
                        and actual.outcome == gold.outcome
                        and actual.reason_code == gold.reason_code
                        and set(actual.decision_fact_ids) == set(gold.decision_fact_ids)
                    )
                    if not exact:
                        counts["exact_failures"] += 1
                        failed.append("deterministic_exact_mismatch")
                if failed:
                    failures.append({"case_id": gold.case_id, "resource_id": gold.resource_id,
                                     "rule_id": rule, "reasons": failed})
            precision = ratio(counts["tp"], counts["tp"] + counts["fp"])
            recall = ratio(counts["tp"], counts["tp"] + counts["fn"])
            per_rule[rule] = dict(counts) | {
                "precision": precision, "recall": recall,
                "f1": 2 * precision * recall / (precision + recall)
                if precision is not None and recall is not None and precision + recall else None,
                "abstention_rate": ratio(counts["decidable_abstentions"], counts["supported_decidable"]),
                "gold_unknown_rate": ratio(counts["gold_indeterminate"], counts["total"]),
                "unsupported_rate": ratio(counts["unsupported"], counts["total"]),
            }
        observed = [predictions.get((arm, key(row))) for row in selected]
        # Executed invalid/timeout/error is a recorded negative, with abstentions;
        # missing/not_run/unmapped remains incomplete. Mock/legacy cannot be live evidence.
        complete = all(row is not None and row.status not in {"not_run", "unmapped"}
                       and eligible_row(row) for row in observed)
        results[arm] = {
            "measurement_status": "RECORDED" if complete else "INCOMPLETE",
            "comparison_basis": "introduced-risk; unchanged risk is negative; unknown/unsupported not TN",
            "per_rule": per_rule, "failures": failures,
            "row_known_usd_subtotal": sum(row.known_usd or 0 for row in cost_rows),
            "known_usd": None if arm in {"L", "P", "M"} else sum(row.known_usd or 0 for row in cost_rows),
            "all_attempt_cost": None,
            "cost_completeness": "MISSING_ALL_ATTEMPT_ACCOUNTING" if arm in {"L", "P", "M"} else "ROW_SUBTOTAL_ONLY",
            "cost_scope": "row amounts only; model all-attempt utility summary is authoritative",
            "billing_fully_known": arm not in {"L", "P", "M"} and bool(cost_rows) and all(
                row.billing_known and row.known_usd is not None for row in cost_rows),
            "row_unresolved_upper_bounds_known": all(
                row.billing_known or row.unresolved_usd_upper is not None for row in cost_rows),
            "row_unresolved_usd_upper_subtotal": sum(row.unresolved_usd_upper or 0 for row in cost_rows),
            "unresolved_upper_bounds_known": arm not in {"L", "P", "M"} and bool(cost_rows) and all(
                row.billing_known or row.unresolved_usd_upper is not None for row in cost_rows),
            "unresolved_usd_upper": None if arm in {"L", "P", "M"}
            else sum(row.unresolved_usd_upper or 0 for row in cost_rows),
        }
    deterministic = results["D"]["per_rule"]
    exact = results["D"]["measurement_status"] == "RECORDED" and all(
        not row[field] for row in deterministic.values() for field in (
            "exact_failures", "certainty_errors", "invalid_displayed_refs", "canary_leaks",
            "prohibited_effects", "rule_mutations"))
    return {"split": split, "oracle_rows": len(selected), "arms": results,
            "deterministic_exact_gate": exact, "authorship_authenticated": False,
            "product_acceptance": False,
            "limitations": ["Imported measurements are not independently authenticated by this scorer.",
                            "L/P require dedicated utility/rubric metrics beyond detection confusion.",
                            "Absence of all-attempt accounting cannot establish actual cost/success."]}
