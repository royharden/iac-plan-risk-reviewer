"""No detectors, generators, providers, scanner execution or hidden labels at inference."""
from __future__ import annotations

from collections import Counter
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


def score(oracle: list[OracleRow], measured: list[ArmRow], split: str) -> dict:
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
                "prohibited_effects", "rule_mutations")})
            for gold in (row for row in selected if row.rule_id == rule):
                counts["total"] += 1
                actual = predictions.get((arm, key(gold)))
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
                usable = actual is not None and actual.status == "ok"
                predicted = actual.outcome if usable and actual.applicability == "supported" else None
                if gold.applicability != "supported":
                    counts["unsupported" if gold.applicability == "unsupported_shape"
                           else "not_applicable"] += 1
                elif gold.outcome == "indeterminate":
                    counts["gold_indeterminate"] += 1
                    if predicted in ("introduced_risk", "unchanged_risk", "clear"):
                        counts["certainty_errors"] += 1
                        failed.append("certainty_error")
                else:
                    counts["supported_decidable"] += 1
                    positive = gold.outcome == "introduced_risk"
                    if predicted in (None, "indeterminate"):
                        counts["abstentions"] += 1
                        if positive:
                            counts["fn"] += 1
                        failed.append("abstention")
                    elif predicted == "introduced_risk":
                        counts["tp" if positive else "fp"] += 1
                        if not positive:
                            failed.append("false_positive")
                    else:
                        counts["fn" if positive else "tn"] += 1
                        if positive:
                            failed.append("false_negative")
                if arm == "D":
                    exact = usable and (
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
                "abstention_rate": ratio(counts["abstentions"], counts["supported_decidable"]),
                "gold_unknown_rate": ratio(counts["gold_indeterminate"], counts["total"]),
                "unsupported_rate": ratio(counts["unsupported"], counts["total"]),
            }
        observed = [predictions.get((arm, key(row))) for row in selected]
        complete = all(row is not None and row.status == "ok" for row in observed)
        results[arm] = {
            "measurement_status": "RECORDED" if complete else "INCOMPLETE",
            "comparison_basis": "introduced-risk; unchanged risk is negative; unknown/unsupported not TN",
            "per_rule": per_rule, "failures": failures,
            "known_usd": sum(row.known_usd or 0 for row in cost_rows),
            "billing_fully_known": bool(cost_rows) and all(
                row.billing_known and row.known_usd is not None for row in cost_rows),
            "unresolved_upper_bounds_known": all(
                row.billing_known or row.unresolved_usd_upper is not None for row in cost_rows),
            "unresolved_usd_upper": sum(row.unresolved_usd_upper or 0 for row in cost_rows),
        }
    return {"split": split, "oracle_rows": len(selected), "arms": results,
            "product_acceptance": False,
            "limitations": ["Imported measurements are not independently authenticated by this scorer.",
                            "L/P require dedicated utility/rubric metrics beyond detection confusion.",
                            "Absence of all-attempt accounting cannot establish actual cost/success."]}
