"""Safe aggregate rendering for seven-arm scorer and utility summaries."""
from __future__ import annotations

import math
from decimal import Decimal, InvalidOperation
from itertools import combinations


ARMS = ("D", "L", "P", "M", "C", "C-custom", "T")
RULES = ("R1", "R2", "R3", "R4")
TOP_KEYS = {"split", "oracle_rows", "arms", "deterministic_exact_gate",
            "authorship_authenticated", "product_acceptance", "limitations"}
ARM_KEYS = {"measurement_status", "comparison_basis", "per_rule", "failures",
            "row_known_usd_subtotal", "known_usd", "all_attempt_cost",
            "cost_completeness", "cost_scope", "billing_fully_known",
            "row_unresolved_upper_bounds_known", "row_unresolved_usd_upper_subtotal",
            "unresolved_upper_bounds_known", "unresolved_usd_upper"}
COUNT_KEYS = {"total", "supported_decidable", "tp", "fp", "fn", "tn", "abstentions",
              "missing", "unmapped", "gold_indeterminate", "unsupported", "not_applicable",
              "certainty_errors", "exact_failures", "invalid_displayed_refs", "canary_leaks",
              "prohibited_effects", "rule_mutations", "ineligible", "binary_predictions",
              "decidable_abstentions", "unknown_gold_abstentions"}
RATE_KEYS = {"precision", "recall", "f1", "abstention_rate", "gold_unknown_rate", "unsupported_rate"}


def _number(value, name: str, *, nullable: bool = False):
    if value is None and nullable:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError(f"invalid numeric result field: {name}")
    return value


def validate_score_result(source: dict) -> dict:
    """Validate the exact scorer envelope while ignoring unrendered free text."""
    if type(source) is not dict or set(source) != TOP_KEYS:
        raise ValueError("closed seven-arm score envelope required")
    if source["split"] not in ("dev", "validation", "heldout"):
        raise ValueError("invalid score split")
    if type(source["oracle_rows"]) is not int or source["oracle_rows"] <= 0:
        raise ValueError("positive independent denominator required")
    arms = source["arms"]
    if type(arms) is not dict or set(arms) != set(ARMS):
        raise ValueError("all seven scorer arms are required")
    for arm in ARMS:
        row = arms[arm]
        if type(row) is not dict or set(row) != ARM_KEYS:
            raise ValueError(f"closed scorer result required for {arm}")
        if row["measurement_status"] not in ("RECORDED", "INCOMPLETE"):
            raise ValueError("unknown measurement status")
        if type(row["per_rule"]) is not dict or set(row["per_rule"]) != set(RULES):
            raise ValueError(f"four rule rows required for {arm}")
        if type(row["failures"]) is not list or len(row["failures"]) > source["oracle_rows"]:
            raise ValueError("bounded failure inventory required")
        for failure in row["failures"]:
            if (type(failure) is not dict or not {"case_id", "resource_id", "rule_id", "reasons"} <= set(failure)
                    or any(type(failure[key]) is not str for key in ("case_id", "resource_id", "rule_id"))
                    or failure["rule_id"] not in RULES or type(failure["reasons"]) is not list):
                raise ValueError("bounded scorer failure identity required")
        for rule in RULES:
            metric = row["per_rule"][rule]
            if type(metric) is not dict or set(metric) != COUNT_KEYS | RATE_KEYS:
                raise ValueError(f"closed rule metrics required for {arm}/{rule}")
            for field in COUNT_KEYS:
                if type(metric[field]) is not int or metric[field] < 0:
                    raise ValueError(f"invalid count {arm}/{rule}/{field}")
            for field in RATE_KEYS:
                _number(metric[field], f"{arm}/{rule}/{field}", nullable=True)
            if metric["total"] > source["oracle_rows"]:
                raise ValueError("rule denominator exceeds selected inventory")
        if sum(row["total"] for row in row["per_rule"].values()) != source["oracle_rows"]:
            raise ValueError("per-rule denominators do not cover the selected inventory")
        for field in ("row_known_usd_subtotal", "known_usd", "all_attempt_cost",
                      "row_unresolved_usd_upper_subtotal", "unresolved_usd_upper"):
            if row[field] is not None:
                _number(row[field], f"{arm}/{field}")
    if type(source["deterministic_exact_gate"]) is not bool:
        raise ValueError("deterministic gate must be Boolean")
    if source["deterministic_exact_gate"] and source["arms"]["D"]["measurement_status"] != "RECORDED":
        raise ValueError("D exact gate cannot be recorded with incomplete D evidence")
    if source["authorship_authenticated"] is not False or source["product_acceptance"] is not False:
        raise ValueError("renderer input cannot claim authorship authentication or acceptance")
    return source


def _fmt(value, digits: int = 3) -> str:
    if value is None:
        return "NA"
    return f"{value:.{digits}f}" if isinstance(value, float) else str(value)


def _usd_string(value, field: str) -> str | None:
    if value is None:
        return None
    if type(value) is not str or len(value) > 128:
        raise ValueError(f"invalid accounting amount: {field}")
    try:
        amount = Decimal(value)
    except InvalidOperation as error:
        raise ValueError(f"invalid accounting amount: {field}") from error
    if not amount.is_finite() or amount < 0:
        raise ValueError(f"invalid accounting amount: {field}")
    return str(amount)


def _accounting_view(arm: str, score_arm: dict, accounting: dict,
                     utility_cost: dict | None = None) -> dict:
    partial = {
        "row_known_usd_subtotal": score_arm["row_known_usd_subtotal"],
        "row_unresolved_usd_upper_subtotal": score_arm["row_unresolved_usd_upper_subtotal"],
        "row_scope": "partial per-row subtotal; does not include unjoined or no-row attempts",
    }
    if arm not in {"L", "P", "M"}:
        return partial | {"all_attempt": "NOT MEASURED"}
    row = accounting.get(arm) if type(accounting) is dict else None
    if type(row) is not dict:
        if type(utility_cost) is dict:
            required_utility = {"attempts_expected", "attempts_observed", "all_attempts_complete",
                                "known_usd", "billing_fully_known", "unresolved_usd_upper",
                                "unresolved_upper_bounds_known", "live_evidence_eligible"}
            if required_utility <= set(utility_cost):
                complete = utility_cost["all_attempts_complete"] is True
                billing = utility_cost["billing_fully_known"] is True
                for name in ("attempts_expected", "attempts_observed"):
                    if type(utility_cost[name]) is not int or utility_cost[name] < 0:
                        raise ValueError("invalid utility attempt count")
                _number(utility_cost["known_usd"], f"{arm}/known_usd")
                _number(utility_cost["unresolved_usd_upper"], f"{arm}/unresolved_usd_upper", nullable=True)
                if utility_cost["known_usd"] < 0 or (utility_cost["unresolved_usd_upper"] is not None
                                                       and utility_cost["unresolved_usd_upper"] < 0):
                    raise ValueError("negative utility accounting amount")
                if type(utility_cost["billing_fully_known"]) is not bool:
                    raise ValueError("invalid utility billing state")
                return partial | {
                    "all_attempt": "utility receipt summary; execution/authorship not authenticated",
                    "requests": utility_cost["attempts_observed"],
                    "known_usd": utility_cost["known_usd"],
                    "total_usd": utility_cost["known_usd"] if complete and billing else None,
                    "unresolved_usd_upper": utility_cost["unresolved_usd_upper"],
                    "billing_fully_known": billing, "usage_complete": None,
                    "pending_attempt_count": utility_cost.get("pending_liabilities"),
                }
        return partial | {"all_attempt": "NOT MEASURED: all-attempt accounting absent"}
    required = {"requests", "known_usd_decimal", "unresolved_usd_upper_decimal",
                "billing_fully_known", "total_usd_decimal", "usage_complete",
                "pending_attempt_ids", "live_evidence_eligible"}
    if not required <= set(row) or row["live_evidence_eligible"] is not False:
        return partial | {"all_attempt": "NOT MEASURED: accounting wire incomplete or ineligible"}
    if (type(row["requests"]) is not int or row["requests"] < 0
            or type(row["billing_fully_known"]) is not bool
            or type(row["usage_complete"]) is not bool
            or type(row["pending_attempt_ids"]) not in (list, tuple)):
        raise ValueError("invalid all-attempt accounting state")
    known = _usd_string(row["known_usd_decimal"], f"{arm}/known_usd")
    total = _usd_string(row["total_usd_decimal"], f"{arm}/total_usd")
    upper = _usd_string(row["unresolved_usd_upper_decimal"], f"{arm}/unresolved_upper")
    if row["billing_fully_known"] != (total is not None):
        raise ValueError("all-attempt total and billing completeness disagree")
    return partial | {
        "all_attempt": "reported; execution/authorship not authenticated",
        "requests": row["requests"], "known_usd": known,
        "total_usd": total,
        "unresolved_usd_upper": upper,
        "billing_fully_known": row["billing_fully_known"],
        "usage_complete": row["usage_complete"],
        "pending_attempt_count": len(row["pending_attempt_ids"]),
    }


def _utility_view(value: dict | None, label: str) -> dict:
    if type(value) is not dict:
        return {"status": "NOT MEASURED", "denominator": 0, "metrics": {}}
    raw_status = value.get("measurement_status")
    status = "RECORDED" if raw_status == "RECORDED" else "NOT MEASURED"
    metrics = {}
    for key in ("successful_explanations", "expected_explanations", "expected_denominator",
                "necessary_fact_recall", "limitation_recall", "support_rate_all_generated",
                "assessor_agreement", "withheld_explanation_rate", "invalid_or_withheld_rate",
                "median_paired_word_reduction", "word_pair_denominator", "enablement_criterion"):
        if key in value:
            item = value[key]
            if isinstance(item, (int, float)) and not isinstance(item, bool):
                _number(item, f"{label}/{key}")
            elif key == "enablement_criterion" and item not in ("MET", "NOT_MET", "INCONCLUSIVE"):
                raise ValueError("unknown utility criterion status")
            elif isinstance(item, str) and key != "enablement_criterion":
                raise ValueError("free-text utility metric not renderable")
            elif item is not None and key != "enablement_criterion" and not isinstance(item, (int, float)):
                raise ValueError("unsupported utility metric value")
            metrics[key] = item
    denominator = value.get("expected_explanations", value.get("expected_denominator", 0))
    if type(denominator) is not int or denominator < 0:
        denominator = 0
    return {"status": status, "denominator": denominator, "metrics": metrics}


def _batch_view(value: dict | None) -> dict | None:
    """Reduce private batch intake to ID-free coverage and one journal cost view."""
    if type(value) is not dict or value.get("batch") is not True:
        return None
    for key in ("eligible_raw_scenarios", "eligible_findings"):
        if type(value.get(key)) is not int or value[key] < 0:
            raise ValueError("invalid batch coverage count")
    failures = value.get("cases_missing_or_incomplete")
    unmatched = value.get("unmatched_global_attempt_ids")
    invocations = value.get("invocations")
    if (type(failures) is not list or type(unmatched) is not list
            or type(invocations) is not list):
        raise ValueError("batch incompleteness inventory required")
    accounting = value.get("cost_accounting")
    if type(accounting) is not dict or accounting.get("invocation_totals_added_to_global") is not False:
        raise ValueError("single global batch accounting boundary required")
    journal = accounting.get("global_journal")
    summary = journal.get("summary") if type(journal) is dict else None
    if type(summary) is not dict:
        raise ValueError("global journal summary missing")
    known = _usd_string(summary.get("known_usd"), "batch/known_usd")
    upper = _usd_string(summary.get("unresolved_usd_upper"), "batch/unresolved_upper")
    billing_known = summary.get("billing_known") is True
    pending = summary.get("pending_attempt_ids", [])
    if type(pending) not in (list, tuple):
        raise ValueError("invalid batch journal pending liabilities")
    complete = (not failures and not unmatched and not pending and billing_known
                and journal.get("snapshot_unavailable") is not True
                and summary.get("new_requests_blocked") is not True)
    return {
        "status": "RECORDED" if complete else "INCOMPLETE",
        "raw_scenarios": value["eligible_raw_scenarios"],
        "finding_rows": value["eligible_findings"],
        "invocations": len(invocations),
        "incomplete_items": len(failures) + len(unmatched) + len(pending),
        "journal_requests": summary.get("requests") if type(summary.get("requests")) is int else None,
        "known_usd": known,
        "unresolved_usd_upper": upper,
        "total_usd": known if complete and billing_known else None,
        "billing_fully_known": billing_known,
        "invocation_costs_added_to_journal": False,
        "live_evidence_eligible": False,
    }


def render_results(score_result: dict, *, l_utility: dict | None = None,
                   assessment_import: dict | None = None,
                   producer_accounting: dict | None = None) -> dict:
    """Return safe aggregate Markdown and JSON data; no case IDs or prose are rendered."""
    score = validate_score_result(score_result)
    accounting = producer_accounting
    p_utility = None
    if type(assessment_import) is dict:
        p_utility = assessment_import.get("p_utility")
        if accounting is None:
            accounting = assessment_import.get("per_arm_costs")
    batch = _batch_view(assessment_import)
    if accounting is None:
        accounting = {}
    summary = {}
    for arm in ARMS:
        raw = score["arms"][arm]
        status = "RECORDED" if raw["measurement_status"] == "RECORDED" else "NOT MEASURED"
        if arm == "D" and status == "RECORDED" and not score["deterministic_exact_gate"]:
            status = "FAIL"
        rules = raw["per_rule"]
        totals = {key: sum(rules[rule][key] for rule in RULES)
                  for key in ("total", "supported_decidable", "tp", "fp", "fn", "tn",
                              "abstentions", "missing", "unmapped", "ineligible", "certainty_errors")}
        summary[arm] = {
            "status": status, "rows": totals["total"], "failures": len(raw["failures"]),
            "counts": totals, "cost": _accounting_view(
                arm, raw, accounting,
                (l_utility or {}).get("cost") if arm == "L" and type(l_utility) is dict
                else (p_utility or {}).get("cost") if arm == "P" and type(p_utility) is dict
                else None),
            "per_rule": {rule: {
                "status": status,
                "denominator": rules[rule]["total"],
                "coverage_count": max(0, rules[rule]["total"] - rules[rule]["missing"]
                                      - max(rules[rule]["unmapped"], rules[rule]["ineligible"])),
                "coverage_rate": (max(0, rules[rule]["total"] - rules[rule]["missing"]
                                      - max(rules[rule]["unmapped"], rules[rule]["ineligible"]))
                                  / rules[rule]["total"] if rules[rule]["total"] else None),
                "supported_decidable": rules[rule]["supported_decidable"],
                "tp": rules[rule]["tp"], "fp": rules[rule]["fp"],
                "fn": rules[rule]["fn"], "tn": rules[rule]["tn"],
                "abstentions": rules[rule]["abstentions"],
                "unknown_gold": rules[rule]["gold_indeterminate"],
                "unsupported": rules[rule]["unsupported"],
                "missing": rules[rule]["missing"], "unmapped": rules[rule]["unmapped"],
                "ineligible": rules[rule]["ineligible"],
                "negative_or_inconclusive": rules[rule]["fp"] + rules[rule]["fn"]
                + rules[rule]["abstentions"] + rules[rule]["certainty_errors"],
                "precision": rules[rule]["precision"], "recall": rules[rule]["recall"],
                "f1": rules[rule]["f1"],
            } for rule in RULES},
        }
    failures_by_arm = {
        arm: {(failure["case_id"], failure["resource_id"], failure["rule_id"])
              for failure in score["arms"][arm]["failures"]}
        for arm in ARMS
    }
    failure_overlap = {
        f"{left}|{right}": len(failures_by_arm[left] & failures_by_arm[right])
        for left, right in combinations(ARMS, 2)
    }
    utility = {"L": _utility_view(l_utility, "L"), "P": _utility_view(p_utility, "P")}
    lines = ["# Evaluation results", "", f"Split: `{score['split']}`; denominator: {score['oracle_rows']} cases.",
             "", "Every arm is evaluated independently. `NOT MEASURED` means eligibility or required evidence was incomplete. `NA` means its metric denominator is zero.",
             "", "## Seven-arm summary", "", "| Arm | Status | Rows | Missing | Unmapped | Ineligible | Failures | Cost scope |",
             "|---|---|---:|---:|---:|---:|---:|---|"]
    for arm in ARMS:
        row = summary[arm]
        cost_label = row["cost"].get("all_attempt", "row subtotal only")
        lines.append(f"| {arm} | {row['status']} | {row['rows']} | {row['counts']['missing']} | {row['counts']['unmapped']} | {row['counts']['ineligible']} | {row['failures']} | {cost_label} |")
    d_gate = ("NOT MEASURED" if summary["D"]["status"] == "NOT MEASURED" else
              "RECORDED" if score["deterministic_exact_gate"] else "FAIL")
    lines += ["", f"D exact gate: **{d_gate}**. Authorship authentication and product acceptance: **false**.",
              "", "## Per-rule coverage and outcomes", "", "| Arm | Rule | Status | Cases | Covered | Coverage | Decidable | TP | FP | FN | TN | Abstain | Neg/abstain/errors | Unknown gold | Unsupported | Missing | Unmapped | Ineligible | Precision | Recall | F1 |",
              "|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for arm in ARMS:
        for rule in RULES:
            row = summary[arm]["per_rule"][rule]
            lines.append("| " + " | ".join((arm, rule, row["status"], str(row["denominator"]),
                str(row["coverage_count"]), _fmt(row["coverage_rate"]),
                str(row["supported_decidable"]), str(row["tp"]), str(row["fp"]), str(row["fn"]),
                str(row["tn"]), str(row["abstentions"]), str(row["negative_or_inconclusive"]),
                str(row["unknown_gold"]),
                str(row["unsupported"]), str(row["missing"]), str(row["unmapped"]),
                str(row["ineligible"]), _fmt(row["precision"]), _fmt(row["recall"]),
                _fmt(row["f1"]))) + " |")
    lines += ["", "## Cross-arm failure overlap", "", "Counts use internal case/resource/rule joins; identifiers remain private.",
              "", "| Arms | Shared failed findings |", "|---|---:|"]
    for pair, count in failure_overlap.items():
        lines.append(f"| {pair.replace('|', ' / ')} | {count} |")
    lines += ["", "## All-attempt cost", "", "Row subtotals are partial. Model-arm totals require all-attempt accounting; missing accounting is not zero.",
              "", "| Arm | All-attempt record | Requests | Known USD | Total USD | Unresolved upper USD | Billing complete | Usage complete | Pending | Row-known subtotal (partial) |",
              "|---|---|---:|---:|---:|---:|---|---|---:|---:|"]
    for arm in ARMS:
        cost = summary[arm]["cost"]
        lines.append(f"| {arm} | {cost.get('all_attempt', 'NOT MEASURED')} | {_fmt(cost.get('requests'))} | {_fmt(cost.get('known_usd'))} | {_fmt(cost.get('total_usd'))} | {_fmt(cost.get('unresolved_usd_upper'))} | {_fmt(cost.get('billing_fully_known'))} | {_fmt(cost.get('usage_complete'))} | {_fmt(cost.get('pending_attempt_count'))} | {_fmt(cost.get('row_known_usd_subtotal'))} |")
    if batch is not None:
        lines += ["", "## Assessment batch accounting", "",
                  "| Status | Distinct raw scenarios | Finding rows | Invocations | Incomplete items | Global requests | Known USD | Total USD | Unresolved upper USD | Billing complete | Invocation totals added |",
                  "|---|---:|---:|---:|---:|---:|---:|---:|---:|---|---|"]
        lines.append(f"| {batch['status']} | {batch['raw_scenarios']} | {batch['finding_rows']} | {batch['invocations']} | {batch['incomplete_items']} | {_fmt(batch['journal_requests'])} | {_fmt(batch['known_usd'])} | {_fmt(batch['total_usd'])} | {_fmt(batch['unresolved_usd_upper'])} | {_fmt(batch['billing_fully_known'])} | false |")
    for arm, title in (("L", "L utility"), ("P", "P assessment utility")):
        view = utility[arm]
        lines += ["", f"## {title}", "", f"Status: **{view['status']}**; denominator: {_fmt(view['denominator'])}."]
        if view["metrics"]:
            lines.append("")
            lines.append("| Metric | Value |")
            lines.append("|---|---|")
            for key, value in view["metrics"].items():
                lines.append(f"| {key} | {_fmt(value) if isinstance(value, (int, float)) or value is None else str(value)} |")
    lines += ["", "Failure details remain in the private source records and are counted above without case identifiers. Negative or inconclusive outcomes are not acceptance. Missing arms and zero-denominator metrics are not converted to passes.",
              ""]
    return {"schema_version": 1, "split": score["split"], "oracle_rows": score["oracle_rows"],
            "arms": summary, "failure_overlap": failure_overlap,
            "utility": utility, "deterministic_exact_gate": score["deterministic_exact_gate"],
            "assessment_batch": batch,
            "authorship_authenticated": False, "product_acceptance": False,
            "markdown": "\n".join(lines)}
