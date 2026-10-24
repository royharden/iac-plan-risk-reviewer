"""Verified local evidence and deliberately narrower shareable report projections.

No input document is embedded. Exact addresses and JSON pointers make the private
projection sensitive even though all attribute values pass the safe-fact filter.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from hashlib import sha256
from html import escape
import json
import math
import os
from pathlib import Path
import re
from time import monotonic
from typing import Any
from uuid import uuid4

from iac_review.contracts import (
    PARSER_VERSION, POLICY_VERSION, EvidenceRef, PlanDocument, ReviewReport,
    RuleEvaluation, ValueState,
)
from iac_review.contracts.report_inventory import (
    BOUND_PAYLOADS, PRIVACY_TEXT, AbortedMarker, classify_bundle, validate_export_state,
)
from iac_review.evidence import resolve, verify_unchanged
from iac_review.ingest import InputError, MAX_BYTES, MAX_SECONDS
from iac_review.provenance import (
    DESCRIPTOR_FILE, ReportProvenance, descriptor_bytes, local_descriptor,
    private_binding, verify_descriptor,
)

REPORT_VERSION = "1.0.0"
_ACTIONS = {"no-op", "create", "read", "update", "delete"}
_TYPES = {
    "aws_security_group_rule", "aws_security_group",
    "aws_vpc_security_group_ingress_rule", "aws_db_instance", "aws_ebs_volume",
    "aws_rds_cluster", "aws_dynamodb_table", "aws_s3_bucket", "aws_efs_file_system",
    "aws_elasticache_replication_group", "aws_instance",
}
_FACT_FIELDS = {
    "type", "protocol", "from_port", "to_port", "cidr_blocks", "ipv6_cidr_blocks",
    "publicly_accessible", "storage_encrypted", "encrypted", "actions", "mode",
    "provider_name", "before", "after", "replace_paths", "prefix_list_ids",
    "source_security_group_id", "self",
}
_ENUMS = _ACTIONS | _TYPES | {
    "ingress", "egress", "tcp", "6", "-1", "udp", "17", "icmp", "1",
    "icmpv6", "58", "managed", "data", "registry.terraform.io/hashicorp/aws",
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
_LIMITS = {
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


def _id() -> str:
    return uuid4().hex


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2,
                       allow_nan=False) + "\n").encode("utf-8")


def _safe_value(state: ValueState) -> tuple[Any, str]:
    """Never recursively project arbitrary plan values, including unknown masks."""
    if state.sensitive:
        return None, "sensitive"
    if state.state != "known":
        return None, state.state
    value = state.value
    if type(value) is bool:
        return value, "known"
    if type(value) is int and abs(value) <= 2**53:
        return value, "known"
    if type(value) is float and math.isfinite(value):
        return value, "known"
    if isinstance(value, str) and value in _ENUMS | {"0.0.0.0/0", "::/0"}:
        return value, "known"
    if isinstance(value, (tuple, list)) and all(
        isinstance(item, str) and item in _ACTIONS for item in value
    ):
        return list(value), "known"
    # Container existence is sufficient for prior-existence evidence. Its contents
    # are never published, even in the explicitly sensitive private projection.
    if isinstance(value, (dict, list, tuple)):
        return None, "present_container"
    return None, "privacy_omitted"


def _field(ref: EvidenceRef) -> str:
    if ref.side == "actions":
        return "actions"
    tokens = [token.replace("~1", "/").replace("~0", "~")
              for token in ref.pointer.split("/")[1:]]
    # Only fixed schema field names may survive into an outbound projection.
    for token in reversed(tokens):
        if token in _FACT_FIELDS:
            return token
    return "source_fact"


def _safe_reason(value: str) -> str:
    # Reason strings originate in the installed rules, but unrecognized arbitrary
    # strings still never become provider/shareable text.
    return value if re.fullmatch(r"[a-z][a-z0-9_]{0,79}", value) else "rule_evaluation"


def build_report(
    plan: PlanDocument, evaluations: tuple[RuleEvaluation, ...], fail_on: int = 3,
) -> ReviewReport:
    """Resolve decision facts before exposing outcomes; uncertainty wins exit 2."""
    if type(fail_on) is not int or fail_on not in range(1, 5):
        raise ValueError("fail_on must be an integer from 1 through 4")
    started = monotonic()
    verify_unchanged(plan)
    resources = {resource.key: resource for resource in plan.resources}
    public_resources = {key: _id() for key in resources}
    case_id = _id()
    run_id = _id()
    limitations: set[str] = set()
    if plan.identity.complete is not True:
        limitations.add("incomplete_plan")
    if plan.identity.errored is not False:
        limitations.add("errored_or_unknown")
    if plan.coverage or any(not resource.action_supported for resource in plan.resources):
        limitations.add("unsupported_input")

    private_rows: list[dict[str, Any]] = []
    shared_rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    counts: Counter[str] = Counter()
    threshold_risk = False
    risk_present = False
    evidence_failures: list[dict[str, str]] = []
    for evaluation in evaluations:
        if monotonic() - started > MAX_SECONDS:
            raise InputError("review_time_limit")
        resource = resources.get(evaluation.resource_key)
        if resource is None:
            raise ValueError("evaluation references a foreign resource")
        row_key = (evaluation.resource_key, evaluation.rule_id)
        if row_key in seen:
            raise ValueError("duplicate resource/rule evaluation")
        seen.add(row_key)
        if evaluation.applicability == "unsupported_shape":
            limitations.add("unsupported_shape")
        if evaluation.coverage:
            limitations.add("coverage_gap")
        outcome = evaluation.outcome
        local_limits: set[str] = set()
        private_facts: list[dict[str, Any]] = []
        shared_facts: list[dict[str, Any]] = []
        decision_failed = False
        for role, refs in (("decision", evaluation.decision_refs),
                           ("supporting", evaluation.supporting_refs)):
            for ref in refs:
                if monotonic() - started > MAX_SECONDS:
                    raise InputError("review_time_limit")
                if ref.resource_key != resource.key or ref.resource_index != resource.index:
                    if role == "decision":
                        decision_failed = True
                        evidence_failures.append({
                            "evaluation_id": evaluation.evaluation_id,
                            "fact_id": ref.fact_id, "role": role, "status": "mismatch",
                        })
                    else:
                        local_limits.add("supporting_evidence_omitted")
                    continue
                resolved = resolve(plan, ref)
                marker_allowed = (
                    outcome == "indeterminate" and
                    resolved.status in {"unknown", "sensitive"}
                )
                valid = resolved.status == "resolved" or marker_allowed
                if not valid:
                    if role == "decision":
                        decision_failed = True
                        evidence_failures.append({
                            "evaluation_id": evaluation.evaluation_id,
                            "fact_id": ref.fact_id,
                            "role": role,
                            "status": resolved.status,
                        })
                    else:
                        local_limits.add("supporting_evidence_omitted")
                    continue
                value, state = _safe_value(resolved.value)
                if state == "privacy_omitted":
                    local_limits.add("privacy_value_omitted")
                fact_id = _id()
                fact = {"fact_id": fact_id, "field": _field(ref), "side": ref.side,
                        "role": role, "state": state, "value": value}
                shared_facts.append(fact)
                private_facts.append({**fact, "pointer": ref.pointer,
                                      "resolution": resolved.status})
        if evaluation.applicability == "supported" and outcome in {
            "introduced_risk", "unchanged_risk", "clear"
        } and not evaluation.decision_refs:
            decision_failed = True
        if decision_failed:
            outcome = "indeterminate"
            local_limits.add("decision_evidence_withheld")
            # Do not display a partial set as the verified support for the finding.
            private_facts = []
            shared_facts = []
        if outcome == "indeterminate":
            local_limits.add("indeterminate")
        limitations.update(local_limits)
        counts[outcome or evaluation.applicability] += 1
        if outcome in {"introduced_risk", "unchanged_risk"}:
            risk_present = True
            threshold_risk |= evaluation.severity >= fail_on
        explanation = _OUTCOME_TEXT[outcome] + " " + _RULE_TEXT[evaluation.rule_id]
        public_row = {
            "finding_id": _id(), "resource_id": public_resources[resource.key],
            "resource_type": resource.type if resource.type in _TYPES else "unsupported_resource",
            "rule_id": evaluation.rule_id, "rule_version": POLICY_VERSION,
            "severity": evaluation.severity, "applicability": evaluation.applicability,
            "outcome": outcome, "explanation": explanation,
            "facts": shared_facts, "limitation_ids": sorted(local_limits),
        }
        # The exact installed reason code stays private; the public explanation is
        # always generated from fixed template text and the effective outcome.
        private_row = {
            **public_row, "address": resource.address,
            "actions": list(resource.actions) if all(a in _ACTIONS for a in resource.actions)
                       else ["unsupported"],
            "reason_code": _safe_reason(evaluation.reason_code), "facts": private_facts,
        }
        private_rows.append(private_row)
        shared_rows.append(public_row)

    expected = {(resource.key, rule) for resource in plan.resources
                for rule in ("R1", "R2", "R3", "R4")}
    if seen != expected:
        limitations.add("missing_evaluation")
    inconclusive = bool(limitations - {"supporting_evidence_omitted", "privacy_value_omitted"})
    exit_code = 2 if inconclusive else 1 if threshold_risk else 0
    no_changes = not inconclusive and not risk_present and all(
        resource.actions == ("no-op",) for resource in plan.resources
    )
    status = "inconclusive" if inconclusive else "no_changes" if no_changes else "evaluated_scope"
    summary = {
        "status": status, "exit_code": exit_code, "risk_present": risk_present,
        "threshold_risk_present": threshold_risk, "fail_on": fail_on,
        "introduced_risks": counts["introduced_risk"],
        "unchanged_risks": counts["unchanged_risk"], "clear": counts["clear"],
        "indeterminate": counts["indeterminate"],
        "unsupported_shape": counts["unsupported_shape"],
        "not_applicable": counts["not_applicable"],
        "resource_count": len(plan.resources),
    }
    common = {
        "schema_version": REPORT_VERSION, "run_id": run_id, "case_id": case_id,
        "parser_version": PARSER_VERSION, "policy_version": POLICY_VERSION,
        "summary": summary, "limitations": [
            {"id": key, "text": _LIMITS[key]} for key in sorted(limitations)
        ],
        "scope": {
            "rules": ["R1", "R2", "R3", "R4"], "provider": "aws",
            "admin_ports": [22, 3389],
            "claim": "Supported declared predicates only; no global security or deployed-state conclusion.",
        },
        "measurements": {arm: "NOT MEASURED" for arm in ("D", "L", "P", "M", "C", "C-custom", "T")},
    }
    private = {
        **common, "projection": "private", "sensitive": True,
        "privacy_notice": "Contains exact addresses and pointers. Treat as sensitive. Marked values are masked.",
        "plan": {
            "sha256": plan.identity.sha256, "format_version": plan.identity.format_version,
            "terraform_version": plan.identity.terraform_version
            if plan.identity.terraform_version and re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", plan.identity.terraform_version)
            else None,
            "complete": plan.identity.complete, "applyable": plan.identity.applyable,
            "errored": plan.identity.errored,
        },
        "evaluations": private_rows, "evidence_failures": evidence_failures,
    }
    shareable = {
        **common, "projection": "shareable", "sensitive": False,
        "privacy_notice": "Opaque identities and safe facts only. Not source-resolvable without the separate private mapping.",
        "evaluations": shared_rows,
    }

    def provenance_budget() -> None:
        if monotonic() - started > MAX_SECONDS:
            raise InputError("review_time_limit")

    descriptor = local_descriptor(plan, run_id, case_id, fail_on, provenance_budget)
    private["provenance"] = private_binding(descriptor)
    verify_unchanged(plan)
    # Canonical report wire validation; a mismatch is a producer defect, not a report.
    report = ReviewReport.validated(private, shareable, exit_code)
    provenance_budget()
    return report


def _html(report: dict[str, Any]) -> bytes:
    """Render only escaped values; no scripts, external fonts, URLs or assets."""
    summary = report["summary"]
    cards: list[str] = []
    for row in report["evaluations"]:
        label = row.get("address", row["resource_id"])
        facts = "".join(
            "<tr>" + "".join(f"<td>{escape(str(fact.get(key, '')))}</td>"
            for key in ("side", "field", "state", "value", "pointer")) + "</tr>"
            for fact in row["facts"]
        )
        cards.append(
            f'<article class="{escape(row["outcome"] or row["applicability"])}">'
            f'<h2>{escape(row["rule_id"])} · {escape(str(label))}</h2>'
            f'<p class="outcome">{escape(row["outcome"] or row["applicability"])}</p>'
            f'<p>{escape(row["explanation"])}</p>'
            + (f'<p>Actions: {escape(" → ".join(row["actions"]))}</p>' if "actions" in row else "")
            + '<table><thead><tr><th>Side</th><th>Fact</th><th>State</th><th>Safe value</th><th>Private pointer</th></tr></thead>'
            + f'<tbody>{facts}</tbody></table>'
            + f'<p>Limitations: {escape(", ".join(row["limitation_ids"]) or "none for this row")}</p></article>'
        )
    limitations = "".join(f'<li>{escape(item["text"])}</li>' for item in report["limitations"])
    document = f'''<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Terraform declared change-risk review</title><style>
body{{font:16px system-ui,sans-serif;background:#101827;color:#e8eef8;margin:0;padding:32px;line-height:1.5}}
main{{max-width:1180px;margin:auto}}header,article{{background:#19263a;padding:24px;border-radius:12px;margin-bottom:20px}}
h1{{font-size:30px;margin:0 0 10px}}h2{{font-size:19px;overflow-wrap:anywhere}}.notice{{color:#e9c16b}}
.introduced_risk,.unchanged_risk{{border-left:5px solid #ef7c83}}.indeterminate,.unsupported_shape{{border-left:5px solid #e9c16b}}
table{{border-collapse:collapse;width:100%;font-size:13px}}td,th{{text-align:left;padding:8px;border-bottom:1px solid #354561;overflow-wrap:anywhere}}
.outcome{{font-weight:bold}}code{{overflow-wrap:anywhere}}footer{{color:#adbbd1}}
</style></head><body><main><header><h1>Declared change-risk review</h1>
<p class="notice">{escape(report["privacy_notice"])}</p>
<p>Status: <strong>{escape(summary["status"])}</strong> · Exit {summary["exit_code"]} · Risk present: {str(summary["risk_present"]).lower()}</p>
<p>Introduced {summary["introduced_risks"]} · Unchanged {summary["unchanged_risks"]} · Clear {summary["clear"]} · Indeterminate {summary["indeterminate"]}</p>
<p>{escape(report["scope"]["claim"])}</p><ul>{limitations}</ul></header>
{''.join(cards)}<footer>Policy {escape(POLICY_VERSION)} · Parser {escape(PARSER_VERSION)}.
R1 covers ports 22/3389 and standalone SG rules only. Static report; no apply or cloud interaction.
All benchmark arms remain NOT MEASURED in this construction edition.</footer></main></body></html>'''
    return document.encode("utf-8")


def write_report(report: ReviewReport, out: Path, *, deadline: float | None = None) -> None:
    """Stage a bounded bundle; publish only within the invocation's deadline.

    export-state.json remains ABORTED until every artifact is published. Failed
    writes roll back this invocation's files; pending files are never reports.
    Existing two-argument callers receive a fresh cooperative export budget.
    """
    deadline = monotonic() + MAX_SECONDS if deadline is None else deadline

    def check_deadline() -> None:
        if monotonic() > deadline:
            raise InputError("review_time_limit")

    out = Path(out).absolute()
    if any(parent.is_symlink() or (hasattr(parent, "is_junction") and parent.is_junction())
           for parent in (out, *out.parents)):
        raise ValueError("output path must not traverse symbolic links")
    if out.exists():
        if not out.is_dir() or any(out.iterdir()):
            raise ValueError("output directory must be new or empty")
    else:
        out.mkdir(parents=True, exist_ok=False)
    state_path = out / "export-state.json"
    aborted = _json_bytes({"state": "ABORTED", "reason": "export_not_finalized"})
    # Fail closed even on process termination before the exception handler runs.
    with state_path.open("xb") as stream:
        stream.write(aborted)
        stream.flush()
        os.fsync(stream.fileno())
    pending = out / ".pending"
    staged: list[Path] = []
    published: list[Path] = []
    try:
        check_deadline()
        pending.mkdir()
        # The facade dictionaries are mutable; revalidate exactly what is published.
        private, shareable = report.validate_wire()
        check_deadline()
        binding = private.get("provenance")
        if type(binding) is not dict or type(binding.get("descriptor")) is not dict:
            raise ValueError("typed private report provenance required")
        descriptor = ReportProvenance.model_validate_json(json.dumps(binding["descriptor"]))
        provenance_bytes = descriptor_bytes(descriptor)
        verify_descriptor(private, shareable, provenance_bytes,
                          private["plan"]["sha256"], private["run_id"])
        check_deadline()
        payloads: dict[str, bytes] = {}
        for name, projection, render in (
            ("private.json", private, _json_bytes),
            ("private.html", private, _html),
            ("shareable.json", shareable, _json_bytes),
            ("shareable.html", shareable, _html),
        ):
            check_deadline()
            payloads[name] = render(projection)
            # Indented ensure_ascii output can outgrow the validated compact wire;
            # never publish an artifact the bundle reader would refuse.
            if len(payloads[name]) > MAX_BYTES:
                raise ValueError("report_artifact_byte_limit")
            check_deadline()
        payloads[DESCRIPTOR_FILE] = provenance_bytes
        private_manifest = {
            "schema_version": "1.1.0", "run_id": private["run_id"],
            "created_at": datetime.now(timezone.utc).isoformat(),
            "plan_sha256": private["plan"]["sha256"],
            "parser_version": PARSER_VERSION, "policy_version": POLICY_VERSION,
            "artifacts": {name: sha256(data).hexdigest() for name, data in payloads.items()},
            "privacy": PRIVACY_TEXT,
        }
        manifest_bytes = _json_bytes(private_manifest)
        payloads["manifest.json"] = manifest_bytes
        payloads["manifest.sha256"] = (sha256(manifest_bytes).hexdigest() + "\n").encode("ascii")
        complete_state = _json_bytes({"state": "COMPLETE", "exit_code": report.exit_code})
        # Self-check against the canonical inventory before anything is staged:
        # the published bundle must classify as a bound COMPLETE bundle.
        if type(validate_export_state(aborted)) is not AbortedMarker:
            raise ValueError("report_inventory_invalid")
        inventory = classify_bundle(
            {*payloads, "export-state.json"}, state=complete_state, manifest=manifest_bytes,
            receipt=payloads["manifest.sha256"],
            artifact_hashes={name: sha256(payloads[name]).hexdigest() for name in BOUND_PAYLOADS})
        if inventory.kind != "bound" or inventory.exit_code != report.exit_code:
            raise ValueError("report_inventory_invalid")
        check_deadline()
        for name, data in payloads.items():
            check_deadline()
            destination = pending / name
            with destination.open("xb") as stream:
                staged.append(destination)
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        for source in staged:
            check_deadline()
            destination = out / source.name
            # Exclusive creation keeps rollback limited to files we own.
            with destination.open("xb") as stream:
                published.append(destination)
                stream.write(source.read_bytes())
                stream.flush()
                os.fsync(stream.fileno())
        for source in staged:
            source.unlink()
        pending.rmdir()
        final_state = out / ".export-state.pending"
        with final_state.open("xb") as stream:
            staged.append(final_state)
            stream.write(complete_state)
            stream.flush()
            os.fsync(stream.fileno())
        # No deadline rejection may occur after this publication boundary.
        check_deadline()
        os.replace(final_state, state_path)
    except BaseException:
        # Remove only exact paths created by this invocation. A filesystem that
        # refuses cleanup retains the fail-closed ABORTED marker for inspection.
        for path in (*published, *staged):
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
        try:
            pending.rmdir()
        except OSError:
            pass
        raise
