"""Canonical report wire (seam S2): contamination, masking, counts, identities,
private locators, strict JSON and API retention.

Regression SOURCE only; authored in Dirty Mode, not imported or executed yet.
Public synthetic plans only, never hidden oracle data.
"""
from copy import deepcopy
import json
from types import MappingProxyType

import pytest

from iac_review.contracts import report_wire as wire
from iac_review.contracts.report_wire import (
    LegacyPrivateReport, PrivateProjection, ShareableProjection, projection_dict,
    validate_legacy_private_report, validate_private_projection, validate_projection,
    validate_report_pair, validate_shareable_projection,
)
from iac_review.ingest import load_plan
from iac_review.report import build_report
from iac_review.rules import evaluate

ADDRESS = "aws_db_instance.wire_contract_canary"
INVALID = "report_projection_invalid"


@pytest.fixture
def pair(tmp_path):
    """Producer output for one RDS change that introduces R2 public accessibility."""
    def build(changes=None):
        source = tmp_path / "public-wire-contract.json"
        if changes is None:
            changes = [{"address": ADDRESS, "name": "demo", "mode": "managed",
                        "provider_name": "registry.terraform.io/hashicorp/aws",
                        "type": "aws_db_instance", "change": {
                            "actions": ["update"],
                            "before": {"publicly_accessible": False, "storage_encrypted": True},
                            "after": {"publicly_accessible": True, "storage_encrypted": True},
                            "after_sensitive": {}, "after_unknown": {}}}]
        source.write_text(json.dumps({
            "format_version": "1.2", "terraform_version": "1.9.0", "complete": True,
            "errored": False, "resource_changes": changes,
        }), encoding="utf-8")
        plan = load_plan(source)
        report = build_report(plan, evaluate(plan))
        return deepcopy(report.private), deepcopy(report.shareable), report.exit_code
    return build


def _rejected(call, *args, **kwargs):
    with pytest.raises(ValueError) as caught:
        call(*args, **kwargs)
    assert str(caught.value) == INVALID
    # Errors never echo report content.
    assert ADDRESS not in str(caught.value) and ADDRESS not in repr(caught.value)


def _risk_row(report):
    return next(r for r in report["evaluations"] if r["outcome"] == "introduced_risk")


# --- API retention ---------------------------------------------------------------

def test_frozen_public_api_names_are_retained():
    for name in ("validate_projection", "validate_private_projection", "validate_shareable_projection",
                 "validate_legacy_private_report", "projection_dict", "validate_report_pair",
                 "PrivateProjection", "ShareableProjection", "LegacyPrivateReport"):
        assert callable(getattr(wire, name)), name


def test_producer_pair_round_trips_through_every_entry_point(pair):
    private, shareable, exit_code = pair()
    a, b = validate_report_pair(private, shareable, exit_code=exit_code)
    assert type(a) is PrivateProjection and type(b) is ShareableProjection
    assert validate_private_projection(private) == projection_dict(a) == private
    assert validate_shareable_projection(shareable) == projection_dict(b) == shareable
    encoded = json.dumps(shareable)
    assert validate_shareable_projection(encoded) == validate_shareable_projection(encoded.encode("utf-8"))
    assert validate_shareable_projection(MappingProxyType(shareable)) == shareable
    assert type(validate_projection(private, projection="private")) is PrivateProjection


def test_unknown_projection_kind_and_input_type_are_rejected(pair):
    private, _, _ = pair()
    _rejected(validate_projection, private, projection="legacy_private")
    _rejected(validate_projection, private, projection="other")
    _rejected(validate_shareable_projection, [private])
    _rejected(validate_shareable_projection, 7)
    with pytest.raises(ValueError):
        projection_dict(private)  # a dictionary is not a canonical model


# --- contamination ---------------------------------------------------------------

@pytest.mark.parametrize("mutate", [
    lambda s, p: s["evaluations"][0].__setitem__("address", ADDRESS),
    lambda s, p: s["evaluations"][0].__setitem__("reason_code", "rds_public"),
    lambda s, p: s["evaluations"][0].__setitem__("actions", ["update"]),
    lambda s, p: _risk_row(s)["facts"][0].__setitem__("pointer", _risk_row(p)["facts"][0]["pointer"]),
    lambda s, p: _risk_row(s)["facts"][0].__setitem__("resolution", "resolved"),
    lambda s, p: s.__setitem__("plan", p["plan"]),
    lambda s, p: s.__setitem__("provenance", p["provenance"]),
    lambda s, p: s.__setitem__("evidence_failures", []),
    lambda s, p: s.__setitem__("sensitive", True),
    lambda s, p: _risk_row(s)["facts"][0].update(state="known", value=ADDRESS),
])
def test_private_fields_never_validate_as_shareable(pair, mutate):
    private, shareable, _ = pair()
    mutate(shareable, private)
    _rejected(validate_shareable_projection, shareable)


def test_shareable_never_contains_private_locators(pair):
    private, shareable, _ = pair()
    text = json.dumps(validate_shareable_projection(shareable))
    assert ADDRESS not in text and "/resource_changes/" not in text and private["plan"]["sha256"] not in text


def test_private_report_cannot_masquerade_as_shareable_or_vice_versa(pair):
    private, shareable, exit_code = pair()
    _rejected(validate_shareable_projection, private)
    _rejected(validate_private_projection, shareable)
    _rejected(validate_report_pair, shareable, private, exit_code=exit_code)


# --- masking -----------------------------------------------------------------------

def test_mask_states_never_carry_values(pair):
    _, shareable, _ = pair()
    fact = _risk_row(shareable)["facts"][0]
    fact.update(state="sensitive", value=True)
    _rejected(validate_shareable_projection, shareable)


def test_unknown_or_sensitive_marker_only_supports_indeterminate(pair):
    _, shareable, _ = pair()
    _risk_row(shareable)["facts"][0].update(state="unknown", value=None)
    _rejected(validate_shareable_projection, shareable)


def test_private_resolution_matches_mask_state(pair):
    # A null (resolved) mask claiming an unknown resolution exercises the masked
    # state->resolution mapping, not the known-fact Literal["resolved"].
    private, _, _ = pair()
    _risk_row(private)["facts"][0].update(state="null", value=None, resolution="unknown")
    _rejected(validate_private_projection, private)


def test_large_cidr_rows_from_the_producer_validate(pair):
    # Bounds follow producer output: >256 facts in one R1 row must not be refused.
    # ipv6_cidr_blocks must be present so R1 is decidable and reads both sides.
    cidrs = [f"10.{i // 256}.{i % 256}.0/24" for i in range(200)]
    rule = {"type": "ingress", "protocol": "tcp", "from_port": 22, "to_port": 22,
            "security_group_id": "sg-synthetic", "ipv6_cidr_blocks": []}
    private, shareable, exit_code = pair(changes=[{
        "address": "aws_security_group_rule.wide", "name": "wide", "mode": "managed",
        "provider_name": "registry.terraform.io/hashicorp/aws", "type": "aws_security_group_rule",
        "change": {"actions": ["update"], "before": {**rule, "cidr_blocks": cidrs},
                   "after": {**rule, "cidr_blocks": [*cidrs, "0.0.0.0/0"]},
                   "after_sensitive": {}, "after_unknown": {}}}])
    validate_report_pair(private, shareable, exit_code=exit_code)
    r1 = next(r for r in private["evaluations"] if r["rule_id"] == "R1")
    assert r1["outcome"] == "introduced_risk"
    assert len(r1["facts"]) > 256  # the old prototype cap
    shared_facts = next(r for r in shareable["evaluations"] if r["rule_id"] == "R1")["facts"]
    assert len(shared_facts) == len(r1["facts"])
    assert r1["facts"] == [
        {**f, "pointer": g["pointer"], "resolution": g["resolution"]} for f, g in zip(shared_facts, r1["facts"])
    ]


def test_projection_dict_normalizes_unserializable_models():
    broken = ShareableProjection.model_construct(projection="shareable", summary=object())
    _rejected(projection_dict, broken)


def test_privacy_omitted_fact_requires_its_limitation(pair):
    _, shareable, _ = pair()
    row = _risk_row(shareable)
    row["facts"][0].update(state="privacy_omitted", value=None)
    assert "privacy_value_omitted" not in row["limitation_ids"]
    _rejected(validate_shareable_projection, shareable)


@pytest.mark.parametrize("value", [0, 1, 0.0, "false"])
def test_boolean_flags_never_accept_numbers_or_strings(pair, value):
    # bool vs number: a Boolean report flag never accepts a number, and vice versa.
    _, shareable, _ = pair()
    shareable["summary"]["risk_present"] = value
    _rejected(validate_shareable_projection, shareable)


def test_summary_counts_reject_bool_numbers(pair):
    _, shareable, _ = pair()
    shareable["summary"]["fail_on"] = True
    _rejected(validate_shareable_projection, shareable)


# --- counts, status, exit ---------------------------------------------------------

@pytest.mark.parametrize("mutate", [
    lambda s: s["summary"].__setitem__("introduced_risks", s["summary"]["introduced_risks"] + 1),
    lambda s: s["summary"].__setitem__("resource_count", s["summary"]["resource_count"] + 1),
    lambda s: s["summary"].__setitem__("exit_code", (s["summary"]["exit_code"] + 1) % 3),
    lambda s: s["summary"].__setitem__("status", "no_changes"),
    lambda s: s["summary"].__setitem__("risk_present", not s["summary"]["risk_present"]),
    lambda s: s["evaluations"].pop(),                       # missing evaluation without limitation
    lambda s: s["summary"].pop("clear"),                    # missing truth is never filled
    lambda s: _risk_row(s).__setitem__("severity", 1),      # severity is fixed per rule
    lambda s: _risk_row(s).__setitem__("outcome", "clear"),  # explanation/count drift
    lambda s: _risk_row(s)["limitation_ids"].append("missing_evaluation"),  # not a row limitation
])
def test_count_status_and_exit_invariants(pair, mutate):
    _, shareable, _ = pair()
    mutate(shareable)
    _rejected(validate_shareable_projection, shareable)


def test_pair_exit_code_must_match_both_projections(pair):
    private, shareable, exit_code = pair()
    _rejected(validate_report_pair, private, shareable, exit_code=(exit_code + 1) % 3)
    _rejected(validate_report_pair, private, shareable, exit_code=bool(exit_code))


def test_zero_resource_plan_is_no_changes_exit_zero(pair):
    private, shareable, exit_code = pair(changes=[])
    assert exit_code == 0 and shareable["summary"]["status"] == "no_changes"
    validate_report_pair(private, shareable, exit_code=0)


def test_private_plan_flags_bind_plan_limitations(pair):
    private, _, _ = pair()
    private["plan"]["complete"] = None
    _rejected(validate_private_projection, private)


# --- identities ---------------------------------------------------------------------

@pytest.mark.parametrize("mutate", [
    lambda s: s["evaluations"][1].__setitem__("finding_id", s["evaluations"][0]["finding_id"]),
    lambda s: s.__setitem__("case_id", s["run_id"]),
    lambda s: _risk_row(s)["facts"][0].__setitem__("fact_id", _risk_row(s)["resource_id"]),
    lambda s: s["evaluations"][0].__setitem__("finding_id", "NOT-HEX"),
    lambda s: s["evaluations"][0].__setitem__("resource_type", "aws_s3_bucket"),
])
def test_identity_duplication_and_role_reuse_rejected(pair, mutate):
    _, shareable, _ = pair()
    mutate(shareable)
    _rejected(validate_shareable_projection, shareable)


def test_pair_rows_must_join_exactly(pair):
    private, shareable, exit_code = pair()
    shareable["evaluations"].reverse()
    _rejected(validate_report_pair, private, shareable, exit_code=exit_code)


# --- private locators ---------------------------------------------------------------

@pytest.mark.parametrize("pointer", [
    "/resource_changes/0/change/after/publicly~2accessible",   # invalid escape
    "/resource_changes/1/change/after/publicly_accessible",    # other resource index
    "/resource_changes/0/change/before/publicly_accessible",   # side mismatch
    "/resource_changes/0/change/after/storage_encrypted",      # field mismatch
    "/resource_changes/00/change/after/publicly_accessible",   # noncanonical index
    "resource_changes/0/change/after/publicly_accessible",     # not absolute
])
def test_private_locator_must_match_row_resource_side_and_field(pair, pointer):
    private, _, _ = pair()
    fact = next(f for f in _risk_row(private)["facts"] if f["side"] == "after")
    fact["pointer"] = pointer
    _rejected(validate_private_projection, private)


def test_private_rows_of_one_resource_share_address_and_actions(pair):
    private, _, _ = pair()
    private["evaluations"][0]["address"] = ADDRESS + "_other"
    _rejected(validate_private_projection, private)


# --- strict JSON ----------------------------------------------------------------------

def test_duplicate_json_keys_rejected(pair):
    _, shareable, _ = pair()
    text = json.dumps(shareable)
    _rejected(validate_shareable_projection, text[:-1] + ',"sensitive":false}')


@pytest.mark.parametrize("raw", [
    b'{"schema_version":NaN}', b'{"a":Infinity}', b"\xff\xfe{}", b'"string"', b"[]",
    '{"x":1}'.encode("utf-16"), b'{"a":' + b"[" * 70 + b"]" * 70 + b"}",
])
def test_malformed_json_rejected(raw):
    _rejected(validate_shareable_projection, raw)


def test_non_string_mapping_keys_are_not_coerced(pair):
    _, shareable, _ = pair()
    shareable["summary"][1] = 1
    _rejected(validate_shareable_projection, shareable)


def test_byte_limit(monkeypatch, pair):
    _, shareable, _ = pair()
    monkeypatch.setattr(wire, "MAX_REPORT_BYTES", 16)
    _rejected(validate_shareable_projection, shareable)


# --- legacy private report ----------------------------------------------------------

def test_legacy_private_report_is_separate_and_never_promoted(pair):
    private, shareable, exit_code = pair()
    legacy = {k: v for k, v in private.items() if k != "provenance"}
    assert validate_legacy_private_report(legacy) == legacy
    assert type(wire._validate(legacy, "legacy_private")) is LegacyPrivateReport
    _rejected(validate_private_projection, legacy)
    _rejected(validate_report_pair, legacy, shareable, exit_code=exit_code)
    # A current bound report is not accepted as legacy either.
    _rejected(validate_legacy_private_report, private)
