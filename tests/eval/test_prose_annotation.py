"""Synthetic bookkeeping regressions only; no real prose assessment or hidden gold.

This source was authored but not imported/executed during Dirty Mode. Toy labels
exercise wire validation, not semantic correctness or independent actor identity.
"""
import json

import pytest
from pydantic import ValidationError

from eval.model.annotation import (
    export_assessments, prepare_adjudication, prepare_sheet, render_worksheet, write_private,
)
from eval.model.explanation_artifacts import (
    AnnotationRow, DecisionReference, ExplanationArtifact, Rubric, SpanSpec,
    digest, make_inventory, text_digest, validate_inventory,
)

TOY_RUBRIC = "Synthetic bookkeeping instructions only; not an AWS semantic oracle."


def artifact(text="Alpha. Beta.", *, withheld=False):
    return ExplanationArtifact(
        artifact_id="a" * 32, case_id="b" * 32, finding_id="c" * 32, attempt_id="d" * 32,
        generator_actor_ids=("1" * 32,),
        decision=DecisionReference(rule_id="R2", outcome="introduced_risk", immutable_outcome_sha256="e" * 64),
        origin="mock", raw_input_sha256="a" * 64, projection_sha256="b" * 64,
        prompt_sha256="c" * 64, build_sha256="d" * 64, response_sha256=text_digest(text),
        prose=text, prose_sha256=text_digest(text), explanation_withheld=withheld,
        fact_ids=("6" * 32,), limitation_ids=("indeterminate",),
    )


def example():
    value = artifact()
    inventory = make_inventory(value, (
        SpanSpec(start=0, end=7, kind="claim"), SpanSpec(start=7, end=12, kind="claim", withheld=True),
    ), "2" * 32, curation_receipt_sha256="a" * 64)
    rubric = Rubric(rubric_id="7" * 32, rubric_text=TOY_RUBRIC, rubric_text_sha256=text_digest(TOY_RUBRIC), required_fact_ids=value.fact_ids,
                    required_limitation_ids=value.limitation_ids, independent_rubric_receipt_sha256="b" * 64)
    first = prepare_sheet(value, inventory, rubric, "3" * 32, "4" * 32)
    second = prepare_sheet(value, inventory, rubric, "4" * 32, "3" * 32)
    return value, inventory, rubric, first, second


def completed(sheet, *, label="supported", critical=False):
    rows = tuple(AnnotationRow(
        claim_id=row.claim_id, label=label, withheld=row.withheld, critical_false=critical,
        necessary_fact_ids=("6" * 32,) if label == "supported" else (),
        limitation_ids=("indeterminate",) if label == "supported" else (),
    ) for row in sheet.rows)
    return sheet.model_copy(update={"rows": rows, "review_receipt_sha256": "c" * 64})


@pytest.mark.parametrize("text", ["bad\x1b[31m", "bad\x00", "bad\u202e", "bad\x7f"])
def test_terminal_and_directional_controls_reject_artifact(text):
    with pytest.raises((ValidationError, ValueError)):
        artifact(text)


def test_html_prose_is_escaped_and_never_interpreted():
    value = artifact('<script>alert("toy")</script>')
    inventory = make_inventory(value, (SpanSpec(start=0, end=len(value.prose), kind="claim"),), "2" * 32)
    rubric = Rubric(rubric_id="7" * 32, rubric_text=TOY_RUBRIC, rubric_text_sha256=text_digest(TOY_RUBRIC), required_fact_ids=(), required_limitation_ids=())
    sheet = prepare_sheet(value, inventory, rubric, "3" * 32, "4" * 32)
    html = render_worksheet(value, inventory, rubric, sheet)
    assert "&lt;script&gt;" in html and "<script>" not in html
    assert "default-src 'none'" in html


def test_stable_inventory_covers_exact_text_and_rejects_tampering():
    value, inventory, *_ = example()
    validate_inventory(value, inventory)
    assert "".join(span.text for span in inventory.spans) == value.prose
    assert inventory.spans[0].span_id != inventory.spans[1].span_id
    for changed in (
        inventory.model_copy(update={"artifact_sha256": "0" * 64}),
        inventory.model_copy(update={"spans": inventory.spans[:1]}),
        inventory.model_copy(update={"spans": (inventory.spans[0].model_copy(update={"text": "Changed"}), inventory.spans[1])}),
    ):
        with pytest.raises(ValueError):
            validate_inventory(value, changed)
    with pytest.raises(ValidationError):
        ExplanationArtifact.model_validate_json(value.model_dump_json().replace(value.prose_sha256, "0" * 64))


def test_blank_preparation_is_not_unknown_or_automatic_support():
    value, inventory, rubric, first, second = example()
    assert all(row.label is None and row.critical_false is None for row in first.rows)
    result = export_assessments(value, inventory, rubric, first, second)
    assert result["generated"] == 2 and result["withheld_generated"] == 1
    assert result["metrics"] is None and result["bookkeeping_complete"] is False


@pytest.mark.parametrize("fault", ["missing", "duplicate", "pin", "foreign_fact", "foreign_limit", "withholding"])
def test_invalid_sheet_cannot_drop_claims_or_change_pins_catalogs(fault):
    # Parameters are toy source cases; no live claim inventory is loaded.
    value, inventory, rubric, first, second = example()
    first, second = completed(first), completed(second)
    if fault == "missing":
        second = second.model_copy(update={"rows": second.rows[:1]})
    elif fault == "duplicate":
        second = second.model_copy(update={"rows": (second.rows[0], second.rows[0])})
    elif fault == "pin":
        second = second.model_copy(update={"rubric_sha256": "0" * 64})
    elif fault == "foreign_fact":
        second = second.model_copy(update={"rows": (second.rows[0].model_copy(update={"necessary_fact_ids": ("9" * 32,)}), second.rows[1])})
    elif fault == "foreign_limit":
        second = second.model_copy(update={"rows": (second.rows[0].model_copy(update={"limitation_ids": ("coverage_gap",)}), second.rows[1])})
    else:
        second = second.model_copy(update={"rows": (second.rows[0], second.rows[1].model_copy(update={"withheld": False}))})
    with pytest.raises(ValueError):
        export_assessments(value, inventory, rubric, first, second)


@pytest.mark.parametrize("actor", ["1" * 32, "3" * 32])
def test_generator_and_same_assessor_collisions_reject(actor):
    value, inventory, rubric, *_ = example()
    with pytest.raises(ValueError):
        prepare_sheet(value, inventory, rubric, "3" * 32, actor)


def test_withheld_stays_in_all_generated_support_denominator_and_no_live_promotion():
    value, inventory, rubric, first, second = example()
    first, second = completed(first), completed(second)
    def retain_withheld_negative(sheet):
        rows = tuple(row if not row.withheld else AnnotationRow(
            claim_id=row.claim_id, label="unsupported", withheld=True, critical_false=False,
        ) for row in sheet.rows)
        return sheet.model_copy(update={"rows": rows})
    first, second = retain_withheld_negative(first), retain_withheld_negative(second)
    result = export_assessments(value, inventory, rubric, first, second)
    assert result["metrics"]["generated"] == 2
    assert result["metrics"]["counts"]["withheld"] == 1
    assert result["metrics"]["support_rate"] == 0.5
    assert len(result["claim_ids"]) == 2 and len(result["first"]) == 2
    assert result["bookkeeping_complete"] is True
    assert result["live_eligible"] is False and result["complete"] is False
    assert result["identity_authenticated"] is False and result["product_prose_enabled"] is False
    assert value.origin == "mock"


def test_disagreement_needs_third_actor_and_exact_original_sheet_hashes():
    value, inventory, rubric, first, second = example()
    first, second = completed(first), completed(second, label="contradicted", critical=True)
    unresolved = export_assessments(value, inventory, rubric, first, second)
    assert len(unresolved["unresolved_claim_ids"]) == 2 and not unresolved["bookkeeping_complete"]
    with pytest.raises(ValueError):
        prepare_adjudication(value, inventory, rubric, first, second, first.assessor_id)
    draft = prepare_adjudication(value, inventory, rubric, first, second, "5" * 32)
    judged = draft.model_copy(update={"rows": tuple(row.model_copy(update={"label": "contradicted", "critical_false": True})
                                                  for row in draft.rows), "review_receipt_sha256": "d" * 64})
    result = export_assessments(value, inventory, rubric, first, second, judged)
    assert result["unresolved_claim_ids"] == []
    assert result["metrics"]["counts"]["contradicted"] == 2
    assert len(result["critical_false_claim_ids"]) == 2
    assert result["first_sheet_sha256"] == digest(first)
    stale = judged.model_copy(update={"first_sheet_sha256": "0" * 64})
    with pytest.raises(ValueError):
        export_assessments(value, inventory, rubric, first, second, stale)


def test_critical_only_dispute_stays_incomplete_without_polluting_protocol_adjudication():
    value, inventory, rubric, first, second = example()
    first = completed(first, label="contradicted", critical=False)
    second = completed(second, label="contradicted", critical=True)
    result = export_assessments(value, inventory, rubric, first, second)
    assert result["metrics"]["complete"] is True  # Existing protocol is semantic-only.
    assert result["bookkeeping_complete"] is False and len(result["unresolved_claim_ids"]) == 2
    assert result["adjudicated"] == {}
    draft = prepare_adjudication(value, inventory, rubric, first, second, "5" * 32)
    judged = draft.model_copy(update={"rows": tuple(row.model_copy(update={"label": "contradicted", "critical_false": True})
                                                  for row in draft.rows), "review_receipt_sha256": "d" * 64})
    result = export_assessments(value, inventory, rubric, first, second, judged)
    assert result["bookkeeping_complete"] is True and len(result["critical_false_claim_ids"]) == 2
    assert result["adjudicated"] == {}


def test_empty_text_is_incomplete_and_global_withholding_cannot_be_dropped():
    value = artifact("")
    inventory = make_inventory(value, (), "2" * 32)
    rubric = Rubric(rubric_id="7" * 32, rubric_text=TOY_RUBRIC, rubric_text_sha256=text_digest(TOY_RUBRIC), required_fact_ids=(), required_limitation_ids=())
    first = prepare_sheet(value, inventory, rubric, "3" * 32, "4" * 32)
    second = prepare_sheet(value, inventory, rubric, "4" * 32, "3" * 32)
    result = export_assessments(value, inventory, rubric, first, second)
    assert result["metrics"]["support_rate"] is None and result["bookkeeping_complete"] is False
    value = artifact(withheld=True)
    with pytest.raises(ValueError):
        make_inventory(value, (SpanSpec(start=0, end=12, kind="claim", withheld=False),), "2" * 32)


def test_fresh_actor_output_refuses_existing_directory(tmp_path):
    occupied = tmp_path / "other-assessor"
    occupied.mkdir()
    sentinel = occupied / "owner.json"
    sentinel.write_text("original", encoding="utf-8")
    with pytest.raises(ValueError):
        write_private(occupied, "3" * 32, {"sheet.json": b"{}"})
    assert sentinel.read_text() == "original"
    fresh = tmp_path / "own-packet"
    write_private(fresh, "3" * 32, {"sheet.json": b"{}"})
    assert json.loads((fresh / "owner.json").read_text())["identity_authenticated"] is False
    assert json.loads((fresh / "packet-state.json").read_text())["state"] == "WRITTEN"
