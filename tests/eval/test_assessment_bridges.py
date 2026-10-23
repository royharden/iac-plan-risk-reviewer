"""Public synthetic bookkeeping/correspondence SOURCE, not hidden gold or labels.

Authored but not imported/executed during Dirty Mode. Toy prose annotations only
exercise shape/denominator gates; they assert no actual semantic assessment truth.
"""
from hashlib import sha256

import pytest

from eval.model.annotation import prepare_sheet, render_worksheet
from eval.model.assessment_bridge import CaseApprovalReference, bridge_assessment
from eval.model.explanation_artifacts import (
    AnnotationRow, DecisionReference, ExplanationArtifact, Rubric, SpanSpec, digest,
    make_inventory, text_digest,
)
from eval.model.review_catalogue import build_catalogue, render_catalogue, validate_catalogue
from eval.runner.fact_mapping import ExpectedLocation, locations_digest, map_facts
from eval.runner.custody import metadata_digest
from eval.runner.utility import ExplanationCase, MeasurementPin
from iac_review.explain import build_capsule
from iac_review.ingest import load_plan
from iac_review.report import build_report, write_report
from iac_review.rules import evaluate


@pytest.fixture
def source_case(core_change, core_plan_file, tmp_path):
    def build(*, masked=False):
        entry = core_change(
            address='aws_db_instance.synthetic["PRIVATE_ADDRESS_CANARY"]',
            before={"publicly_accessible": False, "storage_encrypted": True},
            after={"publicly_accessible": True, "storage_encrypted": True, "tags": {"x": "PRIVATE_TAG_CANARY"}},
            change_fields={"before_sensitive": {"publicly_accessible": masked}},
        )
        path = core_plan_file([entry])
        plan = load_plan(path)
        report = build_report(plan, evaluate(plan))
        row = next(row for row in report.shareable["evaluations"] if row["rule_id"] == "R2")
        capsule = build_capsule(report.shareable, row["finding_id"])
        projection = capsule.model_dump_json()
        prose = "Alpha. Beta."
        artifact = ExplanationArtifact(
            artifact_id="a" * 32, case_id="b" * 32, finding_id=capsule.finding_id, attempt_id="c" * 32,
            generator_actor_ids=("1" * 32,), decision=DecisionReference(
                rule_id="R2", outcome=capsule.outcome, immutable_outcome_sha256="d" * 64),
            origin="mock", raw_input_sha256=plan.identity.sha256,
            projection_sha256=text_digest(projection), prompt_sha256="e" * 64, build_sha256="f" * 64,
            response_sha256=text_digest(prose), prose=prose, prose_sha256=text_digest(prose),
            fact_ids=tuple(fact.fact_id for fact in capsule.facts), limitation_ids=capsule.required_limitation_ids,
        )
        bundle = tmp_path / ("masked-bundle" if masked else "known-bundle")
        write_report(report, bundle)
        locations = (
            ExpectedLocation(expected_fact_id="expected-before", resource_index=0, side="before", tokens=("publicly_accessible",)),
            ExpectedLocation(expected_fact_id="expected-after", resource_index=0, side="after", tokens=("publicly_accessible",)),
        )
        private_pin = sha256((bundle / "private.json").read_bytes()).hexdigest()
        return artifact, capsule, projection, bundle, path, locations, private_pin
    return build


def correspondence(case, locations=None):
    artifact, _, _, bundle, source, original, private_pin = case
    locations = original if locations is None else locations
    return map_facts(artifact, "expected-resource", locations, bundle=bundle, original_plan=source,
                     expected_locations_sha256=locations_digest(locations), private_report_sha256=private_pin,
                     catalogue=build_catalogue(artifact, case[2]))


def workflow(case, *, critical_dispute=False, rubric_text=None):
    artifact, capsule, projection, *_ = case
    public = tuple(fact.fact_id for fact in capsule.facts if fact.field == "publicly_accessible")
    inventory = make_inventory(artifact, (SpanSpec(start=0, end=7, kind="claim"),
                                         SpanSpec(start=7, end=12, kind="claim", withheld=True)),
                               "2" * 32, curation_receipt_sha256="a" * 64)
    rubric_text = rubric_text if rubric_text is not None else "Toy bookkeeping rubric only, not an AWS semantic oracle."
    rubric = Rubric(rubric_id="3" * 32, rubric_text=rubric_text, rubric_text_sha256=text_digest(rubric_text),
                    required_fact_ids=public, required_limitation_ids=(), independent_rubric_receipt_sha256="b" * 64)
    sheets = []
    for actor, other, critical in (("4" * 32, "5" * 32, False), ("5" * 32, "4" * 32, critical_dispute)):
        draft = prepare_sheet(artifact, inventory, rubric, actor, other)
        rows = tuple(AnnotationRow(claim_id=row.claim_id, withheld=row.withheld,
                                   label="contradicted" if critical_dispute else "supported",
                                   critical_false=critical, necessary_fact_ids=public) for row in draft.rows)
        sheets.append(draft.model_copy(update={"rows": rows, "review_receipt_sha256": "c" * 64}))
    expected = ExplanationCase(
        case_id=artifact.case_id, resource_id="expected-resource", rule_id="R2", input_sha256=artifact.raw_input_sha256,
        action="update", knowledge="known", required_fact_ids=("expected-before", "expected-after"),
        allowed_fact_ids=("expected-before", "expected-after"), required_limitation_ids=(), allowed_limitation_ids=(),
    )
    return inventory, rubric, sheets, expected, build_catalogue(artifact, projection)


def test_catalogue_exposes_only_safe_facts_not_private_locations_or_expected_ids(source_case):
    case = source_case()
    artifact, _, projection, *_ = case
    catalogue = build_catalogue(artifact, projection)
    html = render_catalogue(artifact, catalogue)
    wire = catalogue.model_dump_json()
    for canary in ("PRIVATE_ADDRESS_CANARY", "PRIVATE_TAG_CANARY", "resource_changes", "expected-before"):
        assert canary not in wire + html
    assert "publicly_accessible" in html and "before" in html and "after" in html
    assert {fact.fact_id for fact in catalogue.facts} == set(artifact.fact_ids)
    inventory, rubric, sheets, *_ = workflow(case)
    sheet = render_worksheet(artifact, inventory, rubric, sheets[0], review_catalogue=catalogue)
    assert "Safe fact reference" in sheet and "publicly_accessible" in sheet


def test_catalogue_binds_exact_capsule_bytes_and_rejects_unsafe_or_changed_values(source_case):
    artifact, capsule, projection, *_ = source_case()
    with pytest.raises(ValueError):
        build_catalogue(artifact, projection + " ")
    catalogue = build_catalogue(artifact, projection)
    with pytest.raises(ValueError):
        validate_catalogue(artifact, catalogue.model_copy(update={"prose_sha256": "0" * 64}))
    bad_fact = capsule.facts[0].model_copy(update={"value": "<script>PRIVATE_ADDRESS_CANARY</script>"})
    bad_capsule = capsule.model_copy(update={"facts": (bad_fact, *capsule.facts[1:])})
    bad_json = bad_capsule.model_dump_json()
    with pytest.raises(ValueError):
        build_catalogue(artifact.model_copy(update={"projection_sha256": text_digest(bad_json)}), bad_json)


def test_private_locations_map_to_run_ids_without_deriving_expected_labels(source_case):
    case = source_case()
    result = correspondence(case)
    assert len(result.rows) == 2 and all(row.status == "mapped" for row in result.rows)
    assert {row.report_fact_id for row in result.rows} <= set(case[0].fact_ids)
    serialized = result.model_dump_json()
    assert "PRIVATE_ADDRESS_CANARY" not in serialized and "resource_changes" not in serialized
    assert result.identity_authenticated is False


def test_masked_and_duplicate_correspondence_remain_denominator_loss(source_case):
    masked = correspondence(source_case(masked=True))
    assert len(masked.rows) == 2 and masked.rows[0].status == "masked"
    assert masked.rows[0].report_fact_id is None
    case = source_case()
    first, second = case[5]
    duplicate = (first, second.model_copy(update={"side": "before"}))
    result = correspondence(case, duplicate)
    assert len(result.rows) == 2
    assert all(row.status == "ambiguous" and row.report_fact_id is None for row in result.rows)


def test_location_denominator_and_private_report_pins_cannot_change_silently(source_case):
    artifact, _, projection, bundle, source, locations, private_pin = source_case()
    with pytest.raises(ValueError):
        map_facts(artifact, "expected-resource", locations[:1], bundle=bundle, original_plan=source,
                  expected_locations_sha256=locations_digest(locations), private_report_sha256=private_pin,
                  catalogue=build_catalogue(artifact, projection))
    with pytest.raises(ValueError):
        map_facts(artifact, "expected-resource", locations, bundle=bundle, original_plan=source,
                  expected_locations_sha256=locations_digest(locations), private_report_sha256="0" * 64,
                  catalogue=build_catalogue(artifact, projection))


def test_safe_but_wrong_catalogue_value_is_not_source_correspondence(source_case):
    artifact, capsule, _, bundle, source, locations, private_pin = source_case()
    changed = tuple(fact.model_copy(update={"value": True})
                    if fact.field == "publicly_accessible" and fact.side == "before" else fact
                    for fact in capsule.facts)
    projection = capsule.model_copy(update={"facts": changed}).model_dump_json()
    artifact = artifact.model_copy(update={"projection_sha256": text_digest(projection)})
    catalogue = build_catalogue(artifact, projection)
    mapping = map_facts(artifact, "expected-resource", locations, bundle=bundle, original_plan=source,
                        expected_locations_sha256=locations_digest(locations), private_report_sha256=private_pin,
                        catalogue=catalogue)
    assert mapping.rows[0].status == "unresolved" and mapping.rows[0].report_fact_id is None
    assert mapping.rows[1].status == "mapped"


def test_bridge_preserves_mock_claims_missing_counts_attempts_and_denominators(source_case):
    case = source_case()
    inventory, rubric, sheets, expected, catalogue = workflow(case)
    mapping = correspondence(case)
    result = bridge_assessment(case[0], inventory, rubric, *sheets, catalogue=catalogue,
                               mapping=mapping, expected_mapping_sha256=digest(mapping), expected_case=expected)
    assert result.workflow_bookkeeping_complete is True and result.bookkeeping_complete is False
    assert len(result.claim_ids) == 2 and len(result.first) == 2
    assert sum(row.withheld for row in result.first) == 1
    assert result.generated_words is None and result.baseline_words is None and result.attempts == ()
    assert result.observation is None and result.live_eligible is False and result.complete is False
    assert "mock_or_unverified_origin" in result.missing_or_incomplete
    assert "word_counts_or_receipt_missing" in result.missing_or_incomplete
    assert result.unmapped_expected_fact_ids == ()


def test_bridge_gates_outer_critical_dispute_not_nested_semantic_metrics(source_case):
    case = source_case()
    inventory, rubric, sheets, expected, catalogue = workflow(case, critical_dispute=True)
    mapping = correspondence(case)
    result = bridge_assessment(case[0], inventory, rubric, *sheets, catalogue=catalogue,
                               mapping=mapping, expected_mapping_sha256=digest(mapping), expected_case=expected)
    assert "outer_workflow_incomplete" in result.missing_or_incomplete
    assert len(result.unresolved_claim_ids) == 2 and result.observation is None
    assert result.first_sheet == sheets[0] and result.second_sheet == sheets[1]


def test_bridge_never_drops_independent_expected_facts_when_correspondence_is_masked(source_case):
    case = source_case(masked=True)
    inventory, rubric, sheets, expected, catalogue = workflow(case)
    mapping = correspondence(case)
    result = bridge_assessment(case[0], inventory, rubric, *sheets, catalogue=catalogue,
                               mapping=mapping, expected_mapping_sha256=digest(mapping), expected_case=expected)
    assert result.expected_fact_ids == ("expected-before", "expected-after")
    assert result.unmapped_expected_fact_ids == ("expected-before",)
    assert "expected_fact_correspondence_loss" in result.missing_or_incomplete
    assert result.observation is None and len(result.claim_ids) == 2


def global_pin(artifact, *, prompt_sha256="1" * 64, rubric_sha256="2" * 64):
    return MeasurementPin(
        edition_id="synthetic-wire-cases", build_sha256=artifact.build_sha256, corpus_sha256="3" * 64,
        explanation_inventory_sha256="4" * 64, prompt_sha256=prompt_sha256, rubric_sha256=rubric_sha256,
        model_version="mock", price_identity="mock", attempt_ids=(), all_attempts_attested=False,
    )


def approved_reference(artifact, rubric, expected, pin, reference="5" * 64):
    # Synthetic declared reference only; never an authenticated actual approval.
    return CaseApprovalReference(
        reference_sha256=reference, case_id=artifact.case_id, case_sha256=metadata_digest(expected),
        artifact_sha256=digest(artifact), global_pin_sha256=metadata_digest(pin),
        rubric_sha256=digest(rubric), prompt_sha256=artifact.prompt_sha256,
    )


def test_24_distinct_case_rubrics_and_prompts_preserve_one_global_pin_and_no_attempt_repin(source_case):
    # 24 wire examples share a public synthetic source deliberately. They are NOT
    # 24 independent semantic/held-out cases and cannot meet an evaluation floor.
    original = source_case()
    pin = global_pin(original[0])
    frozen = pin.model_dump_json()
    global_sha = metadata_digest(pin)
    rubric_hashes, prompt_hashes = set(), set()
    for index in range(24):
        artifact = original[0].model_copy(update={
            "case_id": f"{index + 256:032x}", "prompt_sha256": text_digest(f"Synthetic case prompt {index}"),
        })
        case = (artifact, *original[1:])
        inventory, rubric, sheets, expected, catalogue = workflow(case, rubric_text=f"Synthetic case rubric {index}; bookkeeping only.")
        mapping = correspondence(case)
        approval = approved_reference(artifact, rubric, expected, pin, f"{index + 1:064x}")
        receipt = bridge_assessment(
            artifact, inventory, rubric, *sheets, catalogue=catalogue, mapping=mapping,
            expected_mapping_sha256=digest(mapping), expected_case=expected, pin=pin,
            expected_pin_sha256=global_sha, case_rubric_sha256=digest(rubric),
            case_prompt_sha256=artifact.prompt_sha256, case_approval_ref=approval,
            expected_case_approval_ref_sha256=approval.reference_sha256,
        )
        assert receipt.content_pin_mode == "case"
        assert receipt.measurement_pin.model_dump_json() == frozen
        assert receipt.attempts == () and receipt.observation is None and receipt.live_eligible is False
        assert pin.model_dump_json() == frozen and metadata_digest(pin) == global_sha
        rubric_hashes.add(digest(rubric))
        prompt_hashes.add(artifact.prompt_sha256)
    assert len(rubric_hashes) == len(prompt_hashes) == 24


@pytest.mark.parametrize("fault", ["missing_ref", "missing_prompt", "missing_external_pin", "forged_reference", "foreign_case", "foreign_artifact", "foreign_global", "wrong_content"])
def test_missing_or_forged_case_override_reference_is_incomplete(source_case, fault):
    case = source_case()
    inventory, rubric, sheets, expected, catalogue = workflow(case)
    artifact = case[0]
    mapping = correspondence(case)
    pin = global_pin(artifact)
    approval = approved_reference(artifact, rubric, expected, pin)
    options = dict(case_rubric_sha256=digest(rubric), case_prompt_sha256=artifact.prompt_sha256,
                   case_approval_ref=approval, expected_case_approval_ref_sha256=approval.reference_sha256)
    if fault == "missing_ref":
        options["case_approval_ref"] = None
    elif fault == "missing_prompt":
        options["case_prompt_sha256"] = None
    elif fault == "missing_external_pin":
        options["expected_case_approval_ref_sha256"] = None
    elif fault == "wrong_content":
        options["case_rubric_sha256"] = "0" * 64
    else:
        key = {"forged_reference": "reference_sha256", "foreign_case": "case_sha256",
               "foreign_artifact": "artifact_sha256", "foreign_global": "global_pin_sha256"}[fault]
        options["case_approval_ref"] = approval.model_copy(update={key: "0" * 64})
    receipt = bridge_assessment(
        artifact, inventory, rubric, *sheets, catalogue=catalogue, mapping=mapping,
        expected_mapping_sha256=digest(mapping), expected_case=expected, pin=pin,
        expected_pin_sha256=metadata_digest(pin), **options,
    )
    assert receipt.content_pin_mode == "incomplete" and receipt.observation is None
    assert receipt.case_approval_ref is None and receipt.live_eligible is False
    assert any(reason.startswith("case_content_approval_") for reason in receipt.missing_or_incomplete)


def test_original_global_content_pin_semantics_remain_the_default(source_case):
    case = source_case()
    artifact = case[0]
    inventory, rubric, sheets, expected, catalogue = workflow(case)
    mapping = correspondence(case)
    pin = global_pin(artifact, prompt_sha256=artifact.prompt_sha256, rubric_sha256=digest(rubric))
    receipt = bridge_assessment(artifact, inventory, rubric, *sheets, catalogue=catalogue, mapping=mapping,
                                expected_mapping_sha256=digest(mapping), expected_case=expected,
                                pin=pin, expected_pin_sha256=metadata_digest(pin))
    assert receipt.content_pin_mode == "global" and receipt.case_approval_ref is None
    wrong_global = global_pin(artifact)
    with pytest.raises(ValueError, match="artifact/rubric"):
        bridge_assessment(artifact, inventory, rubric, *sheets, catalogue=catalogue, mapping=mapping,
                          expected_mapping_sha256=digest(mapping), expected_case=expected,
                          pin=wrong_global, expected_pin_sha256=metadata_digest(wrong_global))
