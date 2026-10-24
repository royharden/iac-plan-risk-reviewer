"""Actual-wire schema/version compatibility regression SOURCE; never run here.

Small public development cases, not measured arm evidence, gold or acceptance.
"""
from dataclasses import replace
import json
from hashlib import sha256

import pytest


@pytest.fixture
def registry():
    from eval.runner import schema_registry
    return schema_registry


def test_data_catalogue_does_not_load_application_or_provider(registry, monkeypatch):
    import builtins
    original = builtins.__import__
    def refuse(name, *args, **kwargs):
        if name.startswith(("iac_review", "eval.model", "eval.scanners")):
            raise AssertionError("data catalogue imported application/provider")
        return original(name, *args, **kwargs)
    monkeypatch.setattr(builtins, "__import__", refuse)
    catalogue = registry.catalogue()
    assert catalogue["schema_version"] == "m4-schema-catalogue-v1"
    assert catalogue["schema_only"] is True
    assert all(catalogue[field] is False for field in (
        "payload_admission", "actor_authenticated", "execution_verified",
        "provider_activated", "release_authorized", "product_acceptance"))


def test_completed_wire_families_use_canonical_types_and_private_classification(registry):
    models = registry.boundary_models()
    from eval.runner.assessment_batch import AssessmentBatchTransport
    from eval.model.provider_activation import Admission
    from iac_review.contracts import ReviewReport
    assert models["batch-AssessmentBatchTransport"] is AssessmentBatchTransport
    assert models["activation-Admission"] is Admission
    assert models["core-ReviewReport"] is ReviewReport
    for name in ("core-ReviewReport", "provenance-ReportProvenance", "artifact-ExplanationArtifact",
                 "capture-_Index", "capture-VerifiedCaptureIndex", "batch-AssessmentBatchTransport",
                 "assembly-ReleaseAuthorization", "release-CompletionReference", "activation-Admission"):
        assert registry.resolve(name).classification == "private"
    assert registry.resolve("selector-ExplanationCapsule").classification == "shareable_shape"
    assert registry.resolve("provider-ProviderConfig").representation == "dataclass_description"


def test_duplicate_missing_version_and_classification_conflicts_refuse(registry):
    entries = registry.declarations()
    with pytest.raises(ValueError, match="duplicate"):
        registry.validate_declarations((*entries, entries[0]))
    with pytest.raises(ValueError, match="missing"):
        registry.validate_declarations(entries[1:])
    for change in ({"contract_version": "99"}, {"classification": "shareable_shape"}):
        with pytest.raises(ValueError, match="conflict"):
            registry.validate_declarations((replace(entries[0], **change), *entries[1:]))
    models = registry.boundary_models()
    del models["release-CompletionReference"]
    with pytest.raises(ValueError, match="missing"):
        registry.schema_documents(models)


def test_dispatch_rejects_unknown_id_contract_and_payload_versions(registry):
    assert registry.resolve("eval-ArmRow", wire_version="1").wire_versions == ("1", "2")
    assert registry.resolve("eval-ArmRow", wire_version="2").contract_version == "1"
    assert registry.resolve("batch-AssessmentBatchTransport",
        wire_version="m4-assessment-batch-transport-v1").classification == "private"
    for args, kwargs in (
        (("not-a-wire",), {}), (("manifest-RunManifest", "99"), {}),
        (("batch-AssessmentBatchTransport",), {"wire_version": "v2"}),
        (("eval-ArmRow",), {"wire_version": "3"}),
    ):
        with pytest.raises(ValueError, match="unsupported"):
            registry.resolve(*args, **kwargs)


def test_batch_actual_wire_has_no_implicit_version_or_unknown_fields(registry):
    from pydantic import ValidationError
    batch = registry.boundary_models()["batch-AssessmentBatchTransport"]
    # Construct nested valid request separately only in later authorized execution.
    # Even an otherwise incomplete envelope must reject these specific fields.
    for version in (None, "m4-assessment-batch-transport-v2"):
        value = {"root_id": "public-development", "root_sha256": "a" * 64,
                 "request": {}, "plans": [], "provider_activation": True}
        if version is not None:
            value["schema_version"] = version
        with pytest.raises(ValidationError) as caught:
            batch.model_validate_json(json.dumps(value))
        errors = {(tuple(row["loc"]), row["type"]) for row in caught.value.errors()}
        assert (("provider_activation",), "extra_forbidden") in errors
        assert any(loc == ("schema_version",) and kind in {"missing", "literal_error"}
                   for loc, kind in errors)


def test_schema_only_wrapper_does_not_invent_nested_report_validator(registry):
    from pydantic import ValidationError
    models = registry.boundary_models()
    report = models["core-ReviewReport"]
    # The real wrapper accepts dictionaries; catalogue explicitly discloses that
    # its schema cannot attest a safe private/shareable payload projection.
    parsed = report(private={}, shareable={}, exit_code=0)
    assert parsed.private == {}
    with pytest.raises(ValidationError):
        report(private={}, shareable={}, exit_code=0, provider_activation=True)
    assert any("dictionary wrapper" in text for text in registry.catalogue()["limitations"])


def test_legacy_arm_defaults_remain_ineligible_and_binary_is_explicit(registry):
    from pydantic import ValidationError
    model = registry.boundary_models()["eval-ArmRow"]
    raw = {"case_id": "synthetic", "resource_id": "resource", "rule_id": "R1", "arm": "M",
           "status": "ok", "source_sha256": "a" * 64, "build_sha256": "b" * 64,
           "measurement_ref": "synthetic-measurement"}
    legacy = model.model_validate_json(json.dumps(raw))
    assert legacy.schema_version == 1 and legacy.measurement_kind == "unverified"
    assert legacy.eligibility_ref is None and legacy.prediction_target == "full_outcome"
    with pytest.raises(ValidationError):
        model.model_validate_json(json.dumps({**raw, "introduced_prediction": True}))
    binary = model.model_validate_json(json.dumps({**raw, "prediction_target": "introduced_risk",
                                                   "introduced_prediction": None}))
    assert binary.outcome is None


@pytest.fixture
def registry_report_bundle(tmp_path, core_plan_file):
    from iac_review.ingest import load_plan
    from iac_review.rules import evaluate
    from iac_review.report import build_report, write_report
    source = core_plan_file()
    plan = load_plan(source)
    report = build_report(plan, evaluate(plan))
    out = tmp_path / "bound-report"
    write_report(report, out)
    return out, source


def _replace_manifest(bundle, change):
    path = bundle / "manifest.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    change(value)
    raw = json.dumps(value, sort_keys=True).encode("utf-8")
    path.write_bytes(raw)
    (bundle / "manifest.sha256").write_text(sha256(raw).hexdigest() + "\n", encoding="ascii")


def test_bound_and_legacy_inventory_keep_distinct_integrity_meanings(registry_report_bundle, tmp_path):
    from iac_review.source_view import verify_report
    bound, source = registry_report_bundle
    assert verify_report(bound, source)["run_manifest_bound"] is True
    legacy = tmp_path / "legacy-report"
    legacy.mkdir()
    names = ("private.json", "shareable.json", "private.html", "shareable.html",
             "manifest.json", "manifest.sha256", "export-state.json")
    for name in names:
        (legacy / name).write_bytes((bound / name).read_bytes())
    private = json.loads((legacy / "private.json").read_text(encoding="utf-8"))
    private.pop("provenance")
    raw = json.dumps(private, sort_keys=True).encode("utf-8")
    (legacy / "private.json").write_bytes(raw)
    def legacy_inventory(value):
        value["schema_version"] = "1.0.0"
        del value["artifacts"]["run-manifest.json"]
        value["artifacts"]["private.json"] = sha256(raw).hexdigest()
    _replace_manifest(legacy, legacy_inventory)
    result = verify_report(legacy, source)
    assert result["run_manifest_bound"] is False
    assert result["producer_authenticated"] is False and result["product_acceptance"] is False


@pytest.mark.parametrize("mutation", ["downgrade_inventory", "unknown_version", "unknown_field"])
def test_report_version_or_inventory_cannot_silently_upgrade(registry_report_bundle, mutation):
    from iac_review.source_view import verify_report
    from iac_review.ingest import InputError
    out, source = registry_report_bundle
    def change(value):
        if mutation == "downgrade_inventory":
            value["schema_version"] = "1.0.0"  # Bound descriptor is still present.
        elif mutation == "unknown_version":
            value["schema_version"] = "99.0.0"
        else:
            value["provider_activation"] = True
    _replace_manifest(out, change)
    with pytest.raises(InputError):
        verify_report(out, source)


def test_deterministic_manifest_is_not_benchmark_admission(registry_report_bundle, registry, tmp_path):
    from pydantic import ValidationError
    from eval.runner.custody import metadata_digest
    from eval.runner.preflight import PreflightPins, preflight
    out, _ = registry_report_bundle
    descriptor = json.loads((out / "run-manifest.json").read_text(encoding="utf-8"))
    model = registry.boundary_models()["manifest-RunManifest"]
    raw = descriptor["run_manifest"]
    local = model.model_validate_json(json.dumps(raw))
    assert local.stage == "deterministic" and local.attempts == () and local.eligibility == ()
    with pytest.raises(ValidationError):
        model.model_validate_json(json.dumps({**raw, "authority_sha256": "a" * 64}))
    with pytest.raises(ValidationError):
        model.model_validate_json(json.dumps({**raw, "stage": "evaluation"}))
    # A schema-valid evaluation declaration with pins is still not execution or
    # custody: full preflight rejects its missing evaluation component inventory.
    declared = model.model_validate_json(json.dumps({**raw, "stage": "evaluation",
        "authority_sha256": "a" * 64, "semantic_suite_sha256": "b" * 64,
        "eligibility_sha256": "c" * 64}))
    pins = PreflightPins(run_manifest_sha256=metadata_digest(declared), authority_sha256="a" * 64,
                        semantic_suite_sha256="b" * 64, eligibility_sha256="c" * 64)
    with pytest.raises(ValueError, match="component|version pins"):
        preflight(tmp_path, declared, pins)


def test_actual_capture_alias_and_closed_source_config(registry):
    from pydantic import ValidationError
    models = registry.boundary_models()
    capture = models["capture-_Index"]
    assert capture.model_fields["schema_version"].alias == "schema"
    config = models["provenance-LocalConfig"]
    assert config(fail_on=4).fail_on == 4
    for extra in ({"provider_activation": True}, {"schema_version": 99}):
        with pytest.raises(ValidationError):
            config.model_validate_json(json.dumps({"fail_on": 4, **extra}))
