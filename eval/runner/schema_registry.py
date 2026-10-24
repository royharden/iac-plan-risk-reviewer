"""Fixed actual-type schema descriptions. No application imports at module scope.

Descriptions grant no payload, identity, execution, release or provider admission.
Canonical imports and Pydantic schema generation occur only on explicit invocation.
"""
from __future__ import annotations

from dataclasses import dataclass, is_dataclass
import json


@dataclass(frozen=True)
class Declaration:
    stable_id: str
    contract_version: str
    type_name: str
    classification: str
    representation: str
    wire_versions: tuple[str, ...]
    wire_version_field: str | None
    compatibility: str = "source_description_only_runtime_unverified"


# A fixed required inventory, not filesystem discovery or CLI-selected modules.
# contract_version is this catalogue's description revision, NOT a payload upgrade.
GROUPS = (
    ("core", "private", "pydantic_closed", "iac_review.contracts", (
        "ValueState", "PlanIdentity", "ResourceChange", "PlanDocument", "EvidenceRef",
        "ResolvedEvidence", "RuleEvaluation", "ReviewReport")),
    ("selector", "shareable_shape", "pydantic_closed", "iac_review.explain", (
        "SafeFact", "ClauseSelection", "ExplanationCapsule", "ExplanationResponse", "SelectionResult")),
    ("model", "private", "pydantic_closed", "eval.model.protocol", (
        "SafeFact", "SafeResource", "ClaimAssessment", "ModelOnlyRequest", "Prediction")),
    ("scanner", "private", "pydantic_closed", "eval.scanners.artifacts", ("Capture", "Mapping")),
    ("eval", "private", "pydantic_closed", "eval.runner.scoring", (
        "ArmRow", "Edition", "OracleRow", "EligibleMeasurement", "EligibilityManifest")),
    ("custody", "private", "pydantic_closed", "eval.runner.custody", (
        "Actor", "CustodyAuthority", "ExposureReceipt", "InventoryRow", "Seal", "SemanticReceipt")),
    ("utility", "private", "pydantic_closed", "eval.runner.utility", (
        "Attempt", "ExplanationCase", "LObservation", "MeasurementPin", "PObservation")),
    ("bridge", "private", "pydantic_closed", "eval.runner.model_bridge", (
        "AttemptSnapshot", "BridgeResult", "JournalLink", "LBatch", "MBatch", "PBatch",
        "UtilityRequest", "ProducerAccounting", "ProducerExport")),
    ("manifest", "private", "pydantic_closed", "iac_review.contracts.manifest", (
        "RunManifest", "ArtifactRef", "AttemptMetadata", "CaseBinding", "ComponentVersion",
        "EvaluationEligibility", "InvocationMetadata")),
    ("provenance", "private", "pydantic_closed", "iac_review.provenance", (
        "SourceFilePin", "LocalConfig", "ReportProvenance")),
    ("accounting", "private", "pydantic_closed", "iac_review.attempts", (
        "Budget", "PriceIdentity", "Reservation")),
    ("artifact", "private", "pydantic_closed", "eval.model.explanation_artifacts", (
        "DecisionReference", "ExplanationArtifact", "SpanSpec", "ExplicitSpans", "TextSpan",
        "ClaimInventory", "Rubric", "AnnotationRow", "AssessorSheet", "AdjudicationSheet")),
    ("catalogue", "private", "pydantic_closed", "eval.model.review_catalogue", ("ReviewCatalogue",)),
    ("fact", "private", "pydantic_closed", "eval.runner.fact_mapping", (
        "ExpectedLocation", "FactCorrespondence", "FactMapping")),
    ("assessment", "private", "pydantic_closed", "eval.model.assessment_bridge", (
        "LimitationBinding", "CaseApprovalReference", "AssessmentReceipt")),
    ("intake", "private", "pydantic_closed", "eval.runner.assessment_import", (
        "CaseAssessmentAuthority", "AssessmentAuthority", "AssessmentSubmission", "AssessmentImportRequest")),
    ("capture", "private", "pydantic_closed", "eval.model.capture_index", (
        "CaptureOutcome", "_Index", "LReceipt", "VerifiedCaptureIndex")),
    ("batch", "private", "pydantic_closed", "eval.runner.assessment_batch", (
        "BatchScenario", "PlanInvocation", "AssessmentBatchRequest", "PrivateFileReference",
        "BatchPlanTransport", "AssessmentBatchTransport")),
    ("assembly", "private", "pydantic_closed", "eval.runner.bundle", (
        "AssemblySelection", "ReleasedArtifact", "ReleaseAuthorization", "CopiedArtifact", "AssemblyReceipt")),
    ("release", "private", "pydantic_closed", "eval.runner.edition_release", (
        "ArmCompletion", "CompletionReference")),
    ("provider", "private", "dataclass_description", "eval.model.provider_wire", (
        "ProviderConfig", "ApprovedAttempt")),
    ("activation", "private", "dataclass_description", "eval.model.provider_activation", (
        "StartedAttempt", "Activation", "Admission")),
    ("producer", "private", "dataclass_description", "eval.model.provenance", ("ExportBundle",)),
)

# Existing legacy ID retained even though PreflightPins lives outside manifest.py.
EXTRA = Declaration("manifest-PreflightPins", "1", "eval.runner.preflight.PreflightPins",
                    "private", "pydantic_closed", (), None)
VERSIONED = {
    "eval-ArmRow": ("1", "2"), "eval-EligibilityManifest": ("2",),
    "bridge-BridgeResult": ("1",), "bridge-UtilityRequest": ("1",),
    "manifest-RunManifest": ("1",), "provenance-LocalConfig": ("1",),
    "provenance-ReportProvenance": ("1",), "artifact-ExplanationArtifact": ("1",),
    "artifact-Rubric": ("1",), "capture-_Index": ("1",),
    "batch-AssessmentBatchTransport": ("m4-assessment-batch-transport-v1",),
    "assembly-AssemblySelection": ("1",), "assembly-ReleaseAuthorization": ("1",),
    "assembly-AssemblyReceipt": ("1",), "release-CompletionReference": ("1",),
}

LIMITATIONS = (
    "Schema descriptions are not payload validation, external actor authentication, execution or admission.",
    "Closed root Pydantic records still contain some dict/Any/string payloads; nested semantic closure is not inferred.",
    "ReviewReport describes the private/shareable dictionary wrapper, not typed individual report artifacts.",
    "Legacy/new report inventories are checked by source_view, not a canonical Pydantic inventory model.",
    "Standard dataclass TypeAdapter descriptions do not add strict parsing or unknown-field rejection to canonical dataclasses.",
    "Validation schemas may describe private fields excluded by serialization (e.g. verified capture artifacts). No instance is exported.",
    "Runtime clients/callbacks, Result/Observation/PrivateCapture private-instance collections and HTTP body wrappers are excluded.",
    "Unfinished D5 finite-selector extension is not registered; existing completed selector wires are retained.",
    "Default product imports do not consume this development registry or activate provider/release paths.",
)


def declarations() -> tuple[Declaration, ...]:
    entries = []
    for prefix, classification, representation, module, names in GROUPS:
        for name in names:
            identity = prefix + "-" + name
            versions = VERSIONED.get(identity, ())
            entries.append(Declaration(identity, "1", module + "." + name, classification,
                                       representation, versions,
                                       "schema" if identity == "capture-_Index" else
                                       "schema_version" if versions else None))
    return (*entries, EXTRA)


def _canonical_groups() -> dict:
    # Fixed imports only, reached by a later explicit schema request. No env/config,
    # approval/payload reads, runtime clients, instances or plugin names are used.
    import iac_review.contracts as core
    import iac_review.explain as selector
    import iac_review.contracts.manifest as manifest
    import iac_review.provenance as provenance
    import iac_review.attempts as accounting
    import eval.model.protocol as model
    import eval.scanners.artifacts as scanner
    import eval.runner.scoring as scoring
    import eval.runner.custody as custody
    import eval.runner.utility as utility
    import eval.runner.model_bridge as bridge
    import eval.model.explanation_artifacts as artifact
    import eval.model.review_catalogue as catalogue
    import eval.runner.fact_mapping as fact
    import eval.model.assessment_bridge as assessment
    import eval.runner.assessment_import as intake
    import eval.model.capture_index as capture
    import eval.runner.assessment_batch as batch
    import eval.runner.bundle as assembly
    import eval.runner.edition_release as release
    import eval.model.provider_wire as provider
    import eval.model.provider_activation as activation
    import eval.model.provenance as producer
    from eval.runner.preflight import PreflightPins
    return {
        "core": (core.ValueState, core.PlanIdentity, core.ResourceChange, core.PlanDocument,
                 core.EvidenceRef, core.ResolvedEvidence, core.RuleEvaluation, core.ReviewReport),
        "selector": (selector.SafeFact, selector.ClauseSelection, selector.ExplanationCapsule,
                     selector.ExplanationResponse, selector.SelectionResult),
        "model": (model.SafeFact, model.SafeResource, model.ClaimAssessment, model.ModelOnlyRequest, model.Prediction),
        "scanner": (scanner.Capture, scanner.Mapping),
        "eval": (scoring.ArmRow, scoring.Edition, scoring.OracleRow,
                 scoring.EligibleMeasurement, scoring.EligibilityManifest),
        "custody": (custody.Actor, custody.CustodyAuthority, custody.ExposureReceipt,
                    custody.InventoryRow, custody.Seal, custody.SemanticReceipt),
        "utility": (utility.Attempt, utility.ExplanationCase, utility.LObservation,
                    utility.MeasurementPin, utility.PObservation),
        "bridge": (bridge.AttemptSnapshot, bridge.BridgeResult, bridge.JournalLink, bridge.LBatch,
                   bridge.MBatch, bridge.PBatch, bridge.UtilityRequest, bridge.ProducerAccounting, bridge.ProducerExport),
        "manifest": (manifest.RunManifest, manifest.ArtifactRef, manifest.AttemptMetadata,
                     manifest.CaseBinding, manifest.ComponentVersion, manifest.EvaluationEligibility, manifest.InvocationMetadata),
        "provenance": (provenance.SourceFilePin, provenance.LocalConfig, provenance.ReportProvenance),
        "accounting": (accounting.Budget, accounting.PriceIdentity, accounting.Reservation),
        "artifact": (artifact.DecisionReference, artifact.ExplanationArtifact, artifact.SpanSpec,
                     artifact.ExplicitSpans, artifact.TextSpan, artifact.ClaimInventory, artifact.Rubric,
                     artifact.AnnotationRow, artifact.AssessorSheet, artifact.AdjudicationSheet),
        "catalogue": (catalogue.ReviewCatalogue,),
        "fact": (fact.ExpectedLocation, fact.FactCorrespondence, fact.FactMapping),
        "assessment": (assessment.LimitationBinding, assessment.CaseApprovalReference, assessment.AssessmentReceipt),
        "intake": (intake.CaseAssessmentAuthority, intake.AssessmentAuthority,
                   intake.AssessmentSubmission, intake.AssessmentImportRequest),
        "capture": (capture.CaptureOutcome, capture._Index, capture.LReceipt, capture.VerifiedCaptureIndex),
        "batch": (batch.BatchScenario, batch.PlanInvocation, batch.AssessmentBatchRequest,
                  batch.PrivateFileReference, batch.BatchPlanTransport, batch.AssessmentBatchTransport),
        "assembly": (assembly.AssemblySelection, assembly.ReleasedArtifact, assembly.ReleaseAuthorization,
                     assembly.CopiedArtifact, assembly.AssemblyReceipt),
        "release": (release.ArmCompletion, release.CompletionReference),
        "provider": (provider.ProviderConfig, provider.ApprovedAttempt),
        "activation": (activation.StartedAttempt, activation.Activation, activation.Admission),
        "producer": (producer.ExportBundle,), "preflight": (PreflightPins,),
    }


def validate_declarations(entries: tuple[Declaration, ...]) -> None:
    expected = declarations()
    ids = [entry.stable_id for entry in entries]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate schema ID/version conflict")
    if set(ids) != {entry.stable_id for entry in expected}:
        raise ValueError("missing or unexpected required completed wire")
    if {entry.stable_id: entry for entry in entries} != {entry.stable_id: entry for entry in expected}:
        raise ValueError("schema declaration/version/classification conflict")


def boundary_models() -> dict:
    groups = _canonical_groups()
    models = {}
    for prefix, _, _, _, names in GROUPS:
        types = groups[prefix]
        if tuple(wire.__name__ for wire in types) != names:
            raise ValueError("completed wire inventory/type-name mismatch")
        for name, wire in zip(names, types, strict=True):
            key = prefix + "-" + name
            if key in models:
                raise ValueError("duplicate schema ID")
            models[key] = wire
    models[EXTRA.stable_id] = groups["preflight"][0]
    validate_models(models)
    return models


def validate_models(models: dict) -> None:
    from pydantic import BaseModel
    from typing import Literal, get_args, get_origin
    entries = declarations()
    validate_declarations(entries)
    if set(models) != {entry.stable_id for entry in entries}:
        raise ValueError("missing or unexpected required completed wire")
    for entry in entries:
        wire = models[entry.stable_id]
        if (not isinstance(wire, type)
                or wire.__module__ + "." + wire.__qualname__ != entry.type_name):
            raise ValueError("noncanonical schema type substitution")
        if entry.representation == "pydantic_closed":
            if (not issubclass(wire, BaseModel) or wire.model_config.get("strict") is not True
                    or wire.model_config.get("frozen") is not True
                    or wire.model_config.get("extra") != "forbid"):
                raise ValueError("canonical boundary must be strict frozen closed")
            fields = {field.alias or name: field for name, field in wire.model_fields.items()}
            field = fields.get(entry.wire_version_field) if entry.wire_version_field else None
            if entry.wire_versions:
                if (field is None or get_origin(field.annotation) is not Literal
                        or tuple(str(value) for value in get_args(field.annotation)) != entry.wire_versions):
                    raise ValueError("canonical literal wire-version declaration drift")
            elif "schema_version" in fields or "schema" in fields:
                raise ValueError("completed versioned wire omitted from declaration")
        elif (not is_dataclass(wire) or not wire.__dataclass_params__.frozen):
            raise ValueError("canonical frozen dataclass description required")


def resolve(stable_id: str, contract_version: str = "1", *, wire_version: str | None = None) -> Declaration:
    """Explicit metadata dispatch only. Does not parse/admit a payload."""
    matches = [entry for entry in declarations() if entry.stable_id == stable_id
               and entry.contract_version == contract_version]
    if len(matches) != 1:
        raise ValueError("unsupported schema ID/contract version")
    entry = matches[0]
    if wire_version is not None and wire_version not in entry.wire_versions:
        raise ValueError("unsupported explicit wire version")
    return entry


def catalogue() -> dict:
    """Data-only fixed catalogue; this function does not load application modules."""
    from dataclasses import asdict
    entries = declarations()
    validate_declarations(entries)
    return {
        "schema_version": "m4-schema-catalogue-v1", "schema_mode": "validation",
        "entries": [{**asdict(entry), "filename": entry.stable_id + ".schema.json",
                     "canonical_root_unknown_fields_rejected": entry.representation == "pydantic_closed"}
                    for entry in entries],
        "schema_only": True, "payload_admission": False, "actor_authenticated": False,
        "execution_verified": False, "provider_activated": False,
        "release_authorized": False, "product_acceptance": False,
        "limitations": list(LIMITATIONS),
    }


def schema_documents(models: dict | None = None) -> dict[str, bytes]:
    """Future schema generation, never called during Dirty Mode construction."""
    from pydantic import TypeAdapter
    models = boundary_models() if models is None else models
    validate_models(models)
    result = {}
    for entry in declarations():
        wire = models[entry.stable_id]
        if entry.representation == "pydantic_closed":
            schema = wire.model_json_schema(mode="validation", by_alias=True)
            if schema.get("additionalProperties") is not False:
                raise ValueError("canonical root schema is not closed")
        else:
            # No config override/duplicate model; preserve actual dataclass limits.
            schema = TypeAdapter(wire).json_schema(mode="validation", by_alias=True)
        result[entry.stable_id + ".schema.json"] = (json.dumps(
            schema, ensure_ascii=True, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("ascii")
    return result
