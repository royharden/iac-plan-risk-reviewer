"""Explicit schema-export source. Imports cause no app loading or file writes."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def boundary_models() -> dict:
    """Only called by explicit export/test invocation after runtime is authorized."""
    import sys

    root = Path(__file__).resolve().parents[1]
    for directory in (root, root / "src"):
        if str(directory) not in sys.path:
            sys.path.insert(0, str(directory))
    from iac_review.contracts import EvidenceRef, PlanIdentity, RuleEvaluation, ValueState
    from iac_review.contracts.manifest import (
        ArtifactRef, AttemptMetadata, CaseBinding, ComponentVersion,
        EvaluationEligibility, InvocationMetadata, RunManifest,
    )
    from iac_review.explain import ClauseSelection, ExplanationCapsule, ExplanationResponse, SelectionResult
    from eval.model.protocol import ClaimAssessment, ModelOnlyRequest, Prediction
    from eval.scanners.artifacts import Capture, Mapping
    from eval.runner.scoring import ArmRow, Edition, EligibleMeasurement, EligibilityManifest, OracleRow
    from eval.runner.custody import Actor, CustodyAuthority, ExposureReceipt, InventoryRow, Seal, SemanticReceipt
    from eval.runner.utility import Attempt, ExplanationCase, LObservation, MeasurementPin, PObservation
    from eval.runner.model_bridge import (
        AttemptSnapshot, BridgeResult, JournalLink, LBatch, MBatch, PBatch, UtilityRequest,
        ProducerAccounting, ProducerExport,
    )
    from eval.runner.preflight import PreflightPins
    return {
        "core-ValueState": ValueState, "core-PlanIdentity": PlanIdentity,
        "core-EvidenceRef": EvidenceRef, "core-RuleEvaluation": RuleEvaluation,
        "selector-ClauseSelection": ClauseSelection, "selector-ExplanationCapsule": ExplanationCapsule,
        "selector-ExplanationResponse": ExplanationResponse, "selector-SelectionResult": SelectionResult,
        "model-ClaimAssessment": ClaimAssessment, "model-ModelOnlyRequest": ModelOnlyRequest,
        "model-Prediction": Prediction, "scanner-Capture": Capture, "scanner-Mapping": Mapping,
        "eval-ArmRow": ArmRow, "eval-Edition": Edition, "eval-OracleRow": OracleRow,
        "eval-EligibleMeasurement": EligibleMeasurement, "eval-EligibilityManifest": EligibilityManifest,
        "custody-Actor": Actor, "custody-CustodyAuthority": CustodyAuthority,
        "custody-ExposureReceipt": ExposureReceipt, "custody-InventoryRow": InventoryRow,
        "custody-Seal": Seal, "custody-SemanticReceipt": SemanticReceipt,
        "utility-Attempt": Attempt, "utility-ExplanationCase": ExplanationCase,
        "utility-LObservation": LObservation, "utility-MeasurementPin": MeasurementPin,
        "utility-PObservation": PObservation, "bridge-AttemptSnapshot": AttemptSnapshot,
        "bridge-BridgeResult": BridgeResult, "bridge-JournalLink": JournalLink,
        "bridge-LBatch": LBatch, "bridge-MBatch": MBatch, "bridge-PBatch": PBatch,
        "bridge-UtilityRequest": UtilityRequest,
        "bridge-ProducerAccounting": ProducerAccounting, "bridge-ProducerExport": ProducerExport,
        "manifest-RunManifest": RunManifest, "manifest-ArtifactRef": ArtifactRef,
        "manifest-AttemptMetadata": AttemptMetadata, "manifest-CaseBinding": CaseBinding,
        "manifest-ComponentVersion": ComponentVersion,
        "manifest-EvaluationEligibility": EvaluationEligibility,
        "manifest-InvocationMetadata": InvocationMetadata, "manifest-PreflightPins": PreflightPins,
    }


def schema_bundle() -> dict[str, bytes]:
    result = {}
    for name, model in sorted(boundary_models().items()):
        if not (model.model_config.get("strict") is True
                and model.model_config.get("frozen") is True
                and model.model_config.get("extra") == "forbid"):
            raise ValueError("schema boundary must be strict, frozen and closed")
        schema = model.model_json_schema(mode="validation")
        if schema.get("additionalProperties") is not False:
            raise ValueError("root JSON object is not closed")
        result[name + ".schema.json"] = (json.dumps(
            schema, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")
    return result


def export_schemas(out: Path) -> dict:
    if out.exists() or any(p.is_symlink() for p in (out, *out.parents)):
        raise ValueError("schema destination must be fresh, without symlink ancestors")
    if not out.parent.is_dir():
        raise ValueError("schema destination parent must already exist")
    files = schema_bundle()  # Validate all schemas before creating a destination.
    manifest = {"schema_version": 1, "schema_mode": "validation",
                "files": {name: hashlib.sha256(data).hexdigest() for name, data in files.items()},
                "limitations": ["JSON Schema does not encode all Python validators or strict parsing semantics.",
                                "Schema availability is not runtime or product acceptance."]}
    out.mkdir(exist_ok=False)
    for name, data in files.items():
        with (out / name).open("xb") as stream:
            stream.write(data)
    with (out / "manifest.json").open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        export_schemas(args.out)
    except (ValueError, OSError) as error:
        parser.exit(2, f"schema export refused: {type(error).__name__}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
