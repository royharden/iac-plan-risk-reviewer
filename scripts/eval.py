"""Pinned offline scorer; custody records are attestations, never authentication."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from eval.runner.scoring import ArmRow, Edition, EligibilityManifest, OracleRow, score  # noqa: E402
from eval.runner.custody import (  # noqa: E402
    CustodyAuthority, ExposureReceipt, Seal, SemanticReceipt, metadata_digest,
    validate_exposure, validate_independence, validate_seal, validate_semantics,
)
from eval.runner.model_bridge import UtilityRequest, utility_summaries  # noqa: E402
from eval.runner.scoring_handoff import (  # noqa: E402
    ScoringHandoff, check_completion_reference, check_handoff_for_scoring)
from eval.runner.edition_release import CompletionReference  # noqa: E402  (read-only D6 type)

MAX_BYTES = 16 * 1024 * 1024


def _pairs(items):
    result = {}
    for name, value in items:
        if name in result:
            raise ValueError("duplicate JSON key")
        result[name] = value
    return result


def _constant(value):
    raise ValueError("nonfinite JSON value")


def regular(path: Path) -> None:
    if any(part.is_symlink() for part in (path, *path.parents)) or not path.is_file():
        raise ValueError("bounded regular input without symlink ancestors required")
    if path.stat().st_size > MAX_BYTES:
        raise ValueError("evaluation input exceeds byte cap")


def read_bytes(path: Path) -> bytes:
    regular(path)
    # Limit the actual read as well as the pre-read size. No application code executes.
    with path.open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("evaluation input grew beyond byte cap")
    return data


def read_json(path: Path):
    return json.loads(read_bytes(path), object_pairs_hook=_pairs, parse_constant=_constant)


def model(path: Path, kind):
    # Duplicate-key/nonfinite checks run before Pydantic JSON-mode tuple/datetime parsing.
    return kind.model_validate_json(json.dumps(read_json(path), allow_nan=False))


def durable_json(path: Path, value: dict) -> None:
    with path.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(value, indent=2, allow_nan=False) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def decode_rows(data: bytes, kind):
    lines = data.decode("utf-8").splitlines()
    if len(lines) > 100000:
        raise ValueError("row count exceeds bound")
    rows = []
    for line in lines:
        if not line.strip():
            continue
        obj = json.loads(line, object_pairs_hook=_pairs, parse_constant=_constant)
        rows.append(kind.model_validate_json(json.dumps(obj, allow_nan=False)))
    return rows


def validate_utility_inputs(request: UtilityRequest, seal: Seal, oracle: list[OracleRow],
                            split: str, measured: list[ArmRow], eligibility: EligibilityManifest) -> None:
    """Do not let a utility artifact describe another build, corpus or denominator."""
    gold = {(row.case_id, row.resource_id, row.rule_id): row for row in oracle if row.split == split}
    inventory = {row.case_id: row for row in seal.inventory if row.split == split}
    predictions = {(row.arm, row.case_id, row.resource_id, row.rule_id): row for row in measured}
    for bundle in request.producer_exports:
        provenance = json.loads(bundle.provenance_json, object_pairs_hook=_pairs, parse_constant=_constant)
        if (provenance.get("build_sha256") != seal.edition.frozen_build_sha256
                or provenance.get("corpus_sha256") != seal.edition.lineage_inventory_sha256):
            raise ValueError("producer accounting belongs to another build/corpus")
        if not set(bundle.rows) <= set(measured):
            raise ValueError("producer accounting rows differ from measurement artifact")
    for batch in (request.l, request.p, request.m):
        if batch is None:
            continue
        pin = batch.pin
        if (pin.edition_id != seal.edition.edition_id
                or pin.build_sha256 != seal.edition.frozen_build_sha256
                or pin.corpus_sha256 != seal.edition.lineage_inventory_sha256):
            raise ValueError("utility build/corpus/edition mismatch")
        # The externally approved authority separately binds prompt/rubric in main().
        for case in getattr(batch, "cases", ()):
            row = gold.get((case.case_id, case.resource_id, case.rule_id))
            item = inventory.get(case.case_id)
            if (row is None or item is None or not item.explanation_eligible
                    or row.applicability != "supported"
                    or row.outcome not in {"introduced_risk", "unchanged_risk"}
                    or case.input_sha256 != item.input_sha256 or case.rule_id != item.rule_id
                    or case.action != item.action or case.knowledge != item.knowledge):
                raise ValueError("utility scenario lacks independently eligible matching oracle")
    if split == "heldout":
        expected = {row.case_id for row in seal.inventory if row.split == split and row.explanation_eligible}
        for batch in (request.l, request.p):
            if batch is not None and {row.case_id for row in batch.cases} != expected:
                raise ValueError("utility drops sealed eligible denominator")
    if request.l is not None:
        for observation in request.l.observations:
            for row in (observation.baseline, observation.selector):
                if predictions.get((row.arm, row.case_id, row.resource_id, row.rule_id)) != row:
                    raise ValueError("utility L/D row differs from detection artifact")
    if request.p is not None:
        if set(request.p.generator_authors) != set(seal.edition.detector_authors):
            raise ValueError("P generator lineage differs from approved implementation")
    # Every model measurement reference must bind a real attempt receipt digest.
    # This reconciles the two formerly separate provenance channels.
    for arm, batch in (("L", request.l), ("P", request.p), ("M", request.m)):
        if batch is None:
            continue
        attempts = {row.attempt_id: row for row in batch.attempts}
        refs = {}
        for attempt in attempts.values():
            refs[metadata_digest(attempt)] = attempt
            refs["sha256:" + metadata_digest(attempt)] = attempt
        for row in measured:
            if row.arm != arm or row.status == "not_run":
                continue
            attempt = refs.get(row.measurement_ref)
            if attempt is None or attempt.source_sha256 != row.source_sha256 or attempt.arm != arm:
                raise ValueError("model row lacks matching all-attempt receipt")
            matching = [meta for meta in eligibility.rows if meta.arm == arm
                        and meta.measurement_ref == row.measurement_ref
                        and meta.source_sha256 == row.source_sha256]
            if len(matching) != 1 or matching[0].provenance_sha256 != attempt.terminal_record_sha256:
                raise ValueError("model row provenance differs from attempt terminal receipt")
            if (matching[0].kind != attempt.origin
                    or matching[0].original_live_receipt_sha256 != attempt.original_live_receipt_sha256):
                raise ValueError("model execution/replay eligibility differs from actual attempt")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--split", choices=("dev", "validation", "heldout"), required=True)
    for name in ("manifest", "oracle", "measurements", "out", "custody-authority", "seal",
                 "semantic-receipt", "eligibility", "utility"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("authority-sha256", "semantic-suite-sha256", "eligibility-sha256", "utility-sha256"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--exposure-receipts", type=Path)
    # Heldout only: pinned post-run handoff (eval/runner/scoring_handoff.py, docs/SCORING-HANDOFF.md).
    parser.add_argument("--scoring-handoff", type=Path)
    parser.add_argument("--scoring-handoff-sha256")
    # Optional release completion reference: when present, cross-checked with the handoff.
    parser.add_argument("--completion-reference", type=Path)
    parser.add_argument("--completion-reference-sha256")
    parser.add_argument("--allow-sealed-exposure", action="store_true",
                        help="requires externally persisted receipt; never makes an exposed edition fresh")
    args = parser.parse_args(argv)
    try:
        authority = model(args.custody_authority, CustodyAuthority)
        seal = model(args.seal, Seal)
        edition = model(args.manifest, Edition)
        if edition != seal.edition:
            raise ValueError("manifest differs from independently pinned seal")
        custody = validate_seal(authority, seal, args.authority_sha256)
        semantic = model(args.semantic_receipt, SemanticReceipt)
        validate_semantics(authority, semantic, args.authority_sha256, args.semantic_suite_sha256)
        eligibility = model(args.eligibility, EligibilityManifest)
        if eligibility.edition_id != edition.edition_id or metadata_digest(eligibility) != args.eligibility_sha256:
            raise ValueError("eligibility manifest pin/edition mismatch")
        exposure = None
        receipts = ()
        handoff = None
        if args.split == "heldout":
            if edition.state == "sealed" and not args.allow_sealed_exposure:
                raise ValueError("sealed edition requires explicit exposure approval")
            if args.exposure_receipts is None:
                raise ValueError("external durable pre-access exposure receipts required")
            raw = read_json(args.exposure_receipts)
            if type(raw) is not list or len(raw) > 7:
                raise ValueError("bounded exposure receipt list required")
            receipts = tuple(ExposureReceipt.model_validate_json(json.dumps(row)) for row in raw)
            exposure = validate_exposure(authority, seal, receipts, args.authority_sha256)
            # S1 item 4: heldout scoring consumes the pinned post-run handoff (metadata only).
            # A committed pre-access input exposure is never scoring permission.
            if args.scoring_handoff is None or args.scoring_handoff_sha256 is None:
                raise ValueError("heldout scoring requires the pinned post-run scoring handoff")
            handoff = model(args.scoring_handoff, ScoringHandoff)
            if (metadata_digest(handoff) != args.scoring_handoff_sha256
                    or handoff.edition_id != edition.edition_id
                    or handoff.build_sha256 != edition.frozen_build_sha256):
                raise ValueError("scoring handoff pin/edition mismatch")
        if (args.completion_reference is None) != (args.completion_reference_sha256 is None):
            raise ValueError("completion reference and its external pin are required together")
        completion_check = None
        if args.completion_reference is not None:
            if handoff is None:
                raise ValueError("completion reference cross-check requires a heldout scoring handoff")
            completion_check = check_completion_reference(handoff, model(args.completion_reference, CompletionReference),
                expected_completion_sha256=args.completion_reference_sha256)
        # Before any oracle/measurement bytes are read, reserve a fresh local output
        # and flush a durable consumption record. Parse/hash failure never removes it.
        if args.out.exists() or any(p.is_symlink() for p in (args.out, *args.out.parents)):
            raise ValueError("output must be fresh with no symlink ancestors")
        regular(args.oracle)
        regular(args.measurements)
        args.out.mkdir(parents=False, exist_ok=False)
        preaccess = {"edition_id": edition.edition_id, "split": args.split,
                     "state": "consumed_holdout" if args.split == "heldout" else "development",
                     "authority_sha256": args.authority_sha256, "seal_sha256": metadata_digest(seal),
                     "build_sha256": edition.frozen_build_sha256,
                     "external_exposure_receipts": [row.model_dump(mode="json") for row in receipts],
                     "scoring_handoff_sha256": args.scoring_handoff_sha256 if handoff is not None else None,
                     "completion_reference_check": completion_check,
                     "authorship_authenticated": False}
        durable_json(args.out / "exposure.json", preaccess)
        # Parent directory fsync/ACL locking and receipt retention remain custody-controller duties.
        request = model(args.utility, UtilityRequest)
        if metadata_digest(request) != args.utility_sha256:
            raise ValueError("utility manifest is not externally pinned")
        for batch in (request.l, request.p, request.m):
            if batch is not None and (batch.pin.prompt_sha256 != authority.prompt_sha256
                                      or batch.pin.rubric_sha256 != authority.rubric_sha256):
                raise ValueError("utility prompt/rubric differs from frozen authority")
        if request.p is not None:
            first, second = request.p.appointed_assessors
            adjudicator = request.p.appointed_adjudicator
            # Reuse real registry/session/fork closure for every pair of rubric actors.
            for a, b in ((first, second), (first, adjudicator), (second, adjudicator)):
                validate_independence(authority.model_copy(update={
                    "oracle_author": a, "oracle_checker": b, "custodian": adjudicator}))
        oracle_bytes = read_bytes(args.oracle)
        measurement_bytes = read_bytes(args.measurements)
        oracle_hash = hashlib.sha256(oracle_bytes).hexdigest()
        measurement_hash = hashlib.sha256(measurement_bytes).hexdigest()
        if oracle_hash != edition.oracle_sha256:
            raise ValueError("oracle bytes differ from frozen edition")
        if any(row.measurements_sha256 != measurement_hash for row in receipts):
            raise ValueError("exposure receipt measurement digest mismatch")
        measured = decode_rows(measurement_bytes, ArmRow)
        handoff_summary = None
        if handoff is not None:
            # Checked BEFORE the oracle is decoded; failure leaves the oracle undecoded.
            handoff_summary = check_handoff_for_scoring(handoff, edition_id=edition.edition_id,
                build_sha256=edition.frozen_build_sha256, receipts=receipts,
                measurement_sha256=measurement_hash, measured=measured)
        oracle = decode_rows(oracle_bytes, OracleRow)
        if receipts and not {row.arm for row in measured} <= {row.arm for row in receipts}:
            raise ValueError("measurement arm lacks pre-access exposure receipt")
        inv = {row.case_id: row for row in seal.inventory}
        for row in oracle:
            item = inv.get(row.case_id)
            if item is None or (row.family_id, row.configuration_lineage, row.mutation_lineage,
                                row.split, row.rule_id) != (item.family_id, item.configuration_lineage,
                                item.mutation_lineage, item.split, item.rule_id):
                raise ValueError("oracle inventory lineage mismatch")
        if {row.case_id for row in oracle} != set(inv):
            raise ValueError("oracle drops sealed inventory")
        for row in measured:
            if row.build_sha256 != edition.frozen_build_sha256 or row.source_sha256 != inv[row.case_id].input_sha256:
                raise ValueError("measurement build/raw case mismatch")
        validate_utility_inputs(request, seal, oracle, args.split, measured, eligibility)
        utility = utility_summaries(request)
        result = score(oracle, measured, args.split, eligibility=eligibility,
                       expected_eligibility_sha256=args.eligibility_sha256)
        for arm in ("L", "P", "M"):
            result["arms"][arm]["utility"] = utility[arm]
            result["arms"][arm]["all_attempt_cost"] = utility[arm].get("cost")
            producer_cost = utility[arm].get("producer_all_attempt_cost")
            if producer_cost is not None:
                result["arms"][arm]["all_attempt_cost"] = producer_cost
                result["arms"][arm]["known_usd"] = float(producer_cost["known_usd_decimal"])
                result["arms"][arm]["cost_completeness"] = "INVOCATION_ACCOUNTING_ONLY"
                result["arms"][arm]["cost_scope"] = producer_cost["scope"]
                result["arms"][arm]["billing_fully_known"] = producer_cost["billing_fully_known"]
                result["arms"][arm]["unresolved_upper_bounds_known"] = True
                result["arms"][arm]["unresolved_usd_upper"] = float(producer_cost["unresolved_usd_upper_decimal"])
            elif utility[arm].get("cost") is not None:
                result["arms"][arm]["known_usd"] = utility[arm]["cost"]["known_usd"]
                result["arms"][arm]["cost_completeness"] = "EXPLICIT_ALL_ATTEMPT_RECEIPTS"
                result["arms"][arm]["cost_scope"] = "all explicit expected attempt receipts"
                result["arms"][arm]["billing_fully_known"] = utility[arm]["cost"]["billing_fully_known"]
                result["arms"][arm]["unresolved_upper_bounds_known"] = utility[arm]["cost"]["unresolved_upper_bounds_known"]
                result["arms"][arm]["unresolved_usd_upper"] = utility[arm]["cost"]["unresolved_usd_upper"]
            if utility[arm]["measurement_status"] != "RECORDED":
                result["arms"][arm]["measurement_status"] = "INCOMPLETE"
        if handoff_summary is not None:
            # No favorable-score gate: every arm the frozen run left incomplete stays so.
            for arm in handoff_summary["incomplete_arms"]:
                if arm in result["arms"]:
                    result["arms"][arm]["measurement_status"] = "INCOMPLETE"
            # score() sets the deterministic gate only for a RECORDED D arm; keep it consistent.
            if "D" in handoff_summary["incomplete_arms"]:
                result["deterministic_exact_gate"] = False
            result["scoring_handoff"] = handoff_summary
            result["completion_reference_check"] = completion_check
        result.update({"provenance": preaccess, "custody": custody,
                       "exposure": exposure, "utility": utility,
                       "authorship_authenticated": False, "product_acceptance": False})
        durable_json(args.out / "results.json", result)
        # Existing README/scoring consumers retain the established JSONL artifact.
        with (args.out / "results.jsonl").open("x", encoding="utf-8") as stream:
            stream.write(json.dumps(result, allow_nan=False) + "\n")
        lines = ["# Imported evaluation results", "", "Runtime/product acceptance remains pending.",
                 "Metadata consistency is not authorship/execution authentication.", "",
                 "| Arm | Status | Failed rows |", "|---|---|---|"]
        for arm, row in result["arms"].items():
            lines.append(f"| {arm} | {row['measurement_status']} | {len(row['failures'])} |")
        (args.out / "results.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
        return 0 if result["deterministic_exact_gate"] and all(
            row["measurement_status"] == "RECORDED" for row in result["arms"].values()) else 2
    except (ValueError, OSError, KeyError, RecursionError, TypeError) as error:
        print(f"evaluation refused: {type(error).__name__}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
