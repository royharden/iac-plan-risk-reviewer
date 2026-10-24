"""Read-only reproducibility metadata preflight. Payloads are NEVER opened here."""
from __future__ import annotations

from decimal import Decimal
import hashlib
import json
from pathlib import Path

from iac_review.contracts.manifest import ArtifactRef, RunManifest, amount, relative_path
from eval.runner.custody import (
    CustodyAuthority, Digest, ExposureReceipt, Seal, SemanticReceipt, metadata_digest,
    validate_exposure, validate_seal, validate_semantics,
)
from eval.runner.scoring import ARMS, EligibilityManifest, Record, record_digest

METADATA_PATHS = {
    "authority": "metadata/custody-authority.json", "seal": "metadata/seal.json",
    "semantic_receipt": "metadata/semantic-receipt.json",
    "eligibility": "metadata/eligibility.json", "exposure": "metadata/exposure.json",
}


class PreflightPins(Record):
    run_manifest_sha256: Digest
    authority_sha256: Digest
    semantic_suite_sha256: Digest
    eligibility_sha256: Digest


def _unique(values, label: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"duplicate {label}")


def checked_path(root: Path, reference: ArtifactRef) -> Path:
    """Resolve only an exact declared relative path; never discover bundle files."""
    relative_path(reference.path)
    base = root.absolute()
    target = base.joinpath(*reference.path.split("/"))
    for path in (target, *target.parents):
        if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
            raise ValueError("symlink/junction artifact path forbidden")
    if not target.is_relative_to(base):
        raise ValueError("artifact escaped bundle root")
    return target


def _object(pairs):
    value = {}
    for name, item in pairs:
        if name in value:
            raise ValueError("duplicate metadata JSON key")
        value[name] = item
    return value


def _constant(value):
    raise ValueError("nonfinite metadata JSON")


def read_metadata(root: Path, ref: ArtifactRef):
    if ref.role not in METADATA_PATHS or ref.path != METADATA_PATHS[ref.role]:
        raise ValueError("artifact role is not on the readable metadata allowlist")
    path = checked_path(root, ref)
    if not path.is_file() or path.stat().st_size > min(ref.bytes_upper, 4 * 1024 * 1024):
        raise ValueError("metadata file absent or exceeds declared bound")
    with path.open("rb") as stream:
        raw = stream.read(min(ref.bytes_upper, 4 * 1024 * 1024) + 1)
    if len(raw) > ref.bytes_upper or len(raw) > 4 * 1024 * 1024:
        raise ValueError("metadata grew past byte cap")
    if hashlib.sha256(raw).hexdigest() != ref.sha256:
        raise ValueError("metadata artifact hash mismatch")
    return json.loads(raw, object_pairs_hook=_object, parse_constant=_constant)


def validate_links(manifest: RunManifest) -> dict:
    """Pure cross-reference checks: no filesystem or payload reads."""
    _unique([row.component_id for row in manifest.components], "component ids")
    _unique([row.case_id for row in manifest.cases], "case ids")
    _unique([row.invocation_id for row in manifest.invocations], "invocation ids")
    _unique([row.attempt_id for row in manifest.attempts], "attempt ids")
    _unique([row.artifact_id for row in manifest.artifacts], "artifact ids")
    _unique([row.path.casefold() for row in manifest.artifacts], "artifact path aliases")
    _unique([(row.arm, row.invocation_id, row.measurement_ref, row.raw_source_sha256)
             for row in manifest.eligibility], "eligibility claims")
    components = {row.component_id: row for row in manifest.components}
    cases = {row.case_id: row for row in manifest.cases}
    invocations = {row.invocation_id: row for row in manifest.invocations}
    attempts = {row.attempt_id: row for row in manifest.attempts}
    if not {"source", "parser", "rules", "prompt", "config", "corpus"} <= {row.kind for row in manifest.components}:
        raise ValueError("missing source/parser/rule/prompt/config/corpus version pins")
    for kind in ("source", "parser", "rules", "prompt", "corpus"):
        if sum(row.kind == kind for row in manifest.components) != 1:
            raise ValueError("ambiguous primary component pin")
    if (next(row.sha256 for row in manifest.components if row.kind == "source") != manifest.build_sha256
            or next(row.sha256 for row in manifest.components if row.kind == "rules") != manifest.policy_sha256):
        raise ValueError("source/rule component differs from run build/policy")
    for row in manifest.cases:
        if row.split != manifest.split:
            raise ValueError("case split differs from run split")
    assigned = []
    for invocation in manifest.invocations:
        _unique(invocation.case_ids, "invocation case ids")
        _unique(invocation.attempt_ids, "invocation attempt ids")
        if not set(invocation.case_ids) <= set(cases) or not set(invocation.attempt_ids) <= set(attempts):
            raise ValueError("invocation references missing case/attempt")
        config = components.get(invocation.config_component_id)
        version = components.get(invocation.version_component_id)
        expected = "model" if invocation.arm in {"L", "P", "M"} else (
            "scanner" if invocation.arm in {"C", "C-custom", "T"} else "rules")
        if config is None or config.kind != "config" or version is None or version.kind != expected:
            raise ValueError("invocation version/config binding mismatch")
        for identity in invocation.attempt_ids:
            attempt = attempts[identity]
            if attempt.invocation_id != invocation.invocation_id or attempt.arm != invocation.arm:
                raise ValueError("attempt crosses invocation/arm")
            candidates = [cases[name] for name in invocation.case_ids]
            matching = [case for case in candidates if case.raw_source_sha256 == attempt.raw_source_sha256]
            if not matching or any(case.safe_projection_sha256 != attempt.safe_projection_sha256 for case in matching):
                raise ValueError("raw/projection hash mismatch")
            if attempt.kind != invocation.kind:
                raise ValueError("attempt origin differs from invocation")
            if attempt.model_version_id is not None and (
                    attempt.model_version_id != invocation.version_component_id or version.kind != "model"):
                raise ValueError("attempt model version differs from invocation component")
            prompt = next(row for row in manifest.components if row.kind == "prompt")
            if attempt.prompt_sha256 is not None and attempt.prompt_sha256 != prompt.sha256:
                raise ValueError("attempt prompt differs from frozen prompt manifest")
            assigned.append(identity)
    if len(assigned) != len(set(assigned)) or set(assigned) != set(attempts):
        raise ValueError("orphaned or multiply assigned attempt")
    for claim in manifest.eligibility:
        invocation = invocations.get(claim.invocation_id)
        if invocation is None or invocation.arm != claim.arm:
            raise ValueError("eligibility references another invocation/arm")
        if claim.raw_source_sha256 not in {cases[name].raw_source_sha256 for name in invocation.case_ids}:
            raise ValueError("eligibility references another raw case")
        if claim.claimed_eligible:
            expected_kinds = {"live", "replay"} if claim.arm in {"L", "P", "M"} else {"executed"}
            if (claim.eligibility_ref is None or invocation.kind not in expected_kinds
                    or invocation.status in {"not_run", "pending", "unmapped"}
                    or not invocation.all_attempts_attested):
                raise ValueError("mock/missing/unverified invocation claims eligibility")
            if claim.arm in {"L", "P", "M"} and not invocation.attempt_ids:
                raise ValueError("eligible model invocation omits all attempts")
            for name in invocation.attempt_ids:
                attempt = attempts[name]
                if (attempt.status in {"pending", "not_run", "unmapped"}
                        or attempt.start_receipt_sha256 is None or attempt.terminal_receipt_sha256 is None):
                    raise ValueError("eligible invocation missing terminal/start receipt")
                if claim.arm in {"L", "P", "M"} and (
                        attempt.safe_projection_sha256 is None or attempt.prompt_sha256 is None
                        or attempt.model_version_id != invocation.version_component_id
                        or attempt.price_sha256 is None):
                    raise ValueError("eligible model attempt missing projection/prompt/model/price binding")
    known = sum((amount(row.known_usd) or Decimal(0) for row in manifest.attempts), Decimal(0))
    unresolved = [row for row in manifest.attempts if not row.billing_known]
    bounds_known = all(row.unresolved_usd_upper is not None for row in unresolved)
    return {"known_usd_decimal": str(known),
            "billing_fully_known": bool(manifest.attempts) and not unresolved,
            "unresolved_bounds_known": bounds_known,
            "unresolved_usd_upper_decimal": str(sum((amount(row.unresolved_usd_upper) or Decimal(0)
                                                     for row in unresolved), Decimal(0))) if bounds_known else None,
            "attempts": len(manifest.attempts),
            "cost_scope": "declared run attempt inventory; not authenticated execution"}


def preflight(root: Path, manifest: RunManifest, pins: PreflightPins) -> dict:
    if manifest.stage != "evaluation":
        raise ValueError("deterministic manifest is not benchmark evaluation input")
    if (metadata_digest(manifest) != pins.run_manifest_sha256
            or manifest.authority_sha256 != pins.authority_sha256
            or manifest.semantic_suite_sha256 != pins.semantic_suite_sha256
            or manifest.eligibility_sha256 != pins.eligibility_sha256):
        raise ValueError("run manifest/authority pins differ from externally approved selection")
    costs = validate_links(manifest)
    refs = {}
    for ref in manifest.artifacts:
        checked_path(root, ref)
        if ref.role in METADATA_PATHS:
            if ref.role in refs:
                raise ValueError("duplicate metadata role")
            refs[ref.role] = ref
    if not {"authority", "seal", "semantic_receipt", "eligibility"} <= set(refs):
        raise ValueError("missing required custody/semantic/eligibility metadata")
    authority = CustodyAuthority.model_validate_json(json.dumps(read_metadata(root, refs["authority"])))
    seal = Seal.model_validate_json(json.dumps(read_metadata(root, refs["seal"])))
    custody = validate_seal(authority, seal, pins.authority_sha256)
    if (manifest.edition_id != authority.edition_id or manifest.build_sha256 != authority.frozen_build_sha256
            or manifest.policy_sha256 != authority.policy_sha256):
        raise ValueError("run edition/build/policy differs from custody")
    if (next(row.sha256 for row in manifest.components if row.kind == "prompt") != authority.prompt_sha256
            or next(row.sha256 for row in manifest.components if row.kind == "corpus") != authority.inventory_sha256):
        raise ValueError("run prompt/corpus differs from independently frozen authority")
    sealed_cases = {row.case_id: row for row in seal.inventory if row.split == manifest.split}
    if {row.case_id for row in manifest.cases} != set(sealed_cases):
        raise ValueError("run omits or adds sealed split inventory")
    for row in manifest.cases:
        item = sealed_cases[row.case_id]
        if (row.raw_source_sha256, row.configuration_id, row.family_id, row.mutation_lineage) != (
                item.input_sha256, item.configuration_lineage, item.family_id, item.mutation_lineage):
            raise ValueError("run case lineage/source differs from sealed inventory")
    semantic = SemanticReceipt.model_validate_json(json.dumps(read_metadata(root, refs["semantic_receipt"])))
    validate_semantics(authority, semantic, pins.authority_sha256, pins.semantic_suite_sha256)
    eligible = EligibilityManifest.model_validate_json(json.dumps(read_metadata(root, refs["eligibility"])))
    if eligible.edition_id != manifest.edition_id or record_digest(eligible) != pins.eligibility_sha256:
        raise ValueError("evaluation eligibility metadata pin mismatch")
    by_digest = {record_digest(row): row for row in eligible.rows}
    if len(by_digest) != len(eligible.rows):
        raise ValueError("duplicate eligible measurement receipt")
    invocation_map = {row.invocation_id: row for row in manifest.invocations}
    eligible_arms = set()
    for claim in manifest.eligibility:
        if not claim.claimed_eligible:
            continue
        row = by_digest.get(claim.eligibility_ref)
        invocation = invocation_map[claim.invocation_id]
        if (row is None or row.arm != claim.arm or row.measurement_ref != claim.measurement_ref
                or row.build_sha256 != manifest.build_sha256 or row.source_sha256 != claim.raw_source_sha256
                or row.kind != invocation.kind or not row.actual_execution_attested
                or (row.kind == "replay" and row.original_live_receipt_sha256 is None)):
            raise ValueError("forged/stale evaluation eligibility claim")
        eligible_arms.add(claim.arm)
    state = seal.edition.state
    receipts = ()
    if "exposure" in refs:
        raw = read_metadata(root, refs["exposure"])
        if type(raw) is not list or len(raw) > 7:
            raise ValueError("bounded exposure metadata list required")
        receipts = tuple(ExposureReceipt.model_validate_json(json.dumps(row)) for row in raw)
        validate_exposure(authority, seal, receipts, pins.authority_sha256)
        state = "consumed_holdout"
    if state == "consumed_holdout" and not receipts:
        raise ValueError("consumed edition lacks actual exposure metadata")
    if manifest.edition_state != state:
        raise ValueError("stale declared edition state")
    if manifest.split == "heldout" and eligible_arms and state != "consumed_holdout":
        raise ValueError("heldout measurement eligibility lacks consumption receipts")
    if manifest.split == "heldout" and not eligible_arms <= {row.arm for row in receipts}:
        raise ValueError("eligible heldout arm lacks exposure receipt")
    # Contract S1.6: report D6's PRE-ACCESS input-exposure journal read-only. It never
    # changes `state`, never satisfies the legacy post-measurement checks above, and
    # is neither oracle/scoring permission nor eligibility evidence. The full pinned
    # verification (`verify_committed_exposure`) belongs to the input-access gate.
    from eval.runner.exposure_journal import exposure_status  # Lazy: that module imports this one.
    try:
        journal = exposure_status(root.absolute())
        input_committed = (journal.state == "COMMITTED" and journal.payload_permission_granted is False
                           and set(journal.exposed_arms) == set(ARMS)
                           and len(journal.exposed_arms) == len(ARMS))
    except (OSError, ValueError, TypeError, KeyError):
        input_committed = False
    missing_arms = sorted(set(ARMS) - eligible_arms)
    return {"schema_version": 1, "run_id": manifest.run_id,
            "input_exposure_committed": input_committed,
            "metadata_status": "CONSISTENT", "evaluation_status": "INCOMPLETE"
            if missing_arms or not costs["billing_fully_known"] else "METADATA_ELIGIBLE",
            "missing_arms": missing_arms, "edition_state": state, "custody": custody,
            "costs": costs, "verified_metadata_artifacts": sorted(refs),
            "unopened_artifact_count": len(manifest.artifacts) - len(refs),
            "payloads_opened": 0, "authorship_authenticated": False, "product_acceptance": False,
            "limitations": ["No oracle, input, result, utility, report or private-map payload is opened.",
                            "Payload hashes are declarations, not verified bytes.",
                            "Metadata attestations do not authenticate identity, execution or permissions.",
                            "Preflight does not authorize unblinding or new experiments."]}
