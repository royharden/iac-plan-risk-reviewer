"""Opt-in private P capture using D7 wires, never a semantic assessment or public export."""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import re
from uuid import uuid4

from eval.model.experiment import Result, canonical, digest as bytes_digest
from eval.model.explanation_artifacts import (
    DecisionReference, ExplanationArtifact, digest as artifact_digest, text_digest,
)
from eval.model.provenance import export_bundle


@dataclass(frozen=True)
class PrivateCapture:
    artifacts: tuple[ExplanationArtifact, ...] = field(repr=False)
    # Diagnostic bytes are JSON/base64 data, not replacement ExplanationArtifact wires.
    diagnostics: tuple[tuple[str, str], ...] = field(repr=False)
    outcomes_json: str
    baseline_sha256: str
    origin: str
    live_eligible: bool = field(default=False, init=False)


def build_capture(result: Result, *, generator_actor_ids: tuple[str, ...],
                  origin: str = "mock") -> PrivateCapture:
    """No files or labels. Preserve every P outcome, including invalid/withheld output.

    Complete UTF-8 fitting the declared wire is stored EXACTLY as response text,
    including a JSON envelope. It is not joined/filtered model 'claims'. A future
    independent curator must supply all claim/context spans; capture labels none.
    Unsupported encoding/controls/size uses private diagnostics, never a sanitized
    pretend original or an invented successful explanation.
    """
    if origin not in ("mock", "unverified") or result.live_eligible:
        raise ValueError("capture_has_no_live_admission")
    if not 1 <= len(generator_actor_ids) <= 16 or len(set(generator_actor_ids)) != len(generator_actor_ids) \
            or any(not re.fullmatch(r"[0-9a-f]{32}", value) for value in generator_actor_ids):
        raise ValueError("capture_generator_ids_invalid")
    bundle = export_bundle(result)  # Proves D snapshot invariance; no prose serialized.
    records = {row["attempt_id"]: row for row in json.loads(bundle.attempts_json)}
    links = {link.finding_id: link for link in result.links}
    baseline = {(row.case_id, row.resource_id, row.rule_id): row for row in result.baseline}
    artifacts = []
    diagnostics = []
    outcomes = []
    p_rows = [row for row in result.observations if row.arm == "P"]
    if len(p_rows) > 10_000:
        raise ValueError("capture_record_limit")
    for obs in p_rows:
        link = links.get(obs.finding_id)
        if link is None:
            raise ValueError("capture_finding_join_missing")
        if any(not re.fullmatch(r"[0-9a-f]{32}", value) for value in (link.case_id, link.finding_id)):
            raise ValueError("capture_opaque_case_and_finding_required")
        base = baseline[(link.case_id, link.resource_id, link.rule_id)]
        if base.outcome is None or base.source_sha256 != result.context.source_sha256 \
                or base.build_sha256 != result.context.build_sha256:
            raise ValueError("capture_D_binding_mismatch")
        attempt = obs.attempt
        if attempt is not None and attempt.arm != "P":
            raise ValueError("capture_foreign_attempt")
        outcome = {
            "case_id": link.case_id, "finding_id": link.finding_id,
            "generator_actor_ids": list(generator_actor_ids), "identity_authenticated": False,
            "attempt_id": attempt.attempt_id if attempt else None, "status": obs.status,
            "artifact_id": None, "artifact_sha256": None, "diagnostic_id": None,
            "live_eligible": False, "semantic_assessment_complete": False,
        }
        artifact = None
        capture_state = "response_unavailable"
        response = obs.private_response
        if response is not None and (type(response) is not bytes or len(response) > 65_536):
            raise ValueError("capture_response_byte_limit")
        if response is not None and obs.private_response_complete is not True:
            capture_state = "response_prefix_only"
        elif response is not None and attempt is not None and attempt.response_sha256 is not None:
            if bytes_digest(response) != attempt.response_sha256:
                raise ValueError("capture_response_digest_mismatch")
            hashes = dict(attempt.hashes)
            if hashes.get("build") != result.context.build_sha256:
                raise ValueError("capture_attempt_build_mismatch")
            try:
                text = response.decode("utf-8", errors="strict")
                artifact = ExplanationArtifact(
                    artifact_id=uuid4().hex, case_id=link.case_id, finding_id=link.finding_id,
                    attempt_id=attempt.attempt_id, generator_actor_ids=generator_actor_ids,
                    decision=DecisionReference(rule_id=base.rule_id, outcome=base.outcome,
                        immutable_outcome_sha256=bytes_digest(canonical(base.model_dump(mode="json")))),
                    origin=origin, raw_input_sha256=result.context.source_sha256,
                    projection_sha256=hashes["projection"], prompt_sha256=hashes["prompt"],
                    build_sha256=result.context.build_sha256, response_sha256=attempt.response_sha256,
                    attempt_record_sha256=bytes_digest(canonical(records[attempt.attempt_id])),
                    price_sha256=attempt.price_sha256, usage_sha256=attempt.usage_sha256,
                    # All P prose remains withheld from product use, including status ok.
                    explanation_withheld=True, prose=text, prose_sha256=text_digest(text),
                    fact_ids=obs.fact_ids, limitation_ids=obs.required_limitation_ids)
                capture_state = "exact_private_response"
            except (ValueError, UnicodeError):
                capture_state = "artifact_wire_rejected"
        elif response is not None:
            capture_state = "response_binding_incomplete"
        if artifact is not None:
            artifacts.append(artifact)
            outcome.update(artifact_id=artifact.artifact_id, artifact_sha256=artifact_digest(artifact))
        else:
            diagnostic_id = uuid4().hex
            diagnostic = canonical({
                "schema": 1, "private": True, "untrusted": True,
                "finding_id": link.finding_id, "attempt_id": attempt.attempt_id if attempt else None,
                "status": obs.status, "capture_state": capture_state,
                "raw_input_sha256": result.context.source_sha256,
                "response_sha256": attempt.response_sha256 if attempt else None,
                "response_capture_complete": obs.private_response_complete is True,
                "retained_bytes": len(response) if response is not None else 0,
                "retained_prefix_sha256": bytes_digest(response) if response is not None else None,
                "response_prefix_base64": base64.b64encode(response).decode("ascii")
                    if response is not None else None,
                "live_eligible": False, "semantic_assessment_complete": False,
            })
            diagnostics.append((diagnostic_id, diagnostic))
            outcome["diagnostic_id"] = diagnostic_id
        outcome["capture_state"] = capture_state
        outcomes.append(outcome)
    return PrivateCapture(tuple(artifacts), tuple(diagnostics), canonical(outcomes),
                          result.baseline_sha256, origin)


def write_private_capture(capture: PrivateCapture, out: Path) -> dict:
    """Fresh, separate caller-selected sink. Writes JSON data only, never HTML/text execution."""
    out = Path(os.path.abspath(out))
    if out.exists() or not out.parent.is_dir() or any(
        p.is_symlink() or (hasattr(p, "is_junction") and p.is_junction()) for p in (out, *out.parents)
    ):
        raise ValueError("fresh_private_capture_directory_required")
    payloads = {}
    for artifact in capture.artifacts:
        name = f"artifact-{artifact.artifact_id}.json"
        if name in payloads:
            raise ValueError("duplicate_capture_artifact")
        # JSON escapes preserve exact text on decoding while avoiding literal HTML
        # delimiters in storage; downstream worksheets must still escape as data.
        encoded = artifact.model_dump_json(indent=2).replace("<", "\\u003c").replace(
            ">", "\\u003e").replace("&", "\\u0026")
        payloads[name] = encoded.encode("utf-8") + b"\n"
    for diagnostic_id, data in capture.diagnostics:
        if not re.fullmatch(r"[0-9a-f]{32}", diagnostic_id):
            raise ValueError("capture_diagnostic_id_invalid")
        name = f"diagnostic-{diagnostic_id}.json"
        if name in payloads:
            raise ValueError("duplicate_capture_diagnostic")
        payloads[name] = data.encode("utf-8") + b"\n"
    index = canonical({
        "schema": 1, "private": True, "untrusted": True, "origin": capture.origin,
        "live_eligible": False, "semantic_assessment_complete": False,
        "baseline_sha256": capture.baseline_sha256,
        "outcomes": json.loads(capture.outcomes_json),
        "files": {name: bytes_digest(data) for name, data in sorted(payloads.items())},
        "artifact_count": len(capture.artifacts), "diagnostic_count": len(capture.diagnostics),
    }).encode("ascii") + b"\n"
    payloads["artifact-index.json"] = index
    index_hash = bytes_digest(index)
    if any(len(data) > 1024 * 1024 for data in payloads.values()) \
            or sum(map(len, payloads.values())) > 64 * 1024 * 1024:
        raise ValueError("private_capture_byte_limit")
    out.mkdir(mode=0o700, exist_ok=False)

    def write(name: str, data: bytes) -> None:
        descriptor = os.open(out / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())

    write("capture-state.json", b'{"state":"INCOMPLETE","private":true,"live_eligible":false}')
    for name, data in payloads.items():
        write(name, data)
    # Any interruption leaves INCOMPLETE; no cleanup/overwrite/reuse after failure.
    write(".capture-state.pending", canonical({
        "state": "WRITTEN", "private": True, "live_eligible": False,
        "semantic_truth_verified": False, "index_sha256": index_hash}).encode("ascii"))
    os.replace(out / ".capture-state.pending", out / "capture-state.json")
    return {"state": "WRITTEN", "private": True, "artifact_count": len(capture.artifacts),
            "diagnostic_count": len(capture.diagnostics), "index_sha256": index_hash,
            "live_eligible": False}
