"""Whole-index verifier regression SOURCE only; not executed in Dirty Mode."""
import base64
from dataclasses import replace
import json
from pathlib import Path

import pytest

from iac_review.explain import SelectionResult
from eval.model.assessment_capture import build_capture, write_private_capture
from eval.model.capture_index import export_digest, verify_capture_index
from eval.model.experiment import Attempt, Context, FindingLink, Observation, Result, canonical, digest
from eval.model.explanation_artifacts import ExplanationArtifact, digest as artifact_digest
from eval.model.provenance import export_bundle
from eval.runner.scoring import ArmRow


def _case(tmp_path: Path, *, raw=b"unverified private generated text", status="ok", missing_l=False):
    context = Context("a" * 64, "b" * 64, "c" * 64, "d" * 64)
    base = ArmRow(case_id="1" * 32, resource_id="2" * 32, rule_id="R2", arm="D", status="ok",
                  applicability="supported", outcome="introduced_risk", reason_code="synthetic_fixture",
                  decision_fact_ids=("4" * 32,), required_limitation_ids=("indeterminate",),
                  source_sha256=context.source_sha256, build_sha256=context.build_sha256,
                  measurement_ref="sha256:" + "0" * 64)

    def attempt(arm, number, terminal):
        return Attempt(attempt_id=number * 32, arm=arm, status=terminal, duration_ms=1,
            input_tokens=0, output_tokens=0, known_usd="0", unresolved_usd_upper="0",
            billing_known=terminal != "timeout", hashes=tuple(sorted({
                "build": context.build_sha256, "corpus": context.corpus_sha256, "projection": "e" * 64,
                "prompt": "f" * 64, "input": "0" * 64, "model": "1" * 64,
                "config": context.config_sha256}.items())),
            response_sha256=digest(raw) if arm == "P" else digest("finite fixture summary"),
            price_sha256="2" * 64, usage_sha256="3" * 64, requires_reconciliation=terminal == "timeout")

    selection = SelectionResult(accepted=True, text="finite fixture summary", source="validated_selection",
        reason_code="valid_finite_selection", selected_fact_ids=("4" * 32,), limitation_ids=("indeterminate",))
    l_obs = Observation("L", "3" * 32, "not_run" if missing_l else "ok", "synthetic_fixture",
        None if missing_l else attempt("L", "5", "ok"), selection=None if missing_l else selection,
        fact_ids=("4" * 32,), required_limitation_ids=("indeterminate",), baseline_words=3,
        rendered_words=None if missing_l else 3)
    p_obs = Observation("P", "3" * 32, status, "synthetic_fixture", attempt("P", "6", status),
        fact_ids=("4" * 32,), required_limitation_ids=("indeterminate",),
        private_response=raw, private_response_complete=True)
    result = Result(context, (base,), digest(canonical([base.model_dump(mode="json")])),
        (FindingLink("3" * 32, base.case_id, base.resource_id, "R2"),), (l_obs, p_obs), (), "{}")
    bundle = export_bundle(result)
    out = tmp_path / "private"
    receipt = write_private_capture(build_capture(result, generator_actor_ids=("7" * 32,)), out)
    return out, bundle, receipt["index_sha256"]


def _rewrite_index(out: Path, change) -> str:
    index = json.loads((out / "artifact-index.json").read_bytes())
    change(index)
    data = canonical(index).encode("ascii") + b"\n"
    (out / "artifact-index.json").write_bytes(data)
    state = json.loads((out / "capture-state.json").read_bytes())
    state["index_sha256"] = digest(data)
    (out / "capture-state.json").write_bytes(canonical(state).encode("ascii"))
    return digest(data)


def _verify(out, bundle, pin):
    return verify_capture_index(out, bundle, expected_export_sha256=export_digest(bundle), expected_index_sha256=pin)


def test_whole_capture_is_structurally_verified_but_never_authenticated(tmp_path: Path) -> None:
    """Catches index verification being confused with semantic/live/identity admission."""
    out, bundle, pin = _case(tmp_path)
    verified = _verify(out, bundle, pin)
    assert verified.status == "verified" and verified.assessment_inputs_complete is True
    assert len(verified.artifacts) == len(verified.p_outcomes) == len(verified.l_receipts) == 1
    assert verified.live_eligible is False and verified.semantic_assessment_complete is False
    assert verified.identity_authenticated is False and verified.origin_authenticated is False
    assert "unverified private generated text" not in verified.model_dump_json()
    assert len(verified.all_attempt_ids) == 2


def test_disabled_missing_pin_and_legacy_exports_stay_incomplete(tmp_path: Path, monkeypatch) -> None:
    """Catches guessed paths/pins or legacy joins being promoted into complete capture."""
    from eval.model import capture_index

    out, bundle, _ = _case(tmp_path)
    def forbidden(*args, **kwargs):
        raise AssertionError("incomplete metadata must not open capture files")
    monkeypatch.setattr(capture_index, "read_source_bytes", forbidden)
    assert verify_capture_index(None, bundle, expected_export_sha256=export_digest(bundle)).reasons == (
        "private_capture_disabled",)
    assert verify_capture_index(out, bundle, expected_export_sha256=export_digest(bundle)).status == "incomplete"
    observations = json.loads(bundle.observations_json)
    for row in observations:
        row.pop("D_row_sha256")
    raw = canonical(observations)
    provenance = json.loads(bundle.provenance_json)
    provenance["observations_sha256"] = digest(raw)
    legacy = replace(bundle, observations_json=raw, provenance_json=canonical(provenance))
    assert verify_capture_index(out, legacy, expected_export_sha256=export_digest(legacy)).reasons == (
        "legacy_finding_catalog_missing",)


def test_removed_failed_outcome_is_rejected_even_after_index_rehash(tmp_path: Path) -> None:
    """Catches cherry-picking a failed P entry while retaining an apparently valid index hash."""
    out, bundle, _ = _case(tmp_path, status="error")
    pin = _rewrite_index(out, lambda index: index.update(outcomes=[]))
    with pytest.raises(ValueError, match="outcome_omission"):
        _verify(out, bundle, pin)


@pytest.mark.parametrize("damage", ["missing", "extra", "pending", "catalog-escape"])
def test_closed_inventory_refuses_missing_extra_pending_and_foreign_files(tmp_path: Path, damage: str) -> None:
    """Catches partial capture acceptance or index-supplied path traversal."""
    out, bundle, pin = _case(tmp_path)
    if damage == "missing":
        next(out.glob("artifact-*.json")).unlink()
    elif damage == "extra":
        (out / "foreign.json").write_bytes(b"must not be opened")
    elif damage == "pending":
        (out / ".capture-state.pending").write_bytes(b"partial")
    else:
        pin = _rewrite_index(out, lambda index: index["files"].update({"../foreign.json": "0" * 64}))
    with pytest.raises(ValueError):
        _verify(out, bundle, pin)


@pytest.mark.parametrize("field", ["raw_input_sha256", "projection_sha256", "build_sha256", "finding_id", "fact_ids"])
def test_rehashed_foreign_provenance_or_catalog_cannot_replace_pinned_attempt(tmp_path: Path, field: str) -> None:
    """Catches raw/projection conflation, foreign finding IDs and altered safe fact catalogues."""
    out, bundle, _ = _case(tmp_path)
    path = next(out.glob("artifact-*.json"))
    raw = json.loads(path.read_bytes())
    raw[field] = ["8" * 32] if field == "fact_ids" else "8" * (32 if field == "finding_id" else 64)
    artifact = ExplanationArtifact.model_validate_json(canonical(raw))
    path.write_bytes(canonical(raw).encode("ascii"))
    def change(index):
        index["files"][path.name] = digest(path.read_bytes())
        index["outcomes"][0]["artifact_sha256"] = artifact_digest(artifact)
    pin = _rewrite_index(out, change)
    with pytest.raises(ValueError):
        _verify(out, bundle, pin)


def test_diagnostic_tamper_is_not_hidden_by_rehashed_files(tmp_path: Path) -> None:
    """Catches changed failed/unsafe output after all superficial index hashes are updated."""
    out, bundle, _ = _case(tmp_path, raw=b"control\x1b[31m", status="invalid")
    path = next(out.glob("diagnostic-*.json"))
    raw = json.loads(path.read_bytes())
    changed = b"changed unsafe output"
    raw.update(response_prefix_base64=base64.b64encode(changed).decode("ascii"),
               retained_bytes=len(changed), retained_prefix_sha256=digest(changed))
    path.write_bytes(canonical(raw).encode("ascii"))
    pin = _rewrite_index(out, lambda index: index["files"].update({path.name: digest(path.read_bytes())}))
    with pytest.raises(ValueError, match="diagnostic_response_mismatch"):
        _verify(out, bundle, pin)


@pytest.mark.parametrize("mode", ["diagnostic", "missing-L", "timeout"])
def test_complete_integrity_never_erases_incomplete_assessment_inputs(tmp_path: Path, mode: str) -> None:
    """Catches diagnostics, missing finite counts or timed-out P text being called fully assessable."""
    out, bundle, pin = _case(tmp_path, raw=b"bad\xff" if mode == "diagnostic" else b"private text",
                             missing_l=mode == "missing-L", status="timeout" if mode == "timeout" else "ok")
    verified = _verify(out, bundle, pin)
    assert verified.status == "verified" and verified.assessment_inputs_complete is False
    assert verified.reasons and verified.live_eligible is False


def test_wrong_external_export_pin_refuses_all_self_rehashed_evidence(tmp_path: Path) -> None:
    """Catches authenticating a locally rewritten index/export solely by adjacent hashes."""
    out, bundle, pin = _case(tmp_path)
    with pytest.raises(ValueError, match="export_pin_mismatch"):
        verify_capture_index(out, bundle, expected_export_sha256="0" * 64, expected_index_sha256=pin)
