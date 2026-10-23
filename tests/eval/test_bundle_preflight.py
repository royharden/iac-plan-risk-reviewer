"""Unexecuted public metadata regression SOURCE; no hidden input/label fixtures."""
import hashlib
from pathlib import Path

import pytest

from iac_review.contracts.manifest import (
    ArtifactRef, AttemptMetadata, CaseBinding, ComponentVersion, EvaluationEligibility,
    InvocationMetadata, RunManifest, relative_path,
)
from eval.runner.custody import metadata_digest
from eval.runner.preflight import PreflightPins, checked_path, preflight, read_metadata, validate_links

H = "a" * 64
B = "b" * 64
C = "c" * 64


def public_manifest():
    components = tuple(ComponentVersion(
        component_id=kind, kind=kind, name=f"public-{kind}", version="unverified-v1",
        sha256=B if kind == "source" else (C if kind == "corpus" else H))
        for kind in ("source", "parser", "rules", "prompt", "config", "corpus"))
    case = CaseBinding(case_id="public-case", split="dev", configuration_id="public-config",
                       family_id="public-family", mutation_lineage="public-mutation",
                       raw_source_sha256=H, safe_projection_sha256=C)
    invocation = InvocationMetadata(
        invocation_id="public-invocation", arm="D", status="ok", kind="mock",
        case_ids=(case.case_id,), config_component_id="config", version_component_id="rules",
        attempt_ids=("public-attempt",), all_attempts_attested=False)
    attempt = AttemptMetadata(
        attempt_id="public-attempt", invocation_id=invocation.invocation_id, arm="D",
        status="ok", kind="mock", raw_source_sha256=H, safe_projection_sha256=C,
        known_usd=None, billing_known=False, unresolved_usd_upper=None)
    return RunManifest(
        run_id="public-metadata-only", edition_id="public-edition", edition_state="sealed", split="dev",
        build_sha256=B, policy_sha256=H, authority_sha256=H, semantic_suite_sha256=H,
        eligibility_sha256=H, components=components, cases=(case,), invocations=(invocation,),
        attempts=(attempt,), artifacts=(), eligibility=())


@pytest.mark.parametrize("path", (
    "../oracle.json", "/outside.json", "C:/secret.json", "metadata/../oracle.json",
    "metadata\\seal.json", "metadata//seal.json", "metadata/CON.json", "metadata/seal.json.",
    "metadata/%2e%2e/oracle.json", "metadata/seal.json:stream",
))
def test_paths_reject_escape_device_stream_and_alias(path):
    with pytest.raises(ValueError):
        relative_path(path)


def test_private_map_cannot_be_an_outward_reference():
    with pytest.raises(ValueError, match="outward"):
        ArtifactRef(artifact_id="public-ref", role="private_map", path="private/maps.json",
                    sha256=H, bytes_upper=128, visibility="shareable")
    with pytest.raises(ValueError, match="private-map"):
        ArtifactRef(artifact_id="public-ref", role="report_shareable", path="shareable/private-map.json",
                    sha256=H, bytes_upper=128, visibility="shareable")


def test_unknown_cost_bounds_never_become_zero_total():
    result = validate_links(public_manifest())
    assert result["known_usd_decimal"] == "0"
    assert result["billing_fully_known"] is False
    assert result["unresolved_bounds_known"] is False
    assert result["unresolved_usd_upper_decimal"] is None


def test_missing_or_duplicate_attempt_receipts_and_projection_mismatch():
    manifest = public_manifest()
    with pytest.raises(ValueError, match="orphaned"):
        validate_links(manifest.model_copy(update={"invocations": ()}))
    altered = manifest.attempts[0].model_copy(update={"safe_projection_sha256": H})
    with pytest.raises(ValueError, match="projection"):
        validate_links(manifest.model_copy(update={"attempts": (altered,)}))
    with pytest.raises(ValueError, match="duplicate"):
        validate_links(manifest.model_copy(update={"attempts": manifest.attempts * 2}))


def test_mock_invocation_cannot_forge_eligible_status():
    manifest = public_manifest()
    claim = EvaluationEligibility(arm="D", invocation_id="public-invocation",
                                  measurement_ref="sha256:" + H, raw_source_sha256=H,
                                  eligibility_ref=H, claimed_eligible=True)
    with pytest.raises(ValueError, match="claims eligibility"):
        validate_links(manifest.model_copy(update={"eligibility": (claim,)}))


def test_artifact_case_aliases_and_wrong_split_reject():
    manifest = public_manifest()
    refs = tuple(ArtifactRef(artifact_id=f"ref-{i}", role="report_private", path=path,
                             sha256=H, bytes_upper=1)
                 for i, path in enumerate(("private/A.json", "private/a.json")))
    with pytest.raises(ValueError, match="path aliases"):
        validate_links(manifest.model_copy(update={"artifacts": refs}))
    with pytest.raises(ValueError, match="split"):
        validate_links(manifest.model_copy(update={"cases": (
            manifest.cases[0].model_copy(update={"split": "heldout"}),)}))


def test_symlink_payload_reference_is_refused_without_open(tmp_path, monkeypatch):
    ref = ArtifactRef(artifact_id="public-ref", role="oracle", path="private/oracle.json",
                      sha256=H, bytes_upper=10)
    original = Path.is_symlink
    monkeypatch.setattr(Path, "is_symlink", lambda path: path.name == "oracle.json" or original(path))
    with pytest.raises(ValueError, match="symlink"):
        checked_path(tmp_path, ref)


def test_payload_role_is_never_opened_by_metadata_reader(tmp_path, monkeypatch):
    ref = ArtifactRef(artifact_id="public-ref", role="oracle", path="private/oracle.json",
                      sha256=H, bytes_upper=10)
    def refuse(*args, **kwargs):
        raise AssertionError("payload opened during metadata preflight")
    monkeypatch.setattr(Path, "open", refuse)
    with pytest.raises(ValueError, match="allowlist"):
        read_metadata(tmp_path, ref)


def test_metadata_hash_and_declared_bound_are_checked(tmp_path):
    metadata = tmp_path / "metadata"
    metadata.mkdir()
    payload = b'{"public_schema_test":true}'
    (metadata / "custody-authority.json").write_bytes(payload)
    ref = ArtifactRef(artifact_id="public-ref", role="authority", path="metadata/custody-authority.json",
                      sha256=H, bytes_upper=128)
    with pytest.raises(ValueError, match="hash"):
        read_metadata(tmp_path, ref)
    small = ref.model_copy(update={"sha256": hashlib.sha256(payload).hexdigest(), "bytes_upper": 1})
    with pytest.raises(ValueError, match="bound"):
        read_metadata(tmp_path, small)


def test_external_scope_pin_is_checked_before_any_metadata_or_payload_open(tmp_path, monkeypatch):
    manifest = public_manifest()
    def refuse(*args, **kwargs):
        raise AssertionError("unapproved manifest read a file")
    monkeypatch.setattr(Path, "open", refuse)
    pins = PreflightPins(run_manifest_sha256=C, authority_sha256=H,
                         semantic_suite_sha256=H, eligibility_sha256=H)
    assert metadata_digest(manifest) != pins.run_manifest_sha256
    with pytest.raises(ValueError, match="externally approved"):
        preflight(tmp_path, manifest, pins)


def test_new_manifest_wires_are_strict_frozen_and_closed():
    manifest = public_manifest()
    with pytest.raises(ValueError):
        RunManifest.model_validate(manifest.model_dump() | {"secret_payload": "must-reject"})
    with pytest.raises(ValueError):
        manifest.run_id = "other"
