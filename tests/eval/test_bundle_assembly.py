"""Unexecuted assembly regression SOURCE; fictional public metadata, no hidden gold.

The preflight stub in write/rollback tests isolates assembly mechanics. It is not
custody authentication or evidence that a corpus/measurement was ever executed.
"""
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path

import pytest

from iac_review.contracts.manifest import ArtifactRef, ComponentVersion, RunManifest
from eval.runner import bundle
from eval.runner.bundle import (
    AssemblySelection, ReleaseAuthorization, ReleasedArtifact, assemble, read_control,
    root_digest, select_artifacts,
)
from eval.runner.custody import metadata_digest
from eval.runner.preflight import PreflightPins

H, B, C = "a" * 64, "b" * 64, "c" * 64


def public_manifest(artifact_hash=H, artifact_size=128, *, state="sealed"):
    return RunManifest(
        run_id="public-assembly-test", edition_id="public-edition", edition_state=state,
        split="dev", build_sha256=B, policy_sha256=H, authority_sha256=H,
        semantic_suite_sha256=H, eligibility_sha256=H,
        components=(ComponentVersion(component_id="source", kind="source", name="public-test",
                                      version="fictional-v1", sha256=B),),
        cases=(), invocations=(), attempts=(), eligibility=(), artifacts=(
            ArtifactRef(artifact_id="authority", role="authority", path="metadata/custody-authority.json",
                        sha256=artifact_hash, bytes_upper=artifact_size),
            ArtifactRef(artifact_id="public-synthetic", role="oracle", path="private/synthetic/oracle/public.json",
                        sha256=C, bytes_upper=128),
            ArtifactRef(artifact_id="never-copy-map", role="private_map", path="private/maps/map.json",
                        sha256=H, bytes_upper=128)))


def authorization(manifest, **updates):
    now = datetime.now(timezone.utc)
    values = dict(run_manifest_sha256=metadata_digest(manifest), edition_id=manifest.edition_id,
                  edition_state="consumed_holdout", custodian="test-registry/custodian",
                  authorized_by="test-registry/release-owner", release_record_sha256=H,
                  exposure_artifact_sha256=H, synthetic_only_attested=True,
                  secret_free_attested=True, owned_project_attested=True,
                  valid_from=now - timedelta(minutes=1), valid_until=now + timedelta(minutes=1),
                  artifacts=(ReleasedArtifact(artifact_id="public-synthetic", role="oracle", sha256=C),))
    return ReleaseAuthorization(**(values | updates))


def test_default_metadata_selection_never_selects_payload_or_private_map():
    manifest = public_manifest()
    selected = select_artifacts(manifest, False, None, None, "sealed")
    assert [row.role for row in selected] == ["authority"]


def test_payload_opt_in_without_external_pin_is_refused():
    manifest = public_manifest(state="consumed_holdout")
    with pytest.raises(ValueError, match="externally pinned"):
        select_artifacts(manifest, True, None, None, "consumed_holdout")
    release = authorization(manifest)
    with pytest.raises(ValueError, match="externally pinned"):
        select_artifacts(manifest, True, release, H, "consumed_holdout")


def test_only_consumed_explicit_synthetic_scope_can_be_selected():
    manifest = public_manifest(state="consumed_holdout")
    release = authorization(manifest)
    selected = select_artifacts(manifest, True, release, metadata_digest(release), "consumed_holdout")
    assert {row.artifact_id for row in selected} == {"authority", "public-synthetic"}
    with pytest.raises(ValueError, match="consumed"):
        select_artifacts(manifest, True, release, metadata_digest(release), "sealed")
    with pytest.raises(ValueError):
        ReleasedArtifact(artifact_id="never-copy-map", role="private_map", sha256=H)
    wrong_path = manifest.artifacts[1].model_copy(update={"path": "private/credentials/public.json"})
    changed = manifest.model_copy(update={"artifacts": (manifest.artifacts[0], wrong_path)})
    changed_release = authorization(changed)
    with pytest.raises(ValueError, match="allowlist"):
        select_artifacts(changed, True, changed_release, metadata_digest(changed_release), "consumed_holdout")


def test_expired_release_refused_before_any_payload_read():
    manifest = public_manifest(state="consumed_holdout")
    now = datetime.now(timezone.utc)
    release = authorization(manifest, valid_from=now - timedelta(days=2), valid_until=now - timedelta(days=1))
    with pytest.raises(ValueError, match="expired"):
        select_artifacts(manifest, True, release, metadata_digest(release), "consumed_holdout")


def fixture_selection(tmp_path):
    root = tmp_path / "source-bundle"
    (root / "metadata").mkdir(parents=True)
    raw = b'{"public_schema_test":true}'  # Not a valid independent custody record.
    (root / "metadata" / "custody-authority.json").write_bytes(raw)
    manifest = public_manifest(sha256(raw).hexdigest(), len(raw))
    out = tmp_path / "assembled"
    pins = PreflightPins(run_manifest_sha256=metadata_digest(manifest), authority_sha256=H,
                         semantic_suite_sha256=H, eligibility_sha256=H)
    selection = AssemblySelection(run_id=manifest.run_id, run_manifest_sha256=metadata_digest(manifest),
                                  source_root_sha256=root_digest(root), output_root_sha256=root_digest(out))
    return root, out, manifest, pins, selection


def test_metadata_only_assembly_never_opens_unselected_payload(tmp_path, monkeypatch):
    root, out, manifest, pins, selection = fixture_selection(tmp_path)
    monkeypatch.setattr(bundle, "preflight", lambda *args: {"edition_state": "sealed"})
    original_open = Path.open
    def guarded(path, *args, **kwargs):
        if "synthetic" in path.parts or "maps" in path.parts:
            raise AssertionError("metadata-only assembly tried to open a payload")
        return original_open(path, *args, **kwargs)
    monkeypatch.setattr(Path, "open", guarded)
    receipt = assemble(root, out, manifest, pins, selection, metadata_digest(selection))
    assert receipt.mode == "metadata_only" and receipt.payloads_included == 0
    assert set(receipt.omitted_artifact_ids) == {"public-synthetic", "never-copy-map"}
    assert not (out / "private").exists()
    assert json.loads((out / "assembly-state.json").read_bytes())["state"] == "COMPLETE"
    raw = (out / "assembly-receipt.json").read_bytes()
    assert (out / "assembly-receipt.sha256").read_text().strip() == sha256(raw).hexdigest()
    assert receipt.external_authorization_authenticated is False


def test_wrong_root_scope_or_existing_destination_refused(tmp_path, monkeypatch):
    root, out, manifest, pins, selection = fixture_selection(tmp_path)
    def refuse(*args):
        raise AssertionError("unapproved roots reached preflight")
    monkeypatch.setattr(bundle, "preflight", refuse)
    changed = selection.model_copy(update={"source_root_sha256": C})
    with pytest.raises(ValueError, match="approved roots"):
        assemble(root, out, manifest, pins, changed, metadata_digest(changed))
    assert not out.exists()
    out.mkdir()
    with pytest.raises(ValueError, match="fresh"):
        assemble(root, out, manifest, pins, selection, metadata_digest(selection))


def test_hash_mismatch_leaves_destination_absent(tmp_path, monkeypatch):
    root, out, manifest, pins, selection = fixture_selection(tmp_path)
    monkeypatch.setattr(bundle, "preflight", lambda *args: {"edition_state": "sealed"})
    (root / "metadata" / "custody-authority.json").write_text("{}")
    with pytest.raises(ValueError, match="hash"):
        assemble(root, out, manifest, pins, selection, metadata_digest(selection))
    assert not out.exists()


def test_publication_failure_retains_aborted_and_rolls_back_owned_files(tmp_path, monkeypatch):
    root, out, manifest, pins, selection = fixture_selection(tmp_path)
    monkeypatch.setattr(bundle, "preflight", lambda *args: {"edition_state": "sealed"})
    def fail(*args):
        raise OSError("fictional publication failure")
    monkeypatch.setattr(bundle.os, "replace", fail)
    with pytest.raises(OSError):
        assemble(root, out, manifest, pins, selection, metadata_digest(selection))
    assert json.loads((out / "assembly-state.json").read_bytes())["state"] == "ABORTED"
    assert not (out / "assembly-receipt.json").exists()
    assert not (out / "metadata").exists()
    assert (root / "metadata" / "custody-authority.json").read_bytes() == b'{"public_schema_test":true}'


def test_cli_control_name_cannot_point_at_oracle(tmp_path, monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("invalid control filename opened a file")
    monkeypatch.setattr(Path, "open", refuse)
    with pytest.raises(ValueError, match="allowlisted"):
        read_control(tmp_path, "../private/oracle.json")
