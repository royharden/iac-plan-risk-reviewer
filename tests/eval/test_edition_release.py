"""Public synthetic metadata regressions, SOURCE ONLY; no oracle or actual edition.

These examples exercise refusal ordering and measured failure distinctions. They
cannot supply independent execution/custody, approved payloads or product acceptance.
"""
import json
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from iac_review.contracts.manifest import RunManifest
from eval.runner import edition_release as release
from eval.runner.custody import metadata_digest
from eval.runner.scoring import ARMS

H = "a" * 64


@pytest.fixture
def edition_metadata():
    # A single public metadata case is sufficient for this pure refusal gate.
    # It deliberately cannot satisfy the real independent 24-case custody gate.
    components = [{"component_id": kind, "kind": kind, "name": kind,
                   "version": "synthetic", "sha256": H}
                  for kind in ("source", "parser", "rules", "prompt", "config", "corpus")]
    invocations = [{"invocation_id": arm, "arm": arm, "status": "error",
                    "kind": "live" if arm in {"L", "P", "M"} else "executed",
                    "case_ids": ["case"], "config_component_id": "config",
                    "version_component_id": "rules", "attempt_ids": [],
                    "all_attempts_attested": True} for arm in ARMS]
    claims = [{"arm": arm, "invocation_id": arm, "measurement_ref": "measurement-" + arm,
               "raw_source_sha256": H, "eligibility_ref": H, "claimed_eligible": True}
              for arm in ARMS]
    artifacts = [{"artifact_id": arm, "role": "measurements",
                  "path": "private/synthetic/measurements/" + arm + ".json",
                  "sha256": H, "bytes_upper": 4096} for arm in ARMS]
    manifest = RunManifest.model_validate_json(json.dumps({
        "run_id": "synthetic", "edition_id": "edition", "edition_state": "consumed_holdout",
        "split": "heldout", "build_sha256": H, "policy_sha256": H,
        "authority_sha256": H, "semantic_suite_sha256": H, "eligibility_sha256": H,
        "components": components, "cases": [{"case_id": "case", "split": "heldout",
            "configuration_id": "config-case", "family_id": "family", "mutation_lineage": "mutation",
            "raw_source_sha256": H}], "invocations": invocations, "artifacts": artifacts,
        "eligibility": claims,
    }))
    rows = (("case", "resource", "R1"),)
    completion = release.CompletionReference(
        run_manifest_sha256=metadata_digest(manifest), authority_sha256=H,
        seal_sha256=H, exposure_sha256=H, eligibility_sha256=H, rubric_sha256=H,
        row_inventory=rows, row_inventory_sha256=release._row_hash(rows),
        arms=tuple(release.ArmCompletion(arm=arm, artifact_id=arm, artifact_sha256=H,
                    score_status="FAIL", score_result_sha256=H, expected_rows=1) for arm in ARMS),
        consumed_at=datetime(2026, 10, 23, tzinfo=timezone.utc))
    return manifest, completion


def repin(manifest, completion):
    return completion.model_copy(update={"run_manifest_sha256": metadata_digest(manifest)})


def test_measured_error_and_fail_are_not_missing_measurement(edition_metadata):
    manifest, completion = edition_metadata
    # Pure metadata gate only: no claim that full preflight or release passed.
    assert release.check_completion(manifest, completion, metadata_digest(completion)) is None


@pytest.mark.parametrize("status", ["not_run", "pending", "unmapped"])
def test_unmeasured_terminal_inventory_refuses_even_with_fresh_pin(edition_metadata, status):
    manifest, completion = edition_metadata
    first = manifest.invocations[0].model_copy(update={"status": status})
    manifest = manifest.model_copy(update={"invocations": (first, *manifest.invocations[1:])})
    completion = repin(manifest, completion)
    with pytest.raises(ValueError, match="unmeasured"):
        release.check_completion(manifest, completion, metadata_digest(completion))


@pytest.mark.parametrize("kind", ["mock", "unverified"])
def test_mock_or_unverified_execution_never_closes_gate(edition_metadata, kind):
    manifest, completion = edition_metadata
    first = manifest.invocations[0].model_copy(update={"kind": kind})
    manifest = manifest.model_copy(update={"invocations": (first, *manifest.invocations[1:])})
    completion = repin(manifest, completion)
    with pytest.raises(ValueError, match="unmeasured"):
        release.check_completion(manifest, completion, metadata_digest(completion))


def test_missing_arm_not_repaired_by_duplicate_arm(edition_metadata):
    manifest, completion = edition_metadata
    completion = completion.model_copy(update={"arms": (completion.arms[0], *completion.arms[:-1])})
    with pytest.raises(ValueError, match="distinct"):
        release.check_completion(manifest, completion, metadata_digest(completion))


def test_foreign_external_pin_refuses_before_any_metadata_access(edition_metadata, tmp_path, monkeypatch):
    manifest, completion = edition_metadata
    root = tmp_path / "private-source"
    root.mkdir()
    parent = tmp_path / "gold" / "editions"
    parent.mkdir(parents=True)
    out = parent / ("1" * 32)
    from eval.runner.bundle import AssemblySelection, root_digest
    from eval.runner.preflight import PreflightPins
    pins = PreflightPins(run_manifest_sha256=metadata_digest(manifest), authority_sha256=H,
                         semantic_suite_sha256=H, eligibility_sha256=H)
    selection = AssemblySelection(run_id=manifest.run_id,
        run_manifest_sha256=metadata_digest(manifest), source_root_sha256=root_digest(root),
        output_root_sha256=root_digest(out))
    def forbidden(*args, **kwargs):
        raise AssertionError("refused release must not read metadata or payloads")
    monkeypatch.setattr(release, "preflight", forbidden)
    monkeypatch.setattr(release, "_read_verified", forbidden)
    interval = SimpleNamespace(valid_from=datetime(2020, 1, 1, tzinfo=timezone.utc),
                               valid_until=datetime(2030, 1, 1, tzinfo=timezone.utc))
    with pytest.raises(ValueError, match="externally pinned"):
        release.prepare_consumed_edition(root, out, manifest, pins, selection,
            metadata_digest(selection), interval, H, completion, "b" * 64)
    assert not out.exists()


def test_dropped_case_and_missing_eligibility_refuse(edition_metadata):
    manifest, completion = edition_metadata
    changed = manifest.model_copy(update={"eligibility": manifest.eligibility[1:]})
    completion = repin(changed, completion)
    with pytest.raises(ValueError, match="genuine eligibility"):
        release.check_completion(changed, completion, metadata_digest(completion))
    bad = completion.model_copy(update={"row_inventory": (("foreign", "resource", "R1"),)})
    with pytest.raises(ValueError, match="inventory"):
        release.check_completion(changed, bad, metadata_digest(bad))


def test_inconsistent_unfiltered_score_pin_refuses(edition_metadata):
    manifest, completion = edition_metadata
    changed = completion.arms[0].model_copy(update={"score_result_sha256": "b" * 64})
    completion = completion.model_copy(update={"arms": (changed, *completion.arms[1:])})
    with pytest.raises(ValueError, match="unfiltered"):
        release.check_completion(manifest, completion, metadata_digest(completion))
