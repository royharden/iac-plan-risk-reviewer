"""Pure finite joins and observer DATA, never operational contexts."""

from copy import deepcopy
from dataclasses import FrozenInstanceError
from pathlib import PureWindowsPath

import pytest

from . import fixture_data as data
from .origin_data import OriginCase


@pytest.fixture
def api():
    from runtime_v1 import errors, metadata_backend, origin_validation

    return origin_validation, metadata_backend, errors


@pytest.fixture
def case(api):
    return OriginCase(api[1].Metadata)


def test_positive_finite_join_returns_immutable_data_only(api, case):
    record = api[0].validate_origin(case.facts_raw, case, deepcopy(case.process))
    for field in ("facts", "manifest", "grant", "invocation", "anchor", "ownership"):
        assert getattr(record, field + "_raw") == getattr(case, field + "_raw")
    assert len(case.digest_calls) == 32
    assert set(case.digest_calls) == set(case.digests)
    assert not hasattr(record, "effect_window")
    with pytest.raises(FrozenInstanceError):
        record.facts_raw = b"caller mutation"


@pytest.mark.parametrize(
    "field,value",
    [
        ("pid", True),
        ("pid", 0),
        ("pid", -1),
        ("parent_pid", False),
        ("parent_pid", 101),
        ("image", "C:\\INERT\\wrong.exe"),
        ("image_sha256", "f" * 64),
        ("cwd", "relative"),
        ("cwd", "C:/wrong"),
        ("argv", []),
        ("argv", ["x"] * 65),
        ("argv", [True]),
        ("argv", ["x\x00y"]),
        ("argv", ["x" * 8193]),
        ("environment", {}),
        ("environment", {"X": True}),
        ("environment", {"": "value"}),
        ("environment", {"X=Y": "value"}),
        ("environment", {"X": "x\x00y"}),
        ("environment", {"X": "x" * 8193}),
    ],
)
def test_process_exact_types_bounds_and_interpreter(api, case, field, value):
    api[0].validate_process(deepcopy(case.process))
    process = deepcopy(case.process)
    process[field] = value
    with pytest.raises(api[2].Denied):
        api[0].validate_process(process)


@pytest.mark.parametrize(
    "field,value",
    [
        ("pid", 103),
        ("parent_pid", 104),
        ("argv", ["different-inert-data"]),
        ("environment", {"OTHER": "data"}),
        ("cwd", "C:\\INERT\\other"),
    ],
)
def test_observed_process_must_match_external_data(api, case, field, value):
    process = deepcopy(case.process)
    process[field] = value
    with pytest.raises(api[2].Denied):
        api[0].validate_origin(case.facts_raw, case, process)


@pytest.mark.parametrize(
    "stage,field,value",
    [
        ("ownership", "runroot", "C:\\INERT\\other"),
        ("ownership", "source_tree", "f" * 40),
        ("manifest", "source_commit", "f" * 40),
        ("manifest", "watchdog_seconds", True),
        ("manifest", "junction_timeout_seconds", 20.0),
        ("grant", "purpose", "construction-only"),
        ("grant", "source_tree", "f" * 40),
        ("anchor", "runroot", "C:\\INERT\\other"),
        ("anchor", "schema", "wrong-inert-schema"),
        ("invocation", "source_tree", "f" * 40),
        ("invocation", "purpose", "construction-only"),
        ("invocation", "launcher_sha256", "f" * 64),
    ],
)
def test_semantic_join_negative_with_digest_edges_rebound(api, case, stage, field, value):
    getattr(case, stage)[field] = value
    case.rebind()
    with pytest.raises(api[2].Denied):
        api[0].validate_origin(case.facts_raw, case, case.process)


@pytest.mark.parametrize(
    "fault",
    [
        "alias",
        "case-alias",
        "inside-root",
        "bad-invocation-hash",
        "ownership-hash",
        "harness-bytes",
        "interpreter-bytes",
        "launcher-bytes",
        "source32-digest",
        "noncanonical-manifest",
        "changed-metadata",
        "nonordinary-file",
    ],
)
def test_external_paths_bytes_and_stable_metadata(api, case, fault):
    if fault == "alias":
        case.facts["grant_path"] = case.facts["manifest_path"]
    elif fault == "case-alias":
        case.facts["grant_path"] = case.facts["manifest_path"].upper()
    elif fault == "inside-root":
        case.facts["source_directory"] = case.manifest["runroot"] + "\\inside"
    elif fault == "bad-invocation-hash":
        case.facts["invocation_sha256"] = "f" * 64
    elif fault == "ownership-hash":
        case.facts["ownership_sha256"] = "f" * 64
    elif fault == "source32-digest":
        first = next(iter(case.digests))
        case.digests[first] = "f" * 64
    elif fault == "changed-metadata":
        case.changed_after_read.add(case.facts["manifest_path"])
    elif fault == "nonordinary-file":
        path = case.facts["manifest_path"]
        case.rows[path] = api[1].Metadata(path, "symlink", "inert-link", "C:\\INERT\\other")
    else:
        if fault == "harness-bytes":
            path = str(PureWindowsPath(case.facts["source_directory"]) / "context.py")
        elif fault == "interpreter-bytes":
            path = case.manifest["interpreter"]["path"]
        elif fault == "launcher-bytes":
            path = case.invocation["launcher_path"]
        else:
            path = case.facts["manifest_path"]
        case.files[path] += b" "
    with pytest.raises(api[2].Denied):
        api[0].validate_origin(case.serialize_facts(), case, case.process)


def observer_case(api):
    manifest = data.original_documents({"context.py": "a" * 64})[0]
    slot = manifest["slots"][0]
    full = data.original_relation(manifest, slot)
    relation = {
        key: full[key]
        for key in (
            "fixture_root",
            "target",
            "link",
            "physical",
            "logical",
            "checked_ordinary_ancestors",
        )
    }
    pending = {
        "slot": slot,
        "relation": relation,
        "target_identity": "INERT-stable-target",
        "pre_sha256": "a" * 64,
    }
    calls = []

    class Backend:
        def __init__(self):
            self.changes = {}
            self.absent = False

        def metadata(self, path):
            calls.append(path)
            if path in self.changes:
                return self.changes[path]
            if path == relation["link"]:
                return api[1].Metadata(
                    path,
                    "absent" if self.absent else "symlink",
                    "INERT-link",
                    None if self.absent else relation["target"],
                )
            return api[1].Metadata(path, "directory", "INERT-stable-target")

    return pending, relation, Backend(), calls


@pytest.mark.parametrize("known_error", [False, True])
def test_owned_observer_known_outcomes_as_injected_data(api, known_error):
    pending, relation, backend, _ = observer_case(api)
    backend.absent = known_error
    error = OSError("inert-original-error") if known_error else None
    result = api[0].observe_owned(pending, relation, None, error, backend, child_terminated=True)
    assert result["known"] is True
    assert result["target_identity"] == pending["target_identity"]
    assert result["link_kind"] == ("absent" if known_error else "symlink")
    assert result["pre_sha256"] == pending["pre_sha256"]
    # This returned dictionary models facts; it is not operational authority.
    assert not hasattr(result, "effect_window")


@pytest.mark.parametrize(
    "fault",
    [
        "target",
        "kind",
        "link-target",
        "absent-success",
        "termination",
        "relation",
        "prehash",
        "slot",
        "error-type",
    ],
)
def test_owned_observer_uncertainty_refuses_without_context(api, fault):
    pending, relation, backend, calls = observer_case(api)
    error = OSError("inert-original-error")
    terminated = True
    if fault == "target":
        backend.changes[relation["target"]] = api[1].Metadata(
            relation["target"], "directory", "foreign"
        )
    elif fault in ("kind", "link-target"):
        backend.changes[relation["link"]] = api[1].Metadata(
            relation["link"],
            "file" if fault == "kind" else "symlink",
            "inert-link",
            "C:\\INERT\\foreign",
        )
    elif fault == "absent-success":
        error = None
        backend.absent = True
    elif fault == "termination":
        terminated = False
    elif fault == "relation":
        relation = dict(relation, logical="C:\\INERT\\foreign")
    elif fault == "prehash":
        pending["pre_sha256"] = "NOT-A-HASH"
    elif fault == "slot":
        pending["slot"] = dict(pending["slot"], kind="foreign")
    else:
        error = "not-an-exception"
    with pytest.raises(api[2].Unknown) as caught:
        api[0].observe_owned(pending, relation, None, error, backend, child_terminated=terminated)
    if isinstance(error, BaseException):
        assert caught.value.__cause__ is error
    if fault in ("slot", "error-type"):
        assert calls == []
