"""Shared backend logic through its explicit public inert observation seam."""

import hashlib
import stat

import pytest

from .metadata_data import FILE, PARENT, TARGET, Observations, snapshot


@pytest.fixture
def api():
    from runtime_v1 import errors, metadata_backend

    return metadata_backend, errors


def backend(api, observations):
    return api[0].LocalMetadataBackend(observations=observations)


def test_constructor_requires_complete_inert_interface_before_any_calls(api):
    observations = Observations()
    backend(api, observations)
    assert observations.calls == []

    class Partial:
        calls = 0

        def lstat(self, path):
            self.calls += 1
            raise AssertionError("invalid dependency invoked")

    partial = Partial()
    with pytest.raises(api[1].Denied):
        backend(api, partial)
    assert partial.calls == 0


@pytest.mark.parametrize(
    "mode,kind", [(stat.S_IFREG | 0o600, "file"), (stat.S_IFDIR | 0o700, "directory")]
)
def test_metadata_regular_and_directory(api, mode, kind):
    observations = Observations(initial=snapshot(mode=mode))
    result = backend(api, observations).metadata(FILE)
    assert result.path == FILE and result.kind == kind
    assert result.identity == "1:2" and result.link_target is None
    assert all(call[0] == "lstat" for call in observations.calls)


@pytest.mark.parametrize("kind,tag", [("symlink", 0xA000000C), ("junction", 0xA0000003)])
def test_metadata_link_target_read_twice_without_real_link(api, kind, tag):
    observations = Observations(initial=snapshot(attrs=0x400, tag=tag))
    result = backend(api, observations).metadata(FILE)
    assert result.kind == kind and result.link_target == TARGET
    assert len([call for call in observations.calls if call[0] == "readlink"]) == 2


def test_metadata_same_identity_retarget_is_unknown(api):
    observations = Observations(initial=snapshot(attrs=0x400, tag=0xA000000C))
    observations.targets = [TARGET, TARGET + "-changed"]
    with pytest.raises(api[1].Unknown):
        backend(api, observations).metadata(FILE)


def test_metadata_absent_is_explicit_initial_absence(api):
    observations = Observations()
    observations.initial_error = FileNotFoundError("inert-absence")
    result = backend(api, observations).metadata(FILE)
    assert result.kind == "absent" and result.path == FILE
    assert result.link_target is None


@pytest.mark.parametrize("error", [PermissionError("inert-permission"), OSError("inert-error")])
def test_metadata_initial_observation_failure_is_unknown(api, error):
    observations = Observations()
    observations.initial_error = error
    with pytest.raises(api[1].Unknown):
        backend(api, observations).metadata(FILE)


@pytest.mark.parametrize(
    "field,value",
    [
        ("st_dev", 0),
        ("st_dev", -1),
        ("st_dev", True),
        ("st_ino", 0),
        ("st_ino", -1),
        ("st_ino", False),
    ],
)
def test_metadata_plain_positive_identity(api, field, value):
    observations = Observations()
    setattr(observations.initial, field, value)
    with pytest.raises(api[1].Unknown):
        backend(api, observations).metadata(FILE)


@pytest.mark.parametrize(
    "mode,attrs,tag", [(stat.S_IFIFO | 0o600, 0, 0), (stat.S_IFREG | 0o600, 0x400, 12345)]
)
def test_metadata_special_or_unknown_reparse_is_unknown(api, mode, attrs, tag):
    observations = Observations(initial=snapshot(mode=mode, attrs=attrs, tag=tag))
    with pytest.raises(api[1].Unknown):
        backend(api, observations).metadata(FILE)


@pytest.mark.parametrize("raw", [b"", b"abcde", b"\x00\xff\r\n"])
def test_injected_read_and_exact_digest(api, raw):
    observations = Observations(raw)
    result = backend(api, observations).read_file(FILE, max(1, len(raw)))
    assert result == raw and type(result) is bytes
    assert ("read", max(1, len(raw)) + 1) in observations.calls
    assert any(call == ("lstat", PARENT) for call in observations.calls)
    assert sum(call == ("lstat", PARENT) for call in observations.calls) >= 4
    second = Observations(raw)
    assert backend(api, second).file_digest(FILE, len(raw)) == hashlib.sha256(raw).hexdigest()


@pytest.mark.parametrize("cap", [0, -1, True, 8 * 1024 * 1024 + 1])
def test_read_cap_exact_type_and_bound_before_reads(api, cap):
    observations = Observations()
    with pytest.raises(api[1].Denied):
        backend(api, observations).read_file(FILE, cap)
    assert observations.calls == []


@pytest.mark.parametrize(
    "stage,field,value",
    [
        ("fd", "st_mode", stat.S_IFDIR | 0o700),
        ("fd", "st_file_attributes", 0x400),
        ("fd", "st_ino", 999),
        ("fd", "st_size", 6),
        ("fd", "st_mtime_ns", 999),
        ("path", "st_mode", stat.S_IFDIR | 0o700),
        ("path", "st_file_attributes", 0x400),
        ("path", "st_ino", 999),
        ("path", "st_size", 6),
        ("path", "st_mtime_ns", 999),
    ],
)
def test_read_post_observation_changes_refuse(api, stage, field, value):
    observations = Observations()
    changed = snapshot()
    setattr(changed, field, value)
    if stage == "fd":
        observations.after_fd = changed
    else:
        observations.after_path = changed
    with pytest.raises(api[1].Denied):
        backend(api, observations).read_file(FILE, 5)


def test_read_rechecks_ordinary_parents(api):
    observations = Observations()
    observations.parent_after = snapshot(mode=stat.S_IFREG | 0o600)
    with pytest.raises(api[1].Denied):
        backend(api, observations).read_file(FILE, 5)


@pytest.mark.parametrize("raw", [b"abcd", b"abcdef"])
def test_premature_or_excess_bytes_refuse(api, raw):
    observations = Observations(raw, initial=snapshot(size=5))
    with pytest.raises(api[1].Denied):
        backend(api, observations).read_file(FILE, 5)


@pytest.mark.parametrize("size", [-1, True, 8 * 1024 * 1024 + 1, 4, 6])
def test_digest_exact_original_size(api, size):
    observations = Observations()
    with pytest.raises(api[1].Denied):
        backend(api, observations).file_digest(FILE, size)
