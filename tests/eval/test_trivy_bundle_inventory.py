"""Independent complete-tree contract tests; metadata only, never execute policies.

The small golden is hand-written from three public literal payloads, including
equal basenames and an empty directory. No product helper generates expectations.
Required API imports deliberately fail collection against the pre-feature base.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import stat
import subprocess
import time
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
from eval.scanners.bundle_inventory import BundleInventory, load_bundle_inventory, verify_tree

from eval.scanners import bundle_inventory as inventory_module

FIXTURES = Path(__file__).parent / "fixtures" / "trivy-bundle-v1"
SMALL_SHA = "171e51e9eea6c8e9d2cba4da52f583b9be56110fdae61f08ec72e1b22a60f024"
REFUSAL = (ValueError, OSError, TimeoutError)


def canonical(value):
    """Test-owned standard JSON encoding, independent of implementation helpers."""
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")


def small_tree(workspace):
    root = workspace / "policy"
    root.mkdir()
    for directory in ("b", "empty", "a"):
        (root / directory).mkdir()
    for name, raw in (
        ("b/check.rego", b"beta\n"),
        ("a/check.rego", b"alpha\n"),
        ("metadata.json", b'{"local":true}\n'),
    ):
        (root / name).write_bytes(raw)
    manifest = workspace.parent / (workspace.name + "-tree.json")
    manifest.write_bytes((FIXTURES / "small-tree.json").read_bytes())
    descriptor = {
        "profile": "m4-trivy-complete-cache-v1",
        "root": str(root),
        "manifest_path": str(manifest),
        "tree_sha256": SMALL_SHA,
    }
    return descriptor, root, manifest


def changed_manifest(workspace, mutate=None, *, raw=None):
    descriptor, root, manifest = small_tree(workspace)
    if raw is None:
        value = json.loads(manifest.read_bytes())
        mutate(value)
        raw = canonical(value)
    manifest.write_bytes(raw)
    descriptor["tree_sha256"] = hashlib.sha256(raw).hexdigest()
    return descriptor, root, manifest


def refused(descriptor, workspace):
    # Refusal may occur in strict loading or the fresh actual filesystem check.
    with pytest.raises(REFUSAL):
        verify_tree(load_bundle_inventory(descriptor, workspace))


def test_literal_golden_has_independent_exact_bytes_and_membership(tmp_path):
    """what_bug_this_catches: product canonicalizer silently changes its own golden."""
    descriptor, root, manifest = small_tree(tmp_path)
    raw = manifest.read_bytes()
    assert len(raw) == 591 and hashlib.sha256(raw).hexdigest() == SMALL_SHA
    assert not raw.endswith(b"\n") and canonical(json.loads(raw)) == raw
    assert [
        (p.relative_to(root).as_posix(), p.read_bytes())
        for p in sorted(root.rglob("*"))
        if p.is_file()
    ] == [
        ("a/check.rego", b"alpha\n"),
        ("b/check.rego", b"beta\n"),
        ("metadata.json", b'{"local":true}\n'),
    ]
    binding = load_bundle_inventory(descriptor, tmp_path)
    assert isinstance(binding, BundleInventory)
    assert binding.root == root and binding.manifest_path == manifest
    assert binding.tree_sha256 == SMALL_SHA
    for _ in range(2):
        summary = verify_tree(binding)
        assert set(summary) == {
            "tree_sha256",
            "files",
            "directories",
            "aggregate_file_bytes",
            "elapsed_seconds",
        }
        assert {k: v for k, v in summary.items() if k != "elapsed_seconds"} == {
            "tree_sha256": SMALL_SHA,
            "files": 3,
            "directories": 3,
            "aggregate_file_bytes": 26,
        }
        assert type(summary["files"]) is int and type(summary["directories"]) is int
        assert type(summary["aggregate_file_bytes"]) is int
        assert type(summary["elapsed_seconds"]) is float and summary["elapsed_seconds"] >= 0


@pytest.mark.parametrize(
    "field,value",
    [
        ("profile", "unknown"),
        ("profile", True),
        ("root", 1),
        ("manifest_path", None),
        ("tree_sha256", "A" * 64),
        ("tree_sha256", "0" * 63),
        ("tree_sha256", False),
    ],
)
def test_descriptor_strict_types_and_pins(tmp_path, field, value):
    """what_bug_this_catches: coercion/unknown profile weakens immutable binding."""
    descriptor, _, _ = small_tree(tmp_path)
    descriptor[field] = value
    refused(descriptor, tmp_path)


@pytest.mark.parametrize("field", ["profile", "root", "manifest_path", "tree_sha256"])
def test_descriptor_fields_required(tmp_path, field):
    descriptor, _, _ = small_tree(tmp_path)
    del descriptor[field]
    refused(descriptor, tmp_path)


@pytest.mark.parametrize("field", ["caps", "rows", "files", "deadline", "extra"])
def test_descriptor_is_closed(tmp_path, field):
    descriptor, _, _ = small_tree(tmp_path)
    descriptor[field] = {}
    refused(descriptor, tmp_path)


@pytest.mark.parametrize(
    "bad_path",
    [
        "",
        ".",
        "..",
        "../check",
        "a/../check",
        "/absolute",
        "//host/share",
        "C:/drive",
        "a\\check",
        "a:ads",
        "a//check",
        "a/./check",
        "a/",
        "a.",
        "a ",
        "NUL",
        "nul.rego",
        "CON",
        "PRN.txt",
        "AUX",
        "COM1",
        "LPT9.log",
        "bad\x00name",
        "bad\nname",
        "caf\u00e9",
        "a/+plus",
        "a/white space",
        "a/\tname",
    ],
)
def test_unsafe_relative_paths_refused(tmp_path, bad_path):
    """what_bug_this_catches: alternate OS spellings alias files or escape root."""
    descriptor, _, _ = changed_manifest(
        tmp_path, lambda value: value["rows"][1].update(path=bad_path)
    )
    refused(descriptor, tmp_path)


@pytest.mark.parametrize("mutation", ["duplicate", "case", "kind", "parent", "order"])
def test_manifest_identity_and_explicit_parent_order(tmp_path, mutation):
    """what_bug_this_catches: duplicate/case aliases or implicit parents admitted."""

    def mutate(value):
        rows = value["rows"]
        if mutation == "duplicate":
            rows.append(copy.deepcopy(rows[1]))
        elif mutation == "case":
            rows.append(dict(rows[1], path="A/check.rego"))
        elif mutation == "kind":
            rows.append(
                {"path": "a", "kind": "file", "bytes": 0, "sha256": hashlib.sha256(b"").hexdigest()}
            )
        elif mutation == "parent":
            rows.pop(0)
        else:
            rows.reverse()

    descriptor, _, _ = changed_manifest(tmp_path, mutate)
    refused(descriptor, tmp_path)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"algorithm":"sha256","algorithm":"sha256","paths":"normalized-posix-relative-utf8","rows":[],"schema_version":"m4-scanner-bundle-tree-v1"}',
        b'{"rows":NaN}',
        b"[]",
        b"null",
        b"\xef\xbb\xbf{}",
    ],
)
def test_raw_json_is_strict_and_closed(tmp_path, raw):
    descriptor, _, _ = changed_manifest(tmp_path, raw=raw)
    refused(descriptor, tmp_path)


@pytest.mark.parametrize("style", ["newline", "pretty", "unsorted", "schema", "extra"])
def test_raw_canonical_bytes_and_schema_are_mandatory(tmp_path, style):
    descriptor, _, manifest = small_tree(tmp_path)
    raw = manifest.read_bytes()
    value = json.loads(raw)
    if style == "newline":
        raw += b"\n"
    elif style == "pretty":
        raw = json.dumps(value, indent=2).encode()
    elif style == "unsorted":
        raw = json.dumps(dict(reversed(list(value.items()))), separators=(",", ":")).encode()
    else:
        value["schema_version" if style == "schema" else "extra"] = "wrong"
        raw = canonical(value)
    manifest.write_bytes(raw)
    descriptor["tree_sha256"] = hashlib.sha256(raw).hexdigest()
    refused(descriptor, tmp_path)


@pytest.mark.parametrize("value", [True, False, -1, 1.0, "6", None, 65537])
def test_file_size_is_strict_bounded_integer(tmp_path, value):
    descriptor, _, _ = changed_manifest(tmp_path, lambda tree: tree["rows"][1].update(bytes=value))
    refused(descriptor, tmp_path)


@pytest.mark.parametrize(
    "mutation",
    [
        "extra-file",
        "hidden-file",
        "extra-empty-dir",
        "same-size",
        "metadata",
        "oversize",
        "manifest",
        "missing-file",
        "missing-dir",
    ],
)
def test_complete_actual_membership_and_bytes(tmp_path, mutation):
    """what_bug_this_catches: subset checks miss unlisted entries or metadata drift."""
    descriptor, root, manifest = small_tree(tmp_path)
    if mutation in {"extra-file", "hidden-file"}:
        (root / ("extra.rego" if mutation == "extra-file" else ".hidden")).write_bytes(b"x")
    elif mutation == "extra-empty-dir":
        (root / "extra").mkdir()
    elif mutation == "same-size":
        (root / "a/check.rego").write_bytes(b"ALPHA\n")
    elif mutation == "metadata":
        (root / "metadata.json").write_bytes(b'{"local":false}')
    elif mutation == "oversize":
        (root / "a/check.rego").write_bytes(b"x" * 65537)
    elif mutation == "manifest":
        manifest.write_bytes(manifest.read_bytes() + b" ")
    else:
        # Preserve every fixture byte; moving an own regular entry outside policy
        # models absence without deleting project files or link targets.
        source = root / ("a/check.rego" if mutation == "missing-file" else "empty")
        source.rename(tmp_path / "retained-omitted-entry")
    refused(descriptor, tmp_path)


@pytest.mark.parametrize("where", ["elsewhere", "nested", "manifest-inside", "relative"])
def test_roles_require_exact_lexical_workspace_policy(tmp_path, where):
    descriptor, root, _ = small_tree(tmp_path)
    if where == "manifest-inside":
        path = root / "manifest.json"
        path.write_bytes((FIXTURES / "small-tree.json").read_bytes())
        descriptor["manifest_path"] = str(path)
    elif where == "relative":
        descriptor["root"] = "policy"
    else:
        descriptor["root"] = str(tmp_path / ("other" if where == "elsewhere" else "policy/a"))
    refused(descriptor, tmp_path)


def test_expected_manifest_reopened_each_verification(tmp_path):
    """what_bug_this_catches: stale cached rows hide later manifest mutation."""
    descriptor, _, manifest = small_tree(tmp_path)
    binding = load_bundle_inventory(descriptor, tmp_path)
    verify_tree(binding)
    manifest.write_bytes(manifest.read_bytes().replace(b'"bytes":6', b'"bytes":7'))
    with pytest.raises(REFUSAL):
        verify_tree(binding)


def test_already_expired_deadline_refuses_without_new_budget(tmp_path):
    descriptor, _, _ = small_tree(tmp_path)
    binding = load_bundle_inventory(descriptor, tmp_path)
    with pytest.raises(TimeoutError):
        verify_tree(binding, deadline=time.monotonic() - 1)


def test_lstat_failure_is_not_ignored(tmp_path, monkeypatch):
    descriptor, root, _ = small_tree(tmp_path)
    binding = load_bundle_inventory(descriptor, tmp_path)
    original = Path.lstat

    def fail(path, *args, **kwargs):
        if Path(path) == root / "a/check.rego":
            raise OSError("owned synthetic lstat failure")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", fail)
    with pytest.raises(REFUSAL):
        verify_tree(binding)


@pytest.mark.parametrize("kind", ["fifo", "socket", "reparse", "unknown-nlink", "hardlink"])
def test_unsupported_stat_objects_fail_closed(tmp_path, monkeypatch, kind):
    """what_bug_this_catches: link/special objects reach content readers."""
    descriptor, root, _ = small_tree(tmp_path)
    binding = load_bundle_inventory(descriptor, tmp_path)
    original = Path.lstat

    def altered(path, *args, **kwargs):
        actual = original(path, *args, **kwargs)
        if Path(path) != root / "a/check.rego":
            return actual
        fields = {name: getattr(actual, name) for name in dir(actual) if name.startswith("st_")}
        if kind in {"fifo", "socket"}:
            fields["st_mode"] = stat.S_IFIFO if kind == "fifo" else stat.S_IFSOCK
        elif kind == "reparse":
            fields["st_file_attributes"] = 0x400
        else:
            fields["st_nlink"] = None if kind == "unknown-nlink" else 2
        return SimpleNamespace(**fields)

    monkeypatch.setattr(Path, "lstat", altered)
    with pytest.raises(REFUSAL):
        verify_tree(binding)


def test_real_hardlink_refused_and_preserved():
    """what_bug_this_catches: regular file aliases escape mutation exclusion."""
    sandbox = (
        Path(__file__).resolve().parents[2] / ".agent-work" / "0053-trivy-links" / uuid.uuid4().hex
    )
    sandbox.mkdir(parents=True)
    descriptor, root, _ = small_tree(sandbox)
    target = sandbox / "owned-hardlink-target"
    target.write_bytes(b"alpha\n")
    (root / "a/check.rego").rename(sandbox / "retained-original")
    os.link(target, root / "a/check.rego")
    refused(descriptor, sandbox)
    assert target.read_bytes() == b"alpha\n"
    assert (root / "a/check.rego").exists()


@pytest.mark.parametrize("position", ["root", "ancestor", "descendant"])
def test_windows_junction_refused_without_cleanup(position):
    """what_bug_this_catches: junction resolution disguises a linked cache path."""
    if os.name != "nt":
        pytest.skip("Windows junction control; mocked reparse control remains portable")
    sandbox = (
        Path(__file__).resolve().parents[2] / ".agent-work" / "0053-trivy-links" / uuid.uuid4().hex
    )
    sandbox.mkdir(parents=True)
    workspace = sandbox / "workspace"
    workspace.mkdir()
    descriptor, root, _ = small_tree(workspace)
    if position == "descendant":
        target = sandbox / "target"
        target.mkdir()
        link = root / "linked"
    elif position == "root":
        target = sandbox / "retained-policy"
        root.rename(target)
        link = root
    else:
        target = sandbox / "retained-workspace"
        workspace.rename(target)
        link = workspace
    # Only this owned junction setup may create a real child process. The
    # scanner boundary is separately mocked in binding tests. Never remove it.
    made = subprocess.run(
        ["cmd.exe", "/c", "mklink", "/J", str(link), str(target)], capture_output=True, check=False
    )
    assert made.returncode == 0, made.stderr
    refused(descriptor, workspace)
    assert link.exists() and target.exists()


def artificial_tree(workspace, file_sizes, directories=()):
    """Independent synthetic cap fixture, not any acquired cache or policy."""
    root = workspace / "policy"
    root.mkdir()
    rows = []
    for directory in directories:
        (root / directory).mkdir(parents=True, exist_ok=True)
        rows.append({"path": directory, "kind": "directory"})
    for name, size in file_sizes:
        raw = b"x" * size
        (root / name).write_bytes(raw)
        rows.append(
            {"path": name, "kind": "file", "bytes": size, "sha256": hashlib.sha256(raw).hexdigest()}
        )
    rows.sort(key=lambda row: row["path"].encode("utf-8"))
    raw = canonical(
        {
            "algorithm": "sha256",
            "paths": "normalized-posix-relative-utf8",
            "rows": rows,
            "schema_version": "m4-scanner-bundle-tree-v1",
        }
    )
    manifest = workspace.parent / (workspace.name + "-tree.json")
    manifest.write_bytes(raw)
    return {
        "profile": "m4-trivy-complete-cache-v1",
        "root": str(root),
        "manifest_path": str(manifest),
        "tree_sha256": hashlib.sha256(raw).hexdigest(),
    }


@pytest.mark.parametrize("over", [False, True])
@pytest.mark.parametrize(
    "cap", ["files", "directories", "entries", "file-bytes", "total-bytes", "depth", "path"]
)
def test_immutable_caps_at_and_over_boundary(tmp_path, cap, over):
    """what_bug_this_catches: off-by-one cap or global legacy cap leaks into tree mode."""
    extra = int(over)
    directories = ()
    if cap == "files":
        files = [(f"f{i:04d}", 0) for i in range(1024 + extra)]
    elif cap == "directories":
        files, directories = [("control", 0)], [f"d{i:03d}" for i in range(256 + extra)]
    elif cap == "entries":
        # One above the combined bound necessarily also exceeds one component;
        # the exact at-bound control independently proves 1280 total accepted.
        files = [(f"f{i:04d}", 0) for i in range(1024 + extra)]
        directories = [f"d{i:03d}" for i in range(256)]
    elif cap == "file-bytes":
        files = [("large", 65536 + extra)]
    elif cap == "total-bytes":
        files = [(f"f{i:02d}", 65536) for i in range(32)]
        if over:
            files.append(("overflow", 1))
    elif cap == "depth":
        directories = ["/".join(["d"] * i) for i in range(1, 12 + extra)]
        files = [("/".join(["d"] * (11 + extra) + ["f"]), 0)]
    else:
        # Keep each segment <=255 bytes on Windows while hitting 256 UTF8 bytes.
        directories = ["a" * 120]
        files = [(directories[0] + "/" + "b" * (135 + extra), 0)]
    descriptor = artificial_tree(tmp_path, files, directories)
    if over:
        refused(descriptor, tmp_path)
    else:
        verify_tree(load_bundle_inventory(descriptor, tmp_path))


def test_manifest_byte_cap_before_json_parse(tmp_path):
    descriptor, _, manifest = small_tree(tmp_path)
    raw = b" " * 524289
    manifest.write_bytes(raw)
    descriptor["tree_sha256"] = hashlib.sha256(raw).hexdigest()
    refused(descriptor, tmp_path)


@pytest.mark.parametrize("cap", [65536, 524288])
@pytest.mark.parametrize("offset", [-1, 0, 1])
def test_direct_bounded_read_enforces_exact_cap(tmp_path, cap, offset):
    """what_bug_this_catches: a cap argument without actual bounded-read enforcement."""
    path = tmp_path / "owned-bounded-read.bin"
    raw = b"x" * (cap + offset)
    path.write_bytes(raw)
    if offset > 0:
        with pytest.raises(ValueError, match="byte cap exceeded"):
            inventory_module._read(path, cap)
    else:
        assert inventory_module._read(path, cap) == raw
    assert path.read_bytes() == raw


@pytest.mark.parametrize("size", [524287, 524288, 524289])
def test_manifest_cap_is_checked_before_parser_entry(tmp_path, monkeypatch, size):
    """what_bug_this_catches: invalid JSON masks a missing manifest read-size gate.

    Near/at-cap raw bytes must reach the parser unchanged; over-cap raw bytes
    must be rejected without invoking it. These are read/parser boundary probes,
    not claims that a full-cap valid canonical tree satisfies every other cap.
    """
    descriptor, _, manifest = small_tree(tmp_path)
    raw = b" " * size
    manifest.write_bytes(raw)
    descriptor["tree_sha256"] = hashlib.sha256(raw).hexdigest()
    calls = []

    class ParserReached(Exception):
        pass

    def parser_spy(value, *args, **kwargs):
        calls.append(value)
        if size > 524288:
            raise AssertionError("over-cap manifest reached JSON parser")
        raise ParserReached

    monkeypatch.setattr(inventory_module.json, "loads", parser_spy)
    if size > 524288:
        with pytest.raises(ValueError, match="byte cap exceeded"):
            load_bundle_inventory(descriptor, tmp_path)
        assert calls == []
    else:
        with pytest.raises(ParserReached):
            load_bundle_inventory(descriptor, tmp_path)
        assert calls == [raw.decode("utf-8")]


def test_data_open_error_fails_closed(tmp_path, monkeypatch):
    """what_bug_this_catches: unreadable listed payload silently omitted."""
    descriptor, root, _ = small_tree(tmp_path)
    binding = load_bundle_inventory(descriptor, tmp_path)
    original = os.open

    def fail(path, *args, **kwargs):
        if Path(path) == root / "a/check.rego":
            raise OSError("owned synthetic open failure")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", fail)
    with pytest.raises(REFUSAL):
        verify_tree(binding)


def test_file_open_uses_nofollow_where_available(tmp_path, monkeypatch):
    """what_bug_this_catches: final file open follows a swap after lstat."""
    if not getattr(os, "O_NOFOLLOW", 0):
        pytest.skip("OS has no O_NOFOLLOW; reparse/lstat checks independently required")
    descriptor, root, _ = small_tree(tmp_path)
    binding = load_bundle_inventory(descriptor, tmp_path)
    original = os.open
    opened = []

    def observe(path, flags, *args, **kwargs):
        if Path(path) == root / "a/check.rego":
            opened.append(flags)
            assert flags & os.O_NOFOLLOW
        return original(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", observe)
    verify_tree(binding)
    assert opened, "payload never reached the required no-follow final open"


@pytest.mark.parametrize("fault", ["error", "short-read", "grow", "identity", "hardlink"])
def test_stream_read_and_fstat_faults_refuse(tmp_path, monkeypatch, fault):
    """what_bug_this_catches: file changes or partial reads become complete hash evidence."""
    descriptor, root, _ = small_tree(tmp_path)
    binding = load_bundle_inventory(descriptor, tmp_path)
    original_open, original_read, original_fstat = os.open, os.read, os.fstat
    payload_fds = set()

    def observe_open(path, *args, **kwargs):
        fd = original_open(path, *args, **kwargs)
        if Path(path) == root / "a/check.rego":
            payload_fds.add(fd)
        else:
            payload_fds.discard(fd)
        return fd

    def read(fd, amount):
        if fd in payload_fds:
            if fault == "error":
                raise OSError("owned synthetic read error")
            if fault == "short-read":
                return b""
        return original_read(fd, amount)

    def fstat(fd):
        actual = original_fstat(fd)
        if fd not in payload_fds or fault not in {"grow", "identity", "hardlink"}:
            return actual
        fields = {name: getattr(actual, name) for name in dir(actual) if name.startswith("st_")}
        if fault == "grow":
            fields["st_size"] += 1
        elif fault == "identity":
            fields["st_ino"] += 1
        else:
            fields["st_nlink"] = 2
        return SimpleNamespace(**fields)

    monkeypatch.setattr(os, "open", observe_open)
    monkeypatch.setattr(os, "read", read)
    monkeypatch.setattr(os, "fstat", fstat)
    with pytest.raises(REFUSAL):
        verify_tree(binding)


def test_malformed_descriptor_refused_before_manifest_reads(tmp_path, monkeypatch):
    descriptor, _, _ = small_tree(tmp_path)
    descriptor["profile"] = "unapproved"

    def forbidden(*args, **kwargs):
        raise AssertionError("malformed descriptor reached filesystem read")

    monkeypatch.setattr(os, "open", forbidden)
    monkeypatch.setattr(Path, "open", forbidden)
    with pytest.raises(ValueError):
        load_bundle_inventory(descriptor, tmp_path)


def test_shared_deadline_exhausts_during_streaming(tmp_path, monkeypatch):
    """what_bug_this_catches: each file or phase restarts its own 30s budget."""
    descriptor, _, _ = small_tree(tmp_path)
    binding = load_bundle_inventory(descriptor, tmp_path)
    original_read = os.read
    clock = [100.0]

    def read(*args, **kwargs):
        clock[0] += 20.0
        return original_read(*args, **kwargs)

    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(os, "read", read)
    with pytest.raises(TimeoutError):
        verify_tree(binding, deadline=130.0)


def test_enumeration_is_bounded_before_materializing_directory(tmp_path, monkeypatch):
    """what_bug_this_catches: list(scandir) allocates an attacker-sized directory."""
    descriptor, root, _ = small_tree(tmp_path)
    binding = load_bundle_inventory(descriptor, tmp_path)
    original = os.scandir
    consumed = []

    class Overflow:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def __iter__(self):
            # Real entry objects retained, but bounded synthetic duplicate names
            # ensure any unbounded eager enumeration trips a distinct assertion.
            with original(root) as entries:
                item = next(entries)
                for i in range(1282):
                    consumed.append(i)
                    if len(consumed) > 1281:
                        raise AssertionError("unbounded eager directory enumeration")
                    yield item

    monkeypatch.setattr(
        os, "scandir", lambda path: Overflow() if Path(path) == root else original(path)
    )
    with pytest.raises(REFUSAL):
        verify_tree(binding)
    assert len(consumed) <= 1281


def test_stable_expected_file_rewritten_before_verification_is_accepted(tmp_path):
    """what_bug_this_catches: Windows birth/change-time mismatch rejects an unchanged valid tree.

    The rewrite finishes before verification. There is no concurrent writer and
    the independently frozen expected payload, hashes, and membership never change.
    """
    descriptor, root, manifest = small_tree(tmp_path)
    time.sleep(0.05)  # Separate creation from rewrite even on coarse filesystem clocks.
    (root / "a/check.rego").write_bytes(b"alpha\n")
    before = (root / "a/check.rego").lstat()
    binding = BundleInventory(descriptor["profile"], root, manifest, SMALL_SHA)
    summary = verify_tree(binding)
    assert {key: value for key, value in summary.items() if key != "elapsed_seconds"} == {
        "tree_sha256": SMALL_SHA,
        "files": 3,
        "directories": 3,
        "aggregate_file_bytes": 26,
    }
    after = (root / "a/check.rego").lstat()
    assert (before.st_ino, before.st_size, before.st_mtime_ns) == (
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    )
    assert manifest.read_bytes() == (FIXTURES / "small-tree.json").read_bytes()
