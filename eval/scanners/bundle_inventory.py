"""Bounded complete Trivy cache identity; data verification only, never execution.

Paths are lexical. No-follow final opens and before/after identity checks reduce
races; only an operator-owned isolated sandbox can exclude concurrent mutation.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import time
from dataclasses import dataclass
from pathlib import Path

PROFILE = "m4-trivy-complete-cache-v1"
SCHEMA = "m4-scanner-bundle-tree-v1"
# Immutable code-owned caps; callers cannot supply a larger profile.
CAPS = (("max_regular_files", 1024), ("max_directories_excluding_root", 256),
        ("max_all_entries_excluding_root", 1280), ("max_file_bytes", 65536),
        ("max_aggregate_file_bytes", 2097152), ("max_relative_path_bytes", 256),
        ("max_relative_depth", 12), ("max_canonical_manifest_bytes", 524288))
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_SEGMENT = re.compile(r"[A-Za-z0-9_.-]+\Z")
_DEVICE = re.compile(r"(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?\Z", re.IGNORECASE)


def _remaining(deadline: float | None) -> None:
    if deadline is not None and (type(deadline) not in {int, float} or not math.isfinite(deadline)):
        raise ValueError("finite absolute monotonic deadline required")
    if deadline is not None and time.monotonic() >= deadline:
        raise TimeoutError("complete-tree attempt deadline exhausted")


def _plain(metadata: os.stat_result, directory: bool) -> None:
    if (getattr(metadata, "st_file_attributes", 0) & 0x400
            or not (stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode))
            or (not directory and getattr(metadata, "st_nlink", None) != 1)):
        raise ValueError("plain unlinked directory or single-link regular file required")


def plain_directory(path: Path, *, deadline: float | None = None) -> None:
    if not path.is_absolute() or any(part in {".", ".."} for part in path.parts):
        raise ValueError("absolute lexical plain directory required")
    for parent in reversed((path, *path.parents)):
        _remaining(deadline)
        _plain(parent.lstat(), True)


def _signature(metadata: os.stat_result, *, cross_api: bool = False) -> tuple:
    # On Windows lstat and fstat can report different ctime meanings. Compare
    # their common mtime across the open boundary, but retain ctime for every
    # same-API before/after check (and across APIs on other platforms).
    ctime = None if cross_api and os.name == "nt" else metadata.st_ctime_ns
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_nlink,
            metadata.st_size, metadata.st_mtime_ns, ctime,
            getattr(metadata, "st_file_attributes", 0))


def _read(path: Path, cap: int, *, deadline: float | None = None) -> bytes:
    _remaining(deadline)
    plain_directory(path.parent, deadline=deadline)
    before = path.lstat()
    _plain(before, False)
    if before.st_size > cap:
        raise ValueError("complete-tree file byte cap exceeded")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        _plain(opened, False)
        if _signature(before, cross_api=True) != _signature(opened, cross_api=True):
            raise ValueError("complete-tree file replaced before open")
        data = bytearray()
        while True:
            _remaining(deadline)
            chunk = os.read(fd, min(8192, cap + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > cap:
                raise ValueError("complete-tree file byte cap exceeded")
        if len(data) != opened.st_size or _signature(opened) != _signature(os.fstat(fd)):
            raise ValueError("complete-tree file changed or short read")
    finally:
        os.close(fd)
    if _signature(before) != _signature(path.lstat()):
        raise ValueError("complete-tree file replaced after read")
    _remaining(deadline)
    return bytes(data)


def _unique(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate complete-tree JSON key")
        result[key] = value
    return result


def _nonfinite(_: str) -> None:
    raise ValueError("nonfinite complete-tree JSON")


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("ascii")


def _relative(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 256:
        raise ValueError("bounded relative ASCII tree path required")
    parts = value.split("/")
    if len(parts) > 12 or any(not _SEGMENT.fullmatch(part) or part in {".", ".."}
                              or part.endswith(".") or _DEVICE.fullmatch(part) for part in parts):
        raise ValueError("noncanonical or reserved complete-tree path")
    return value


def _absolute(value: object) -> Path:
    if not isinstance(value, str) or not Path(value).is_absolute():
        raise ValueError("absolute tree descriptor path required")
    path = Path(value)
    if ".." in path.parts or str(path) != value:
        raise ValueError("normalized lexical descriptor path required")
    return path


@dataclass(frozen=True)
class BundleInventory:
    profile: str
    root: Path
    manifest_path: Path
    tree_sha256: str

    def __post_init__(self) -> None:
        if (self.profile != PROFILE or not isinstance(self.root, Path)
                or not isinstance(self.manifest_path, Path)
                or not isinstance(self.tree_sha256, str) or not _HASH.fullmatch(self.tree_sha256)
                or not self.root.is_absolute() or not self.manifest_path.is_absolute()
                or ".." in self.root.parts or ".." in self.manifest_path.parts
                or self.manifest_path.is_relative_to(self.root)):
            raise ValueError("closed complete-tree profile and external manifest required")

    def identity(self) -> dict:
        return {"profile": self.profile, "root": str(self.root),
                "manifest_path": str(self.manifest_path), "tree_sha256": self.tree_sha256,
                "caps": dict(CAPS)}


def _expected(binding: BundleInventory, *, deadline: float | None = None) -> tuple[dict, bytes]:
    raw = _read(binding.manifest_path, 524288, deadline=deadline)
    if hashlib.sha256(raw).hexdigest() != binding.tree_sha256:
        raise ValueError("complete-tree manifest pin mismatch")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique, parse_constant=_nonfinite)
    if (not isinstance(value, dict) or set(value) != {"schema_version", "algorithm", "paths", "rows"}
            or value["schema_version"] != SCHEMA or value["algorithm"] != "sha256"
            or value["paths"] != "normalized-posix-relative-utf8"
            or not isinstance(value["rows"], list) or not 0 < len(value["rows"]) <= 1280
            or _canonical(value) != raw):
        raise ValueError("closed canonical complete-tree manifest required")
    seen, folded, directories, files, total, order = set(), set(), set(), 0, 0, []
    for row in value["rows"]:
        _remaining(deadline)
        if not isinstance(row, dict):
            raise TypeError("complete-tree row must be an object")
        path = _relative(row.get("path"))
        if path in seen or path.casefold() in folded:
            raise ValueError("duplicate or case-colliding complete-tree path")
        seen.add(path)
        folded.add(path.casefold())
        order.append(path)
        if row.get("kind") == "directory" and set(row) == {"path", "kind"}:
            directories.add(path)
        elif row.get("kind") == "file" and set(row) == {"path", "kind", "bytes", "sha256"}:
            size, sha = row["bytes"], row["sha256"]
            if (type(size) is not int or not 0 <= size <= 65536
                    or not isinstance(sha, str) or not _HASH.fullmatch(sha)):
                raise ValueError("invalid complete-tree file size/hash")
            files += 1
            total += size
        else:
            raise ValueError("unknown complete-tree kind or row fields")
        if files > 1024 or len(directories) > 256 or total > 2097152:
            raise ValueError("complete-tree inventory exceeds profile caps")
    if not files or order != sorted(order, key=lambda path: path.encode("utf-8")):
        raise ValueError("nonempty files and exact path ordering required")
    for path in seen:
        parts = path.split("/")
        if any("/".join(parts[:i]) not in directories for i in range(1, len(parts))):
            raise ValueError("complete-tree explicit parent directory missing")
    return value, raw


def load_bundle_inventory(value: object, workspace: Path, *,
                          deadline: float | None = None) -> BundleInventory:
    if not isinstance(value, dict) or set(value) != {"profile", "root", "manifest_path", "tree_sha256"}:
        raise ValueError("closed complete-tree descriptor required")
    binding = BundleInventory(value["profile"], _absolute(value["root"]),
                              _absolute(value["manifest_path"]), value["tree_sha256"])
    if binding.root != workspace / "policy":
        raise ValueError("complete-tree root must be exact workspace/policy")
    plain_directory(workspace, deadline=deadline)
    _expected(binding, deadline=deadline)
    return binding


def verify_tree(binding: BundleInventory, *, deadline: float | None = None) -> dict:
    """Rehash EVERY plain file and directory; no allowlist subset or cached proof."""
    if type(binding) is not BundleInventory:
        raise ValueError("typed immutable complete-tree binding required")
    started = time.monotonic()
    expected, raw = _expected(binding, deadline=deadline)
    plain_directory(binding.root, deadline=deadline)
    rows, folded, signatures = [], set(), []
    files, directories, total = 0, 0, 0
    # Bounded streaming enumeration, never list(scandir(...)) on untrusted input.
    def walk(directory: Path, prefix: str) -> None:
        nonlocal files, directories, total
        _remaining(deadline)
        before = directory.lstat()
        _plain(before, True)
        signatures.append((directory, _signature(before)))
        with os.scandir(directory) as entries:
            for entry in entries:
                _remaining(deadline)
                relative = _relative(prefix + entry.name)
                if len(rows) >= 1280 or relative.casefold() in folded:
                    raise ValueError("complete-tree entry cap or case collision")
                folded.add(relative.casefold())
                path = directory / entry.name
                metadata = path.lstat()
                if stat.S_ISDIR(metadata.st_mode):
                    _plain(metadata, True)
                    directories += 1
                    if directories > 256:
                        raise ValueError("complete-tree directory cap exceeded")
                    rows.append({"path": relative, "kind": "directory"})
                    walk(path, relative + "/")
                else:
                    _plain(metadata, False)
                    files += 1
                    if files > 1024 or metadata.st_size > 65536:
                        raise ValueError("complete-tree file count/size cap exceeded")
                    total += metadata.st_size
                    if total > 2097152:
                        raise ValueError("complete-tree aggregate byte cap exceeded")
                    content = _read(path, 65536, deadline=deadline)
                    rows.append({"path": relative, "kind": "file", "bytes": len(content),
                                 "sha256": hashlib.sha256(content).hexdigest()})
        if _signature(before) != _signature(directory.lstat()):
            raise ValueError("complete-tree directory changed during walk")
    walk(binding.root, "")
    # Restat all directories after reads, including root, without following links.
    for path, signature in signatures:
        _remaining(deadline)
        metadata = path.lstat()
        _plain(metadata, True)
        if _signature(metadata) != signature:
            raise ValueError("complete-tree directory replaced")
    observed = {**expected, "rows": sorted(rows, key=lambda row: row["path"].encode("utf-8"))}
    actual = _canonical(observed)
    observed_sha = hashlib.sha256(actual).hexdigest()
    if actual != raw or observed_sha != binding.tree_sha256:
        raise ValueError("complete-tree membership/bytes differ from pinned manifest")
    _remaining(deadline)
    return {"tree_sha256": observed_sha, "files": files, "directories": directories,
            "aggregate_file_bytes": total, "elapsed_seconds": time.monotonic() - started}
