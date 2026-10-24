"""Bounded local Terraform JSON ingestion; no Terraform or HCL execution."""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import time
from pathlib import Path
from typing import Any
from uuid import uuid4

from iac_review.contracts import PlanDocument, PlanIdentity, ResourceChange

MAX_BYTES = 16 * 1024 * 1024
MAX_RESOURCES = 10_000
MAX_DEPTH = 64
MAX_STRING_BYTES = 256 * 1024
MAX_SECONDS = 30
FORMAT_TARGETS = frozenset({"1.0", "1.1", "1.2"})
ACTION_SEQUENCES = frozenset({
    ("no-op",), ("create",), ("read",), ("update",), ("delete",),
    ("delete", "create"), ("create", "delete"),
})


class InputError(ValueError):
    """A fixed public error code, intentionally containing no input text/path."""


class SourceChangedError(InputError):
    """The pinned input can no longer support this review."""


def _deadline(started: float) -> None:
    if time.monotonic() - started > MAX_SECONDS:
        raise InputError("review_time_limit")


def _safe_regular(path: Path) -> os.stat_result:
    # Do not follow a user-selected symlink or junction to an unexpected source.
    for node in (path, *path.parents):
        if node.is_symlink() or (hasattr(node, "is_junction") and node.is_junction()):
            raise InputError("source_link_rejected")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode):
        raise InputError("source_not_regular")
    if info.st_size > MAX_BYTES:
        raise InputError("input_byte_limit")
    return info


def read_source_bytes(path: Path) -> bytes:
    """Read a bounded regular file, checking the opened object and stable identity."""
    try:
        path = path.absolute()
        before = _safe_regular(path)
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if not stat.S_ISREG(opened.st_mode):
                raise InputError("source_not_regular")
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise SourceChangedError("source_changed_during_open")
            data = handle.read(MAX_BYTES + 1)
            after = os.fstat(handle.fileno())
        current = _safe_regular(path)
        fields = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)
        if fields(before) != fields(after) or fields(after) != fields(current):
            raise SourceChangedError("source_changed_during_read")
        if len(data) > MAX_BYTES:
            raise InputError("input_byte_limit")
        return data
    except InputError:
        raise
    except (OSError, ValueError, RuntimeError) as exc:
        raise InputError("source_unreadable") from exc


def _lexical_limits(data: bytes, started: float) -> None:
    """Bound nesting and encoded string size before the recursive JSON decoder."""
    depth = 0
    in_string = False
    escaped = False
    string_bytes = 0
    for index, char in enumerate(data):
        if index % 65536 == 0:
            _deadline(started)
        if in_string:
            string_bytes += 1
            if string_bytes > MAX_STRING_BYTES:
                raise InputError("encoded_string_limit")
            if escaped:
                escaped = False
            elif char == 92:
                escaped = True
            elif char == 34:
                in_string = False
        elif char == 34:
            in_string = True
            string_bytes = 0
        elif char in (91, 123):
            depth += 1
            if depth > MAX_DEPTH:
                raise InputError("json_depth_limit")
        elif char in (93, 125):
            depth -= 1


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise InputError("duplicate_json_key")
        result[key] = value
    return result


def _constant(_: str) -> Any:
    raise InputError("nonfinite_json_number")


def _float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise InputError("nonfinite_json_number")
    return value


def decode_source(data: bytes, started: float | None = None) -> dict[str, Any]:
    """Strict decoder shared by initial ingestion and pinned evidence reopening."""
    started = time.monotonic() if started is None else started
    _lexical_limits(data, started)
    try:
        text = data.decode("utf-8", errors="strict")
        raw = json.loads(text, object_pairs_hook=_object, parse_constant=_constant, parse_float=_float)
    except InputError:
        raise
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise InputError("malformed_json") from exc
    if not isinstance(raw, dict):
        raise InputError("plan_envelope_not_object")
    _deadline(started)
    return raw


def _string(container: dict[str, Any], name: str) -> str:
    value = container.get(name)
    if not isinstance(value, str) or not value:
        raise InputError("resource_identity_malformed")
    return value


def _optional_flag(raw: dict[str, Any], name: str) -> bool | None:
    if name not in raw:
        return None
    value = raw[name]
    if type(value) is not bool:
        raise InputError("plan_flag_malformed")
    return value


def _mask_shape(mask: Any) -> bool:
    if type(mask) is bool:
        return True
    if isinstance(mask, dict):
        return all(_mask_shape(value) for value in mask.values())
    if isinstance(mask, list):
        return all(_mask_shape(value) for value in mask)
    return False


def load_plan(path: Path) -> PlanDocument:
    """Normalize explicit supported facts and retain unsupported scope as coverage."""
    started = time.monotonic()
    data = read_source_bytes(path)
    return _normalize_plan_bytes(data, path, started)


def load_plan_bytes(data: bytes, *, source_path: Path, expected_sha256: str | None = None) -> PlanDocument:
    """Normalize already permission-gated bytes; source_path is private metadata only.

    No stat/open/copy or source-path reopening occurs. Admission/decoder/masks and
    source identity use the same normalizer as load_plan, without relaxed limits.
    """
    started = time.monotonic()
    if type(data) is not bytes or len(data) > MAX_BYTES:
        raise InputError("input_byte_limit")
    if expected_sha256 is not None and (not isinstance(expected_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None
            or hashlib.sha256(data).hexdigest() != expected_sha256):
        raise SourceChangedError("source_identity_mismatch")
    return _normalize_plan_bytes(data, source_path, started)


def _normalize_plan_bytes(data: bytes, path: Path, started: float) -> PlanDocument:
    raw = decode_source(data, started)
    version = raw.get("format_version")
    if not isinstance(version, str) or re.fullmatch(r"[0-9]+\.[0-9]+", version) is None:
        raise InputError("format_version_malformed")
    if version.split(".", 1)[0] != "1":
        raise InputError("format_major_unsupported")
    coverage: list[str] = []
    if version not in FORMAT_TARGETS:
        coverage.append("format_minor_unsupported")
    producing_version = raw.get("terraform_version")
    if producing_version is not None and not isinstance(producing_version, str):
        raise InputError("terraform_version_malformed")
    complete = _optional_flag(raw, "complete")
    errored = _optional_flag(raw, "errored")
    applyable = _optional_flag(raw, "applyable")
    if complete is not True:
        coverage.append("plan_completeness_missing" if complete is None else "plan_incomplete")
    if errored is not False:
        coverage.append("plan_error_flag_missing" if errored is None else "plan_errored")
    changes = raw.get("resource_changes", [])
    if "resource_changes" not in raw:
        coverage.append("resource_changes_missing")
    if not isinstance(changes, list):
        raise InputError("resource_changes_malformed")
    if len(changes) > MAX_RESOURCES:
        raise InputError("resource_count_limit")
    resources: list[ResourceChange] = []
    identities: set[tuple[str, str | None]] = set()
    for index, entry in enumerate(changes):
        _deadline(started)
        if not isinstance(entry, dict):
            raise InputError("resource_entry_malformed")
        address = _string(entry, "address")
        deposed = entry.get("deposed")
        if deposed is not None and (not isinstance(deposed, str) or not deposed):
            raise InputError("deposed_identity_malformed")
        identity = (address, deposed)
        if identity in identities:
            raise InputError("duplicate_resource_identity")
        identities.add(identity)
        change = entry.get("change")
        if not isinstance(change, dict):
            raise InputError("resource_change_malformed")
        actions = change.get("actions")
        if not isinstance(actions, list) or not actions or any(not isinstance(action, str) or not action for action in actions):
            raise InputError("actions_malformed")
        action_tuple = tuple(actions)
        arguments: dict[str, Any] = {
            "key": uuid4().hex,
            "index": index,
            "address": address,
            "deposed": deposed,
            "provider_name": _string(entry, "provider_name"),
            "mode": _string(entry, "mode"),
            "type": _string(entry, "type"),
            "name": _string(entry, "name"),
            "actions": action_tuple,
            "action_supported": action_tuple in ACTION_SEQUENCES,
        }
        for side in ("before", "after"):
            if side in change:
                arguments[side] = change[side]
        for name in ("before_sensitive", "after_sensitive", "after_unknown"):
            mask = change.get(name, False)
            if not _mask_shape(mask):
                raise InputError("value_mask_malformed")
            arguments[name] = mask
        if action_tuple not in ACTION_SEQUENCES:
            coverage.append("action_sequence_unsupported")
        if arguments["mode"] not in ("managed", "data"):
            coverage.append("resource_mode_unsupported")
        resources.append(ResourceChange(**arguments))
    identity = PlanIdentity(
        sha256=hashlib.sha256(data).hexdigest(),
        format_version=version,
        terraform_version=producing_version,
        complete=complete,
        errored=errored,
        applyable=applyable,
        limits={"bytes": MAX_BYTES, "resources": MAX_RESOURCES, "depth": MAX_DEPTH,
                "encoded_string_bytes": MAX_STRING_BYTES, "seconds": MAX_SECONDS},
    )
    _deadline(started)
    return PlanDocument(identity=identity, source_path=str(path.absolute()), raw=raw,
                        resources=tuple(resources), coverage=tuple(dict.fromkeys(coverage)))


__all__ = ["InputError", "SourceChangedError", "decode_source", "load_plan", "load_plan_bytes", "read_source_bytes"]
