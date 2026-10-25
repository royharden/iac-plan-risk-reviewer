"""Mask-aware facts and exact RFC6901 locators in one digest-pinned document."""
from __future__ import annotations

import hashlib
import math
import re
from collections.abc import Callable
from pathlib import Path
from time import monotonic
from typing import Any, Literal
from uuid import uuid4

from iac_review.contracts import (
    EvidenceRef,
    PlanDocument,
    ResolvedEvidence,
    ResourceChange,
    ValueState,
)
from iac_review.ingest import (
    MAX_SECONDS,
    InputError,
    SourceChangedError,
    decode_source,
    read_source_bytes,
)

Side = Literal["before", "after", "actions", "metadata"]
Token = str | int
_ABSENT = object()


def _child(value: Any, token: Token) -> Any:
    if isinstance(value, dict) and isinstance(token, str):
        return value.get(token, _ABSENT)
    if isinstance(value, (list, tuple)) and type(token) is int and 0 <= token < len(value):
        return value[token]
    return _ABSENT


def _mask_child(mask: Any, token: Token) -> Any:
    if type(mask) is bool:
        return mask
    child = _child(mask, token)
    return False if child is _ABSENT else child


def _any_true(mask: Any) -> bool:
    if type(mask) is bool:
        return mask
    if isinstance(mask, dict):
        return any(_any_true(value) for value in mask.values())
    if isinstance(mask, list):
        return any(_any_true(value) for value in mask)
    return True  # A malformed mask is never permission to disclose a value.


def _read(root: Any, tokens: tuple[Token, ...], sensitive: Any = False, unknown: Any = False) -> ValueState:
    current = root
    for token in (*tokens, _ABSENT):
        if sensitive is True:
            return ValueState(state="unknown", sensitive=True)
        if unknown is True:
            return ValueState(state="unknown")
        if token is _ABSENT:
            break
        current = _child(current, token)
        sensitive = _mask_child(sensitive, token)
        unknown = _mask_child(unknown, token)
    if not isinstance(current, (dict, list, tuple)) and _any_true(sensitive):
        return ValueState(state="unknown", sensitive=True)
    if not isinstance(current, (dict, list, tuple)) and _any_true(unknown):
        return ValueState(state="unknown")
    if current is _ABSENT:
        return ValueState(state="absent")
    if current is None:
        return ValueState(state="null")
    # A container-root fact asserts shape/existence, not all arbitrary contents.
    # This lets destruction evidence use prior existence without exporting tags.
    if isinstance(current, dict):
        return ValueState(state="known", value={})
    if isinstance(current, (list, tuple)):
        if _any_true(sensitive):
            return ValueState(state="unknown", sensitive=True)
        if _any_true(unknown):
            return ValueState(state="unknown")
        if any(isinstance(value, (dict, list, tuple)) for value in current):
            # No rule in policy v1 needs an arbitrary nested container as a fact.
            return ValueState(state="unknown")
        return ValueState(state="known", value=list(current))
    return ValueState(state="known", value=current)


def read_value(resource: ResourceChange, side: Side, tokens: tuple[Token, ...] = ()) -> ValueState:
    """Read a rule fact; sensitive and unknown ancestors dominate leaf contents.

    Known object roots return `{}` as a structural existence summary. Exact bytes
    remain pinned by the plan digest; arbitrary object values are never a fact.
    """
    if side in ("before", "after"):
        root = getattr(resource, side) if side in resource.model_fields_set else _ABSENT
        sensitive = getattr(resource, f"{side}_sensitive")
        unknown = resource.after_unknown if side == "after" else False
        return _read(root, tokens, sensitive, unknown)
    if side == "actions":
        return _read(list(resource.actions), tokens)
    if side == "metadata":
        metadata = {name: getattr(resource, name) for name in (
            "address", "deposed", "provider_name", "mode", "type", "name")
            if name in resource.model_fields_set}
        return _read(metadata, tokens)
    raise ValueError("invalid_evidence_side")


def _escape(token: Token) -> str:
    return str(token).replace("~", "~0").replace("/", "~1")


def _base(resource: ResourceChange, side: Side) -> str:
    root = f"/resource_changes/{resource.index}"
    return root if side == "metadata" else f"{root}/change/{side}"


def _raw_root(raw: dict[str, Any], index: int, side: Side) -> tuple[Any, Any, Any]:
    entry = raw["resource_changes"][index]
    if side == "metadata":
        return entry, False, False
    change = entry["change"]
    if side == "actions":
        return change.get("actions", _ABSENT), False, False
    return (change.get(side, _ABSENT), change.get(f"{side}_sensitive", False),
            change.get("after_unknown", False) if side == "after" else False)


def make_ref(plan: PlanDocument, resource: ResourceChange, side: Side,
             tokens: tuple[Token, ...] = (), role: Literal["decision", "supporting"] = "decision") -> EvidenceRef:
    if not any(item is resource for item in plan.resources):
        raise ValueError("resource_not_in_plan")
    root, sensitive, unknown = _raw_root(plan.raw, resource.index, side)
    expected = _read(root, tokens, sensitive, unknown)
    suffix = "".join(f"/{_escape(token)}" for token in tokens)
    return EvidenceRef(fact_id=uuid4().hex, plan_sha256=plan.identity.sha256,
                       resource_key=resource.key, resource_index=resource.index,
                       side=side, pointer=_base(resource, side) + suffix,
                       expected=expected, role=role)


def verify_unchanged(plan: PlanDocument) -> None:
    """Reopen only the pinned local path; fail the review on any byte mutation."""
    data = read_source_bytes(Path(plan.source_path))
    if hashlib.sha256(data).hexdigest() != plan.identity.sha256:
        raise SourceChangedError("source_digest_changed")


def _decode_pointer(pointer: str) -> tuple[str, ...]:
    if not pointer.startswith("/"):
        raise ValueError("pointer_malformed")
    parts = pointer[1:].split("/")
    if any(re.search(r"~(?:[^01]|$)", part) for part in parts):
        raise ValueError("pointer_escape_malformed")
    return tuple(part.replace("~1", "/").replace("~0", "~") for part in parts)


def _relative_tokens(root: Any, parts: tuple[str, ...], sensitive: Any = False,
                     unknown: Any = False) -> tuple[Token, ...]:
    result: list[Token] = []
    current = root
    for part in parts:
        token: Token = part
        if isinstance(current, list) or isinstance(sensitive, list) or isinstance(unknown, list):
            if re.fullmatch(r"0|[1-9][0-9]*", part) is None:
                raise ValueError("array_pointer_malformed")
            token = int(part)
        result.append(token)
        current = _child(current, token)
        sensitive = _mask_child(sensitive, token)
        unknown = _mask_child(unknown, token)
    return tuple(result)


def _checked_absence(root: Any, tokens: tuple[Token, ...]) -> bool:
    if not tokens:
        return root is _ABSENT
    current = root
    for token in tokens[:-1]:
        current = _child(current, token)
        if current is _ABSENT:
            return False
    if not isinstance(current, (dict, list, tuple)):
        return False
    return _child(current, tokens[-1]) is _ABSENT


def _same_json_value(actual: Any, expected: Any) -> bool:
    """Compare source facts without Python's Boolean/numeric coercion."""
    if type(actual) is not type(expected):
        return False
    if isinstance(actual, dict):
        return actual.keys() == expected.keys() and all(
            _same_json_value(value, expected[key]) for key, value in actual.items()
        )
    if isinstance(actual, (list, tuple)):
        return len(actual) == len(expected) and all(
            _same_json_value(left, right) for left, right in zip(actual, expected)
        )
    return actual == expected


def _pinned_raw(plan: PlanDocument) -> dict[str, Any]:
    data = read_source_bytes(Path(plan.source_path))
    if hashlib.sha256(data).hexdigest() != plan.identity.sha256:
        raise SourceChangedError("source_digest_changed")
    return decode_source(data)


def _resolve_checked(
    plan: PlanDocument, ref: EvidenceRef, raw_source: Callable[[], dict[str, Any]],
) -> ResolvedEvidence:
    """One checker for standalone reads and the explicit snapshot transaction."""
    empty = ValueState(state="absent")

    def result(status: Literal["resolved", "unknown", "sensitive", "missing", "mismatch"],
               value: ValueState = empty, reason: str = "") -> ResolvedEvidence:
        return ResolvedEvidence(ref=ref, status=status, value=value, reason=reason)

    if ref.plan_sha256 != plan.identity.sha256:
        return result("mismatch", reason="wrong_plan")
    resource = next((item for item in plan.resources if item.key == ref.resource_key), None)
    if resource is None or resource.index != ref.resource_index:
        return result("mismatch", reason="wrong_resource")
    # The standalone caller reopens here, preserving early identity rejection.
    # The batch caller supplies only its freshly reopened, digest-checked raw.
    raw = raw_source()
    try:
        entry = raw["resource_changes"][resource.index]
        if (entry.get("address"), entry.get("deposed")) != (resource.address, resource.deposed):
            return result("mismatch", reason="resource_identity_changed")
        for name in ("provider_name", "mode", "type", "name"):
            if entry.get(name) != getattr(resource, name):
                return result("mismatch", reason="resource_metadata_changed")
        base = _base(resource, ref.side)
        if ref.pointer != base and not ref.pointer.startswith(base + "/"):
            return result("mismatch", reason="wrong_side_or_index")
        decoded = _decode_pointer(ref.pointer)
        base_parts = _decode_pointer(base)
        if decoded[:len(base_parts)] != base_parts:
            return result("mismatch", reason="wrong_pointer_anchor")
        root, sensitive, unknown = _raw_root(raw, resource.index, ref.side)
        tokens = _relative_tokens(root, decoded[len(base_parts):], sensitive, unknown)
        actual = _read(root, tokens, sensitive, unknown)
        if actual != ref.expected or not _same_json_value(actual.value, ref.expected.value):
            return result("mismatch", actual, "value_or_mask_mismatch")
        if actual.sensitive:
            return result("sensitive", actual, "sensitive_value_withheld")
        if actual.state == "unknown":
            return result("unknown", actual, "unknown_value")
        if actual.state == "absent" and not _checked_absence(root, tokens):
            return result("missing", actual, "absence_parent_unavailable")
        return result("resolved", actual, "checked_absence" if actual.state == "absent" else "")
    except (KeyError, IndexError, TypeError, ValueError):
        return result("mismatch", reason="pointer_or_shape_malformed")


def resolve(plan: PlanDocument, ref: EvidenceRef) -> ResolvedEvidence:
    """Validate one fact against independently reopened and decoded source bytes."""
    return _resolve_checked(plan, ref, lambda: _pinned_raw(plan))


def resolve_many(
    plan: PlanDocument, refs: tuple[EvidenceRef, ...], *, deadline: float | None = None,
) -> tuple[ResolvedEvidence, ...]:
    """Resolve ordered refs atomically against one freshly verified snapshot.

    Entry and exit reopen the source. A transient mutation restored wholly
    between those boundaries may go unobserved; this is not continuous source
    monitoring. No raw snapshot or partial result escapes this invocation.
    """
    started = monotonic()
    if deadline is not None and (
        type(deadline) not in (int, float) or not math.isfinite(deadline)
    ):
        raise ValueError("deadline_invalid")
    end = started + MAX_SECONDS if deadline is None else min(deadline, started + MAX_SECONDS)

    def check_deadline() -> None:
        if monotonic() >= end:
            raise InputError("review_time_limit")

    check_deadline()
    raw = _pinned_raw(plan)
    check_deadline()
    results: list[ResolvedEvidence] = []
    for ref in refs:
        check_deadline()
        results.append(_resolve_checked(plan, ref, lambda: raw))
        check_deadline()
    # Refuse the entire transaction if closure cannot verify the original input.
    verify_unchanged(plan)
    check_deadline()
    return tuple(results)


__all__ = ["make_ref", "read_value", "resolve", "resolve_many", "verify_unchanged"]
