"""Finite offline wire producer; no paths, source opening, or custody authority.

Readers and their observations are trusted cooperative injections. Validation
establishes framed DATA consistency, never actual scanner execution or custody.
"""

from __future__ import annotations

import math
import stat
import struct
import time
from collections.abc import Callable
from dataclasses import dataclass
from hashlib import sha256

from . import storage_wire
from .storage_receiver import BytesReader, CaptureReader, InputSnapshot

__all__ = [
    "BytesReader",
    "CaptureReader",
    "ExportError",
    "ExportRecord",
    "InputSnapshot",
    "encode_capture",
]

_FIXED_BYTES = 80 + 23 * 52 + 50
_CHUNK = 65_536
_U64 = (1 << 64) - 1


def _finite_time(value: object) -> bool:
    # Integers are finite without a lossy float conversion (which may overflow).
    return type(value) is int or type(value) is float and math.isfinite(value)


class ExportError(ValueError):
    """Sanitized bounded failure, retaining frozen wire classifications."""

    def __init__(self, code: str, wire_step: int | None = None, record_id: int | None = None):
        self.code = code
        self.wire_step = wire_step
        self.record_id = record_id
        super().__init__(code)


@dataclass(frozen=True)
class ExportRecord:
    record_id: int
    state: int
    reason: int
    logical_bytes: int | None
    source: CaptureReader | None


def _snapshot(value: InputSnapshot, owner_uid: int | None) -> InputSnapshot:
    if (
        type(value) is not InputSnapshot
        or type(value.token) is not tuple
        or not 1 <= len(value.token) <= 16
        or any(type(v) is not int for v in value.token)
        or type(value.logical_bytes) is not int
        or not 0 <= value.logical_bytes <= storage_wire.CAPTURE_CAP
    ):
        raise ExportError("INPUT_SNAPSHOT")
    if value.kind == "immutable-bytes":
        if any(v is not None for v in (value.mode, value.nlink, value.owner_uid, value.reparse)):
            raise ExportError("INPUT_METADATA")
    elif value.kind == "ordinary-file":
        if (
            owner_uid is None
            or type(value.mode) is not int
            or not stat.S_ISREG(value.mode)
            or type(value.nlink) is not int
            or value.nlink != 1
            or type(value.owner_uid) is not int
            or value.owner_uid != owner_uid
            or value.reparse is not False
        ):
            raise ExportError("INPUT_METADATA")
    else:
        raise ExportError("INPUT_KIND")
    return value


def encode_capture(
    records: tuple[ExportRecord, ...],
    *,
    expected: storage_wire.Identity,
    deadline: float,
    clock: Callable[[], float] = time.monotonic,
    owner_uid: int | None = None,
) -> bytes:
    """Return one complete framed capture or raise; never invent record contents.

    Caller-supplied partial/missing/rejected records retain those states. Even
    all-complete consistent DATA cannot assert native or physical eligibility.
    """
    if not _finite_time(deadline):
        raise ExportError("DEADLINE")
    if owner_uid is not None and (type(owner_uid) is not int or owner_uid < 0):
        raise ExportError("OWNER_UID")
    if type(expected) is not storage_wire.Identity:
        raise ExportError("IDENTITY", 2)
    if type(records) is not tuple or len(records) != 23:
        raise ExportError("RECORD_COUNT", 3)

    def check() -> None:
        try:
            now = clock()
        except Exception:  # noqa: BLE001 - sanitize trusted cooperative clock failures
            raise ExportError("CLOCK") from None
        if not _finite_time(now):
            raise ExportError("CLOCK")
        if now >= deadline:
            raise ExportError("DEADLINE")

    def observe(source: CaptureReader) -> InputSnapshot:
        check()
        try:
            value = source.snapshot()
        except Exception:  # noqa: BLE001 - no arbitrary source error text escapes
            raise ExportError("INPUT_IO") from None
        check()
        return _snapshot(value, owner_uid)

    check()
    # Validate the complete record roster before invoking any source adapter.
    for ordinal, record in enumerate(records, 1):
        if (
            type(record) is not ExportRecord
            or type(record.record_id) is not int
            or record.record_id != ordinal
        ):
            raise ExportError("RECORD_ORDINAL", 3, ordinal)
        if (
            type(record.state) is not int
            or record.state not in (0, 1, 2, 3)
            or type(record.reason) is not int
            or not 0 <= record.reason <= 255
            or record.logical_bytes is not None
            and (type(record.logical_bytes) is not int or not 0 <= record.logical_bytes <= _U64)
        ):
            raise ExportError("STATE_ENCODING", 4, ordinal)
        if (record.state in (0, 3)) != (record.source is None):
            raise ExportError("SOURCE_STATE", 4, ordinal)
    check()

    try:
        snapshots: dict[int, InputSnapshot] = {}
        total = _FIXED_BYTES
        for record in records:
            rid = record.record_id
            retained = 0
            if record.source is not None:
                snapshot = observe(record.source)
                snapshots[rid] = snapshot
                retained = snapshot.logical_bytes
            logical = record.logical_bytes if record.logical_bytes is not None else 0
            known = int(record.logical_bytes is not None)
            sentinel = bytes(32) if record.state in (0, 3) else sha256(b"").digest()
            # Reuse the frozen decoder's state and roster grammar; no copied catalog.
            storage_wire._frame_state(
                rid, record.state, record.reason, known, logical, retained, sentinel
            )
            cap = storage_wire._CAPS[rid - 1]
            if (
                retained > cap
                or record.state in (1, 2)
                and logical > cap
                or record.state == 1
                and logical != retained
                or record.state == 2
                and not 0 <= retained < logical
                or record.state == 3
                and record.reason == 4
                and logical <= cap
            ):
                raise ExportError("LENGTH_CAP", 5, rid)
            total += retained
            if total > storage_wire.CAPTURE_CAP:
                raise ExportError("LENGTH_CAP", 5, rid)
            check()

        phase = int(expected.phase == "dev-primary-r1")
        output = bytearray(
            struct.pack(
                ">8sHBBHH32s32s",
                b"M4CAP02\n",
                2,
                phase,
                expected.wire_ordinal,
                23,
                0,
                bytes.fromhex(expected.e_sha256),
                bytes.fromhex(expected.slot_manifest_sha256),
            )
        )
        check()
        for record in records:
            payload = bytearray()
            if record.source is not None:
                before = snapshots[record.record_id]
                while True:
                    maximum = min(_CHUNK, before.logical_bytes + 1 - len(payload))
                    check()
                    try:
                        part = record.source.read(maximum)
                    except Exception:  # noqa: BLE001 - sanitize injected reader failures
                        raise ExportError("INPUT_IO", record_id=record.record_id) from None
                    check()
                    if type(part) is not bytes or len(part) > maximum:
                        raise ExportError("INPUT_READ_BOUND", record_id=record.record_id)
                    if not part:
                        break
                    payload.extend(part)
                    if len(payload) > before.logical_bytes:
                        raise ExportError("INPUT_LENGTH", record_id=record.record_id)
                if len(payload) != before.logical_bytes:
                    raise ExportError("INPUT_LENGTH", record_id=record.record_id)
                if observe(record.source) != before:
                    raise ExportError("INPUT_CHANGED", record_id=record.record_id)
            check()
            digest = sha256(payload).digest() if record.state in (1, 2) else bytes(32)
            check()
            output.extend(
                struct.pack(
                    ">BBBBQQ32s",
                    record.record_id,
                    record.state,
                    record.reason,
                    int(record.logical_bytes is not None),
                    record.logical_bytes or 0,
                    len(payload),
                    digest,
                )
            )
            output.extend(payload)
            check()
        digest = sha256(output).digest()
        check()
        output.extend(struct.pack(">8sHQ32s", b"M4END02\n", 23, len(output), digest))
        if len(output) != total or len(output) > storage_wire.CAPTURE_CAP:
            raise ExportError("LENGTH_CAP", 5)
        raw = bytes(output)
        check()
        capture = storage_wire.decode_framing(raw, expected=expected)
        check()
        storage_wire.validate_state(capture)
        check()
        # Reobserve all sources after later adapters and validation have run.
        for record in records:
            if record.source is not None and observe(record.source) != snapshots[record.record_id]:
                raise ExportError("INPUT_CHANGED", record_id=record.record_id)
        check()
        return raw
    except storage_wire.WireError as exc:
        raise ExportError(exc.code, exc.step, exc.record_id) from None
