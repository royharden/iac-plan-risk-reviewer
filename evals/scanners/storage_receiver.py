"""Offline receiver foundations; payload/status policy awaits INT disposition.

This module does not establish global reservation or physical custody.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from . import storage_wire

CAPTURE_CAP = storage_wire.CAPTURE_CAP
STATUS_CAP = 65_536


class ReceiverError(ValueError):
    """Sanitized local precondition failure, without payload or path echo."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class InputSnapshot:
    kind: str
    token: tuple[int, ...]
    logical_bytes: int
    mode: int | None = None
    nlink: int | None = None
    owner_uid: int | None = None
    reparse: bool | None = None


class CaptureReader(Protocol):
    """Trusted cooperative adapter; b'' is EOF, never a temporary empty read."""

    def read(self, max_bytes: int) -> bytes: ...

    def snapshot(self) -> InputSnapshot: ...


@dataclass(frozen=True)
class ReceiveResult:
    outcome: str
    code: str
    wire_step: int | None = None
    capture_path: Path | None = None
    status_path: Path | None = None
    capture_bytes: int | None = None
    capture_charged_bytes: int = 0
    status_bytes: int | None = None
    status_charged_bytes: int = 0
    complete_sha256: str | None = None
    prefix_sha256: str | None = None
    status_committed: bool = False
    native_eligible: bool = False
    durable_verified: bool = False


class BytesReader:
    """Immutable synthetic input, with no invented filesystem observations."""

    def __init__(self, data: bytes):
        if type(data) is not bytes:
            raise ReceiverError("INPUT_TYPE")
        if len(data) > CAPTURE_CAP:
            raise ReceiverError("INPUT_CAP")
        self._data = data
        self._position = 0

    def read(self, max_bytes: int) -> bytes:
        if type(max_bytes) is not int or not 1 <= max_bytes <= CAPTURE_CAP + 1:
            raise ReceiverError("READ_BOUND")
        end = min(len(self._data), self._position + max_bytes)
        data = self._data[self._position:end]
        self._position = end
        return data

    def snapshot(self) -> InputSnapshot:
        return InputSnapshot("immutable-bytes", (len(self._data),), len(self._data))


class CaseReservation:
    """One-use local ceiling; never evidence of a global allocator or custody.

    A consumed instance remains consumed after every failure. No release API.
    """

    def __init__(self, capture_limit: int = CAPTURE_CAP, status_limit: int = STATUS_CAP):
        if type(capture_limit) is not int or not 1 <= capture_limit <= CAPTURE_CAP:
            raise ReceiverError("CAPTURE_BUDGET")
        if type(status_limit) is not int or not 1 <= status_limit <= STATUS_CAP:
            raise ReceiverError("STATUS_BUDGET")
        self._capture_limit = capture_limit
        self._status_limit = status_limit
        self._used = False

    @property
    def capture_limit(self) -> int:
        return self._capture_limit

    @property
    def status_limit(self) -> int:
        return self._status_limit

    @property
    def used(self) -> bool:
        return self._used

    def _consume(self) -> None:
        if self._used:
            raise ReceiverError("RESERVATION_USED")
        self._used = True
