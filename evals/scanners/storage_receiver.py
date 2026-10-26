"""Bounded offline receiver with exclusive, retained ordinary-file output.

This module does not establish global reservation or physical custody.
"""

from __future__ import annotations

import json
import math
import os
import stat
import time
from collections.abc import Callable
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import BinaryIO, Protocol

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
        data = self._data[self._position : end]
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


class ReceiverFS(Protocol):
    """Trusted cooperative IO seam, without cleanup or replacement operations."""

    def lstat(self, path: Path) -> os.stat_result: ...
    def fstat(self, handle: BinaryIO) -> os.stat_result: ...
    def open_exclusive(self, path: Path) -> BinaryIO: ...
    def open_read(self, path: Path) -> BinaryIO: ...
    def write(self, handle: BinaryIO, data: bytes) -> int: ...
    def read(self, handle: BinaryIO, max_bytes: int) -> bytes: ...
    def flush(self, handle: BinaryIO) -> None: ...
    def fsync(self, handle: BinaryIO) -> None: ...
    def close(self, handle: BinaryIO) -> None: ...


class OrdinaryFS:
    """Unbuffered local IO; observations are cooperative, not hostile-writer isolation."""

    def lstat(self, path: Path) -> os.stat_result:
        return path.lstat()

    def fstat(self, handle: BinaryIO) -> os.stat_result:
        return os.fstat(handle.fileno())

    def open_exclusive(self, path: Path) -> BinaryIO:
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        return os.fdopen(os.open(path, flags, 0o600), "wb", buffering=0)

    def open_read(self, path: Path) -> BinaryIO:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        return os.fdopen(os.open(path, flags), "rb", buffering=0)

    def write(self, handle: BinaryIO, data: bytes) -> int:
        return handle.write(data)

    def read(self, handle: BinaryIO, max_bytes: int) -> bytes:
        return handle.read(max_bytes)

    def flush(self, handle: BinaryIO) -> None:
        handle.flush()

    def fsync(self, handle: BinaryIO) -> None:
        os.fsync(handle.fileno())

    def close(self, handle: BinaryIO) -> None:
        handle.close()


_SEAL = object()
_CHUNK = 65_536


def _node(info: os.stat_result, *, directory: bool) -> tuple[int, int, int, int]:
    valid_type = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if not valid_type or getattr(info, "st_file_attributes", 0) & 0x400:
        raise ReceiverError("METADATA_TYPE")
    if not directory and info.st_nlink != 1:
        raise ReceiverError("METADATA_LINKS")
    owner = getattr(info, "st_uid", None)
    if not directory and hasattr(os, "getuid") and owner != os.getuid():
        raise ReceiverError("METADATA_OWNER")
    return info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode), owner


@dataclass(frozen=True)
class Destination:
    root: Path
    expected: storage_wire.Identity
    filesystem: ReceiverFS
    anchors: tuple[tuple[Path, tuple[int, int, int, int]], ...]
    _seal: object


def _anchors(destination: Destination) -> None:
    for path, identity in destination.anchors:
        if _node(destination.filesystem.lstat(path), directory=True) != identity:
            raise ReceiverError("ANCHOR_CHANGED")


def _absent(fs: ReceiverFS, path: Path) -> None:
    try:
        fs.lstat(path)
    except FileNotFoundError:
        return
    raise ReceiverError("DESTINATION_EXISTS")


def bind_destination(
    root: Path, *, expected: storage_wire.Identity, filesystem: ReceiverFS | None = None
) -> Destination:
    """Bind an existing ordinary namespace; never create files during admission."""
    if not isinstance(root, Path) or not root.is_absolute() or ".." in root.parts:
        raise ReceiverError("ROOT_PATH")
    if type(expected) is not storage_wire.Identity:
        raise ReceiverError("IDENTITY")
    fs = OrdinaryFS() if filesystem is None else filesystem
    try:
        anchors = tuple(
            (p, _node(fs.lstat(p), directory=True)) for p in (*reversed(root.parents), root)
        )
        if hasattr(os, "getuid") and anchors[-1][1][3] != os.getuid():
            raise ReceiverError("METADATA_OWNER")
        _absent(fs, root / expected.host_capture_name)
        _absent(fs, root / expected.host_status_name)
        destination = Destination(root, expected, fs, anchors, _SEAL)
        _anchors(destination)
        return destination
    except ReceiverError:
        raise
    except Exception:  # noqa: BLE001 - sanitize arbitrary trusted-adapter faults
        raise ReceiverError("DESTINATION_IO") from None


def _snapshot(value: InputSnapshot, owner: int | None) -> InputSnapshot:
    if (
        type(value) is not InputSnapshot
        or type(value.token) is not tuple
        or not 1 <= len(value.token) <= 16
        or any(type(v) is not int for v in value.token)
        or type(value.logical_bytes) is not int
        or not 0 <= value.logical_bytes <= CAPTURE_CAP
    ):
        raise ReceiverError("INPUT_SNAPSHOT")
    if value.kind == "immutable-bytes":
        if any(v is not None for v in (value.mode, value.nlink, value.owner_uid, value.reparse)):
            raise ReceiverError("INPUT_METADATA")
    elif value.kind == "ordinary-file":
        if (
            type(value.mode) is not int
            or not stat.S_ISREG(value.mode)
            or type(value.nlink) is not int
            or value.nlink != 1
            or value.reparse is not False
            or type(value.owner_uid) is not int
            or value.owner_uid != owner
        ):
            raise ReceiverError("INPUT_METADATA")
    else:
        raise ReceiverError("INPUT_KIND")
    return value


class _Fault(Exception):
    pass


def receive_capture(
    reader: CaptureReader,
    *,
    expected: storage_wire.Identity,
    destination: Destination,
    reservation: CaseReservation,
    deadline: float,
    clock: Callable[[], float] = time.monotonic,
) -> ReceiveResult:
    """Validate before creation; retain failures without retry, overwrite or cleanup.

    COMPLETE describes a verified local copy, never successful scanner arms. Both
    eligibility flags remain false even for a structurally complete capture.
    """
    if (
        type(expected) is not storage_wire.Identity
        or type(destination) is not Destination
        or destination._seal is not _SEAL
        or destination.expected != expected
        or type(reservation) is not CaseReservation
    ):
        raise ReceiverError("ADMISSION")
    if type(deadline) not in (int, float) or not math.isfinite(deadline):
        raise ReceiverError("DEADLINE")
    reservation._consume()
    fs = destination.filesystem
    capture_path = destination.root / expected.host_capture_name
    status_path = destination.root / expected.host_status_name
    fault: str | None = None
    wire_step: int | None = None
    expired = False
    unknown = False
    created_capture = False
    created_status = False
    capture_count = 0
    status_count = 0
    capture_charge = 0
    status_charge = 0
    prefix_hash: str | None = None
    complete_hash: str | None = None
    committed = False
    stage = "INPUT_IO"
    created_identities: dict[Path, tuple] = {}
    verified_files: dict[Path, tuple] = {}

    def latch(code: str) -> None:
        nonlocal fault
        if fault is None:
            fault = code

    def check() -> None:
        nonlocal expired
        try:
            now = clock()
        except Exception:  # noqa: BLE001 - sanitize arbitrary trusted-adapter faults
            latch("CLOCK")
            expired = True
            raise _Fault from None
        if type(now) not in (int, float) or not math.isfinite(now):
            latch("CLOCK")
            expired = True
            raise _Fault
        if now >= deadline:
            latch("DEADLINE")
            expired = True
            raise _Fault

    def call(fn, *args):
        check()
        result = fn(*args)
        check()
        return result

    def anchors() -> None:
        call(_anchors, destination)

    def file_identity(handle, path):
        anchors()
        held = call(fs.fstat, handle)
        named = call(fs.lstat, path)
        a = _node(held, directory=False)
        if (
            a != _node(named, directory=False)
            or held.st_size != named.st_size
            or a[3] != destination.anchors[-1][1][3]
        ):
            raise ReceiverError("OUTPUT_CHANGED")
        return a, held.st_size

    def close(handle) -> bool:
        # Unbuffered default handles cannot flush additional payload on close.
        # Closing remains mandatory even after deadline or a first fault.
        try:
            fs.close(handle)
            return True
        except Exception:  # noqa: BLE001 - sanitize arbitrary trusted-adapter faults
            latch("CLOSE_IO")
            return False

    def write_blob(path: Path, data: bytes, *, status: bool) -> bool:
        nonlocal created_capture, created_status, capture_count, status_count
        nonlocal capture_charge, status_charge, unknown
        anchors()
        call(_absent, fs, path)
        check()
        handle = fs.open_exclusive(path)
        if status:
            created_status = True
        else:
            created_capture = True
        try:
            check()
            identity, size = file_identity(handle, path)
            created_identities[path] = identity
            if size != 0:
                raise ReceiverError("OUTPUT_SIZE")
            for offset in range(0, len(data), _CHUNK):
                anchors()
                check()
                chunk = data[offset : offset + _CHUNK]
                try:
                    count = fs.write(handle, chunk)
                except Exception:  # noqa: BLE001 - sanitize arbitrary trusted-adapter faults
                    unknown = True
                    if status:
                        status_charge += len(chunk)
                    else:
                        capture_charge += len(chunk)
                    latch("WRITE_UNKNOWN")
                    raise _Fault from None
                if type(count) is not int or not 0 <= count <= len(chunk):
                    unknown = True
                    if status:
                        status_charge += len(chunk)
                    else:
                        capture_charge += len(chunk)
                    latch("WRITE_UNKNOWN")
                    raise _Fault
                if status:
                    status_count += count
                    status_charge += count
                else:
                    capture_count += count
                    capture_charge += count
                # Count the observed write even if the clock expires on return.
                check()
                if count != len(chunk):
                    latch("SHORT_WRITE")
                    raise _Fault
                current, size = file_identity(handle, path)
                if current != identity or size != offset + count:
                    raise ReceiverError("OUTPUT_CHANGED")
            call(fs.flush, handle)
            call(fs.fsync, handle)
            current, size = file_identity(handle, path)
            if current != identity or size != len(data):
                raise ReceiverError("OUTPUT_CHANGED")
        except ReceiverError as exc:
            latch(exc.code)
            raise
        except _Fault:
            raise
        except Exception:
            latch("STATUS_IO" if status else "CAPTURE_IO")
            raise
        finally:
            if not close(handle):
                raise _Fault
        return True

    def readback(path: Path, data: bytes) -> str:
        anchors()
        before = call(fs.lstat, path)
        identity = created_identities[path]
        if _node(before, directory=False) != identity:
            raise ReceiverError("READBACK_CHANGED")
        if before.st_size != len(data):
            raise ReceiverError("READBACK_SIZE")
        check()
        handle = fs.open_read(path)
        try:
            check()
            held, size = file_identity(handle, path)
            if held != identity or size != len(data):
                raise ReceiverError("READBACK_CHANGED")
            offset = 0
            digest = sha256()
            while offset < len(data):
                maximum = min(_CHUNK, len(data) - offset)
                part = call(fs.read, handle, maximum)
                if type(part) is not bytes or not part or len(part) > maximum:
                    raise ReceiverError("READBACK_LENGTH")
                if part != data[offset : offset + len(part)]:
                    raise ReceiverError("READBACK_MISMATCH")
                digest.update(part)
                offset += len(part)
            if call(fs.read, handle, 1) != b"":
                raise ReceiverError("READBACK_EOF")
            held, size = file_identity(handle, path)
            after = call(fs.lstat, path)
            if (
                held != identity
                or size != len(data)
                or _node(after, directory=False) != identity
                or after.st_size != len(data)
                or after.st_mtime_ns != before.st_mtime_ns
                or after.st_ctime_ns != before.st_ctime_ns
            ):
                raise ReceiverError("READBACK_CHANGED")
            check()
            verified_files[path] = (identity, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            return digest.hexdigest()
        except ReceiverError as exc:
            latch(exc.code)
            raise
        except _Fault:
            raise
        except Exception:
            latch("READBACK_IO")
            raise
        finally:
            if not close(handle):
                raise _Fault

    payload = b""
    validated = False
    try:
        anchors()
        call(_absent, fs, capture_path)
        call(_absent, fs, status_path)
        owner = destination.anchors[-1][1][3]
        initial = _snapshot(call(reader.snapshot), owner)
        buffer = bytearray()
        limit = min(reservation.capture_limit, CAPTURE_CAP)
        while True:
            maximum = min(_CHUNK, limit + 1 - len(buffer))
            part = call(reader.read, maximum)
            if type(part) is not bytes or len(part) > maximum:
                raise ReceiverError("INPUT_READ_BOUND")
            if not part:
                break
            buffer.extend(part)
            if len(buffer) > limit:
                raise ReceiverError("INPUT_CAP")
        if _snapshot(call(reader.snapshot), owner) != initial:
            raise ReceiverError("INPUT_CHANGED")
        if len(buffer) != initial.logical_bytes:
            raise ReceiverError("INPUT_LENGTH")
        payload = bytes(buffer)
        check()
        capture = storage_wire.decode_framing(payload, expected=expected)
        check()
        storage_wire.validate_state(capture)
        check()
        validated = True
        stage = "CAPTURE_IO"
        write_blob(capture_path, payload, status=False)
        stage = "READBACK_IO"
        complete_hash = readback(capture_path, payload)
        if fault is not None:
            complete_hash = None
    except storage_wire.WireError as exc:
        latch(exc.code)
        wire_step = exc.step
    except ReceiverError as exc:
        latch(exc.code)
    except _Fault:
        pass
    except Exception:  # noqa: BLE001 - sanitize arbitrary trusted-adapter faults
        latch(stage)

    # Only independently read-back, known-count bytes can have a prefix digest.
    if created_capture and not unknown and not expired:
        try:
            prefix_hash = readback(capture_path, payload[:capture_count])
        except ReceiverError as exc:
            latch(exc.code)
            complete_hash = None
        except _Fault:
            complete_hash = None
        except Exception:  # noqa: BLE001 - sanitize arbitrary trusted-adapter faults
            latch("PREFIX_READBACK_IO")
            complete_hash = None

    if not unknown and not expired:
        try:
            check()
            local = {
                "kind": "local-receiver-v1-diagnostic",
                "phase": expected.phase,
                "wire_ordinal": expected.wire_ordinal,
                "case_ordinal": expected.case_ordinal,
                "code": fault or "OK",
                "wire_step": wire_step,
                "capture_bytes": capture_count if created_capture else None,
                "capture_charged_bytes": capture_charge,
                "complete_sha256": complete_hash if fault is None else None,
                "prefix_sha256": prefix_hash,
                "native_eligible": False,
                "durable_verified": False,
            }
            diagnostic = (json.dumps(local, sort_keys=True, separators=(",", ":")) + "\n").encode()
            check()
            if len(diagnostic) > reservation.status_limit:
                raise ReceiverError("STATUS_CAP")
            stage = "STATUS_IO"
            write_blob(status_path, diagnostic, status=True)
            readback(status_path, diagnostic)
            check()
            committed = True
        except ReceiverError as exc:
            latch(exc.code)
        except _Fault:
            pass
        except Exception:  # noqa: BLE001 - sanitize arbitrary trusted-adapter faults
            latch(stage)

    try:
        anchors()
        for path, identity in created_identities.items():
            info = call(fs.lstat, path)
            current = (
                _node(info, directory=False),
                info.st_size,
                info.st_mtime_ns,
                info.st_ctime_ns,
            )
            if current[0] != identity or (
                path in verified_files and current != verified_files[path]
            ):
                prefix_hash = None
                committed = False
                raise ReceiverError("OUTPUT_CHANGED")
        check()
    except ReceiverError as exc:
        latch(exc.code)
        prefix_hash = None
        committed = False
    except _Fault:
        committed = False
    except Exception:  # noqa: BLE001 - sanitize arbitrary trusted-adapter faults
        latch("FINAL_METADATA_IO")
        prefix_hash = None
        committed = False
    if fault is not None:
        complete_hash = None
    outcome = (
        "COMPLETE"
        if fault is None
        else ("UNKNOWN" if unknown else ("INCOMPLETE" if validated else "REFUSED"))
    )
    return ReceiveResult(
        outcome=outcome,
        code=fault or "OK",
        wire_step=wire_step,
        capture_path=capture_path if created_capture else None,
        status_path=status_path if created_status else None,
        capture_bytes=None
        if unknown and not created_status
        else (capture_count if created_capture else None),
        capture_charged_bytes=capture_charge,
        status_bytes=None
        if unknown and created_status
        else (status_count if created_status else None),
        status_charged_bytes=status_charge,
        complete_sha256=complete_hash,
        prefix_sha256=prefix_hash,
        status_committed=committed,
    )
