"""Pure, bounded M4 storage wire v3 decoding.

Binary framing remains version 2; generated metadata is version 3. Original
records are opaque bytes. Structural validation never establishes native
eligibility, source truth, reservation consumption, or durable custody.
"""

from __future__ import annotations

import json
import re
import struct
from dataclasses import dataclass
from hashlib import sha256

CAPTURE_CAP = 16_777_216
_U64 = (1 << 64) - 1
_ARMS = ("C", "C-custom", "T")
_STATES = ("missing", "complete", "partial", "rejected")
_ERRORS = {
    1: "HEADER_SYNTAX",
    2: "IDENTITY_BINDING",
    3: "RECORD_ORDINAL",
    4: "STATE_ENCODING",
    5: "LENGTH_CAP",
    6: "PAYLOAD_EOF_OR_IO",
    7: "PAYLOAD_HASH",
    8: "GENERATED_SCHEMA_OR_CANONICAL",
    9: "TRAILER",
    10: "TRAILING_BYTES",
    11: "STATE_OR_CLOSURE_INCOMPLETE",
}


class WireError(ValueError):
    """Finite error classification; messages never contain input payloads."""

    def __init__(self, code: str, step: int, record_id: int | None = None):
        self.code = code
        self.step = step
        self.record_id = record_id
        super().__init__(f"{code} (step {step}, record {record_id})")


class FramingError(WireError):
    """Steps 1..10: framing, per-frame state, metadata, or identity failure."""


class StateError(WireError):
    """Step 11: contradictory cross-record state assertions."""


def _fail(step: int, record_id: int | None = None) -> None:
    cls = StateError if step == 11 else FramingError
    raise cls(_ERRORS[step], step, record_id)


@dataclass(frozen=True)
class Identity:
    phase: str
    wire_ordinal: int
    e_sha256: str
    slot_manifest_sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.phase) is not str
            or self.phase not in ("dev-compat-r1", "dev-primary-r1")
            or type(self.wire_ordinal) is not int
            or not 1 <= self.wire_ordinal <= 24
            or (self.phase, self.wire_ordinal) not in _IDENTITIES
            or any(
                type(s) is not str or len(s) != 64 or re.fullmatch(r"[0-9a-f]{64}", s) is None
                for s in (self.e_sha256, self.slot_manifest_sha256)
            )
        ):
            _fail(2)

    @property
    def case_ordinal(self) -> int:
        return _IDENTITIES[self.phase, self.wire_ordinal][0]

    @property
    def case_id(self) -> str:
        return _IDENTITIES[self.phase, self.wire_ordinal][1]

    @property
    def slot(self) -> str:
        return f"c{self.case_ordinal:02d}"

    @property
    def host_capture_name(self) -> str:
        return f"{self.phase}-{self.slot}.capture"

    @property
    def host_status_name(self) -> str:
        return f"{self.phase}-{self.slot}.status.json"


@dataclass(frozen=True)
class Record:
    record_id: int
    state: int
    reason: int
    logical_known: bool
    logical_length: int
    retained_length: int
    retained_sha256: str
    payload: bytes


@dataclass(frozen=True)
class Capture:
    identity: Identity
    records: tuple[Record, ...]
    sha256: str


@dataclass(frozen=True)
class StateValidation:
    arm_states: tuple[str, str, str]
    required_records_present: bool
    native_eligible: bool = False
    durable_verified: bool = False


def canonical_json(value: object) -> bytes:
    """Encode the finite CANONICAL-JSON-v2 grammar, with bounded traversal.

    This grammar check is separate from each record's tighter closed schema.
    The top level is an object; depth includes that object as level one.
    """
    out = bytearray()

    def emit(part: bytes) -> None:
        if len(part) > CAPTURE_CAP - len(out):
            _fail(8)
        out.extend(part)

    def string(s: str, maximum: int = 256) -> None:
        if len(s) > maximum or any(not 32 <= ord(c) <= 126 for c in s):
            _fail(8)
        emit(b'"' + s.replace("\\", "\\\\").replace('"', '\\"').encode("ascii") + b'"')

    def visit(v: object, depth: int) -> None:
        if depth > 8:
            _fail(8)
        if type(v) is dict:
            # Bound key sorting before allocating a key copy.
            if len(v) > CAPTURE_CAP // 4 or any(type(k) is not str for k in v):
                _fail(8)
            for key in v:
                if len(key) > 64 or any(not 32 <= ord(c) <= 126 for c in key):
                    _fail(8)
            emit(b"{")
            for index, key in enumerate(sorted(v)):
                if index:
                    emit(b",")
                string(key, 64)
                emit(b":")
                visit(v[key], depth + 1)
            emit(b"}")
        elif type(v) is list:
            if len(v) > CAPTURE_CAP // 2:
                _fail(8)
            emit(b"[")
            for index, item in enumerate(v):
                if index:
                    emit(b",")
                visit(item, depth + 1)
            emit(b"]")
        elif type(v) is str:
            string(v)
        elif v is None:
            emit(b"null")
        elif type(v) is bool:
            emit(b"true" if v else b"false")
        elif type(v) is int and 0 <= v <= _U64:
            emit(str(v).encode("ascii"))
        else:
            _fail(8)

    if type(value) is not dict:
        _fail(8)
    visit(value, 1)
    emit(b"\n")
    return bytes(out)


def _schema(value: object, rule: dict) -> bool:
    """Validate only the finite schema vocabulary used by records 17..23."""
    if "anyOf" in rule:
        return any(_schema(value, branch) for branch in rule["anyOf"])
    if "const" in rule:
        return type(value) is type(rule["const"]) and value == rule["const"]
    if "enum" in rule and not any(type(value) is type(v) and value == v for v in rule["enum"]):
        return False
    kind = rule.get("type")
    if kind == "object":
        if type(value) is not dict:
            return False
        props = rule["properties"]
        return (
            set(value) <= set(props)
            and set(rule["required"]) <= set(value)
            and all(_schema(v, props[k]) for k, v in value.items())
        )
    if kind == "array":
        return (
            type(value) is list
            and rule["minItems"] <= len(value) <= rule["maxItems"]
            and all(_schema(v, rule["items"]) for v in value)
        )
    if kind == "integer":
        return type(value) is int and rule["minimum"] <= value <= rule["maximum"]
    if kind == "string":
        return (
            type(value) is str
            and rule["minLength"] <= len(value) <= rule["maxLength"]
            and re.fullmatch(rule["pattern"], value) is not None
        )
    if kind == "boolean":
        return type(value) is bool
    if kind == "null":
        return value is None
    return "enum" in rule


def _metadata(payload: bytes, record_id: int) -> dict:
    # Inspect finite bytes BEFORE JSON parsing, especially its recursive descent.
    depth = 0
    quoted = escaped = False
    for byte in payload:
        if byte > 126 or byte < 32 and byte != 10:
            _fail(8, record_id)
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > 8:
                _fail(8, record_id)
        elif byte in (93, 125):
            depth -= 1
            if depth < 0:
                _fail(8, record_id)

    def pairs(items: list[tuple[str, object]]) -> dict:
        result = {}
        for key, value in items:
            if key in result:
                _fail(8, record_id)
            result[key] = value
        return result

    def integer(token: str) -> int:
        if len(token) > 20 or not token.isascii() or not token.isdecimal():
            _fail(8, record_id)
        number = int(token)
        if number > _U64:
            _fail(8, record_id)
        return number

    def reject_number(token: str) -> None:
        _fail(8, record_id)

    try:
        value = json.loads(
            payload,
            object_pairs_hook=pairs,
            parse_int=integer,
            parse_float=reject_number,
            parse_constant=reject_number,
        )
        if canonical_json(value) != payload or not _schema(value, _SCHEMAS[record_id]):
            _fail(8, record_id)
    except (ValueError, RecursionError, UnicodeError) as exc:
        if isinstance(exc, FramingError) and exc.record_id == record_id:
            raise
        raise FramingError(_ERRORS[8], 8, record_id) from None
    return value


def _identity_fields(identity: Identity) -> dict:
    return {
        "version": 3,
        "phase": identity.phase,
        "wire_ordinal": identity.wire_ordinal,
        "E_sha256": identity.e_sha256,
        "slot_manifest_sha256": identity.slot_manifest_sha256,
        "case_ordinal": identity.case_ordinal,
        "case_id": identity.case_id,
        "slot": identity.slot,
        "host_capture_name": identity.host_capture_name,
        "host_status_name": identity.host_status_name,
    }


def _frame_state(
    rid: int, state: int, reason: int, known: int, logical: int, retained: int, digest: bytes
) -> None:
    sentinel = digest == bytes(32)
    if known not in (0, 1):
        _fail(4, rid)
    if state == 0:
        allowed = (1, 2) if rid <= 12 else (2,) if rid <= 16 else (2, 8)
        if reason not in allowed or known or logical or retained or not sentinel:
            _fail(4, rid)
    elif state == 1:
        if reason != 0 or known != 1:
            _fail(4, rid)
    elif state == 2:
        if rid > 16 or reason != 3 or known != 1:
            _fail(4, rid)
    elif state == 3:
        if (
            reason not in (4, 5, 6, 7, 9)
            or retained
            or not sentinel
            or not known
            and logical
            or reason == 4
            and not known
        ):
            _fail(4, rid)
    else:
        _fail(4, rid)


def decode_framing(data: bytes, *, expected: Identity) -> Capture:
    """Decode frozen steps 1..10, without paths, writes, or native operations."""
    if type(data) is not bytes or len(data) < 80:
        _fail(1)
    magic, version, phase, ordinal, count, flags, ehash, mhash = struct.unpack_from(
        ">8sHBBHH32s32s", data
    )
    if (
        magic != b"M4CAP02\n"
        or version != 2
        or flags
        or count != 23
        or phase not in (0, 1)
        or not 1 <= ordinal <= (4 if phase == 0 else 24)
    ):
        _fail(1)
    identity = Identity(
        ("dev-compat-r1", "dev-primary-r1")[phase], ordinal, ehash.hex(), mhash.hex()
    )
    if type(expected) is not Identity or identity != expected:
        _fail(2)
    # No payload slicing, metadata parsing, or hashing an overcap input.
    if len(data) > CAPTURE_CAP:
        _fail(5)
    view = memoryview(data)
    offset = 80
    records = []
    metadata = {}
    offsets = {}
    for rid in range(1, 24):
        offsets[rid] = offset
        if len(data) - offset < 52:
            _fail(3, rid)
        got, state, reason, known, logical, retained, digest = struct.unpack_from(
            ">BBBBQQ32s", data, offset
        )
        if got != rid:
            _fail(3, rid)
        _frame_state(rid, state, reason, known, logical, retained, digest)
        offset += 52
        cap = _CAPS[rid - 1]
        if (
            retained > cap
            or state in (1, 2)
            and logical > cap
            or state == 1
            and logical != retained
            or state == 2
            and not 0 <= retained < logical
            or state == 3
            and reason == 4
            and logical <= cap
            or retained > CAPTURE_CAP - offset - (23 - rid) * 52 - 50
        ):
            _fail(5, rid)
        if retained > len(data) - offset:
            _fail(6, rid)
        payload_view = view[offset : offset + retained]
        if state in (1, 2) and sha256(payload_view).digest() != digest:
            _fail(7, rid)
        payload = bytes(payload_view)
        record = Record(rid, state, reason, bool(known), logical, retained, digest.hex(), payload)
        records.append(record)
        if rid >= 17 and state == 1:
            value = _metadata(payload, rid)
            if any(value[k] != v for k, v in _identity_fields(identity).items()):
                _fail(8, rid)
            if rid == 17:
                for item, original in zip(value["originals"], records[:16]):
                    if (
                        item["id"] != original.record_id
                        or item["state"] != _STATES[original.state]
                        or item["logical_bytes"]
                        != (original.logical_length if original.logical_known else None)
                        or item["retained_bytes"] != original.retained_length
                        or item["retained_sha256"]
                        != (original.retained_sha256 if original.state in (1, 2) else None)
                    ):
                        _fail(8, rid)
                if [v["id"] for v in value["generated_presence"]] != list(range(17, 24)) or tuple(
                    v["arm"] for v in value["arm_states"]
                ) != _ARMS:
                    _fail(8, rid)
            if rid == 19 and tuple(v["arm"] for v in value["invocations"]) != _ARMS:
                _fail(8, rid)
            if rid == 21 and (
                value["observed_capture_bytes_before_record21"] != offsets[21]
                or value["phase_allocated_bytes"] != (201326592 if phase == 0 else 536870912)
            ):
                _fail(8, rid)
            metadata[rid] = value
        offset += retained
    if 17 in metadata:
        for item, record in zip(metadata[17]["generated_presence"], records[16:]):
            if item["state"] != _STATES[record.state]:
                _fail(8, 17)
    if len(data) - offset < 50:
        _fail(9)
    magic, count, preceding, digest = struct.unpack_from(">8sHQ32s", data, offset)
    if (
        magic != b"M4END02\n"
        or count != 23
        or preceding != offset
        or digest != sha256(view[:offset]).digest()
    ):
        _fail(9)
    if offset + 50 != len(data):
        _fail(10)
    return Capture(identity, tuple(records), sha256(data).hexdigest())


def validate_state(capture: Capture) -> StateValidation:
    """Classify step 11; missing/failed proof never becomes native acceptance.

    Call with a capture returned by decode_framing. No opaque start/terminal
    bytes are interpreted as native evidence by this module.
    Arm labels are finite: unstarted, started, finished, aborted, or unknown.
    """
    if (
        type(capture) is not Capture
        or type(capture.records) is not tuple
        or len(capture.records) != 23
        or any(type(r) is not Record for r in capture.records)
    ):
        _fail(11)
    records = capture.records
    if tuple(r.record_id for r in records) != tuple(range(1, 24)):
        _fail(11)
    meta = {r.record_id: _metadata(r.payload, r.record_id) for r in records[16:] if r.state == 1}
    declared = [v["state"] for v in meta[17]["arm_states"]] if 17 in meta else None
    states = []
    for index in range(3):
        arm = [records[index + offset] for offset in (0, 3, 6, 9)]
        unstarted = all(r.state == 0 and r.reason == 1 for r in arm)
        # Any observed/unknown start forbids claiming other originals unstarted.
        if not unstarted and any(r.state == 0 and r.reason == 1 for r in arm):
            _fail(11, arm[0].record_id)
        observed = (
            "unstarted"
            if unstarted
            else "unknown"
            if arm[0].state != 1
            else "finished"
            if all(r.state == 1 for r in arm)
            else "aborted"
            if any(r.state in (2, 3) for r in arm)
            else "started"
            if arm[0].state == 1
            else "unknown"
        )
        state = declared[index] if declared is not None else observed
        if (
            state == "unstarted"
            and not unstarted
            or state == "finished"
            and not all(r.state == 1 for r in arm)
            or state == "started"
            and (arm[0].state != 1 or arm[3].state == 1)
            or state == "aborted"
            and unstarted
        ):
            _fail(11, arm[0].record_id)
        states.append(state)
    required = all(r.state == 1 for r in records)
    if 22 in meta:
        status = meta[22]
        # Required/candidate execution needs a declared normal driver finish;
        # complete preservation alone may still describe an incomplete run.
        driver_finished = 23 in meta and meta[23]["driver_terminal"] == "normal"
        failed = (
            status["original_failure_observed"]
            or "aborted" in states
            or any(r.state in (2, 3) for r in records)
            or 23 in meta
            and meta[23]["driver_terminal"] == "error"
        )
        if (
            status["required_capture"] == "complete-candidate"
            and (not required or not driver_finished)
            or status["original_execution"] == "candidate"
            and (
                failed
                or not required
                or not driver_finished
                or any(s != "finished" for s in states)
            )
        ):
            _fail(11, 22)
        if failed and status["original_execution"] != "ineligible":
            _fail(11, 22)
    return StateValidation(tuple(states), required)


# Normative public protocol constants follow. They contain no runtime paths,
# agent metadata, example oracles, actual launch identities, or custody receipts.

_CAPS = (
    16384,
    16384,
    16384,
    2097152,
    2097152,
    2097152,
    262144,
    262144,
    262144,
    16384,
    16384,
    16384,
    2097152,
    2097152,
    65536,
    65536,
    262144,
    65536,
    65536,
    65536,
    65536,
    65536,
    65536,
)

_IDENTITIES = {
    ("dev-compat-r1", 1): (1, "r1-world-ssh-create"),
    ("dev-compat-r1", 2): (8, "r2-public-create"),
    ("dev-compat-r1", 3): (13, "r3-removes-encryption"),
    ("dev-compat-r1", 4): (18, "r4-delete"),
    ("dev-primary-r1", 1): (1, "r1-world-ssh-create"),
    ("dev-primary-r1", 2): (2, "r1-https-outside-policy"),
    ("dev-primary-r1", 3): (3, "r1-ipv6-rdp"),
    ("dev-primary-r1", 4): (4, "r1-cidr-reorder"),
    ("dev-primary-r1", 5): (5, "r1-add-rdp-to-ssh"),
    ("dev-primary-r1", 6): (6, "r1-unknown-prior"),
    ("dev-primary-r1", 7): (7, "r1-inline-unsupported"),
    ("dev-primary-r1", 8): (8, "r2-public-create"),
    ("dev-primary-r1", 9): (9, "r2-still-public"),
    ("dev-primary-r1", 10): (10, "r2-becomes-private"),
    ("dev-primary-r1", 11): (11, "r2-unknown-prior"),
    ("dev-primary-r1", 12): (12, "r2-sensitive-after"),
    ("dev-primary-r1", 13): (13, "r3-removes-encryption"),
    ("dev-primary-r1", 14): (14, "r3-create-unencrypted"),
    ("dev-primary-r1", 15): (15, "r3-unknown-prior"),
    ("dev-primary-r1", 16): (16, "r3-still-encrypted"),
    ("dev-primary-r1", 17): (17, "r3-missing-after"),
    ("dev-primary-r1", 18): (18, "r4-delete"),
    ("dev-primary-r1", 19): (19, "r4-destroy-create"),
    ("dev-primary-r1", 20): (20, "r4-create-destroy"),
    ("dev-primary-r1", 21): (21, "r4-create"),
    ("dev-primary-r1", 22): (22, "r4-update"),
    ("dev-primary-r1", 23): (23, "r4-contradictory-prior"),
    ("dev-primary-r1", 24): (24, "r4-other-stateful"),
}

_IDENTITY_SCHEMA = {
    "version": {"const": 3},
    "E_sha256": {"type": "string", "minLength": 1, "maxLength": 64, "pattern": "^[0-9a-f]{64}$"},
    "phase": {"enum": ["dev-compat-r1", "dev-primary-r1"]},
    "wire_ordinal": {"type": "integer", "minimum": 1, "maximum": 24},
    "slot_manifest_sha256": {
        "type": "string",
        "minLength": 1,
        "maxLength": 64,
        "pattern": "^[0-9a-f]{64}$",
    },
    "case_ordinal": {"type": "integer", "minimum": 1, "maximum": 24},
    "case_id": {
        "enum": [
            "r1-world-ssh-create",
            "r2-public-create",
            "r3-removes-encryption",
            "r4-delete",
            "r1-https-outside-policy",
            "r1-ipv6-rdp",
            "r1-cidr-reorder",
            "r1-add-rdp-to-ssh",
            "r1-unknown-prior",
            "r1-inline-unsupported",
            "r2-still-public",
            "r2-becomes-private",
            "r2-unknown-prior",
            "r2-sensitive-after",
            "r3-create-unencrypted",
            "r3-unknown-prior",
            "r3-still-encrypted",
            "r3-missing-after",
            "r4-destroy-create",
            "r4-create-destroy",
            "r4-create",
            "r4-update",
            "r4-contradictory-prior",
            "r4-other-stateful",
        ]
    },
    "slot": {
        "enum": [
            "c01",
            "c08",
            "c13",
            "c18",
            "c02",
            "c03",
            "c04",
            "c05",
            "c06",
            "c07",
            "c09",
            "c10",
            "c11",
            "c12",
            "c14",
            "c15",
            "c16",
            "c17",
            "c19",
            "c20",
            "c21",
            "c22",
            "c23",
            "c24",
        ]
    },
    "host_capture_name": {
        "enum": [
            "dev-compat-r1-c01.capture",
            "dev-compat-r1-c08.capture",
            "dev-compat-r1-c13.capture",
            "dev-compat-r1-c18.capture",
            "dev-primary-r1-c01.capture",
            "dev-primary-r1-c02.capture",
            "dev-primary-r1-c03.capture",
            "dev-primary-r1-c04.capture",
            "dev-primary-r1-c05.capture",
            "dev-primary-r1-c06.capture",
            "dev-primary-r1-c07.capture",
            "dev-primary-r1-c08.capture",
            "dev-primary-r1-c09.capture",
            "dev-primary-r1-c10.capture",
            "dev-primary-r1-c11.capture",
            "dev-primary-r1-c12.capture",
            "dev-primary-r1-c13.capture",
            "dev-primary-r1-c14.capture",
            "dev-primary-r1-c15.capture",
            "dev-primary-r1-c16.capture",
            "dev-primary-r1-c17.capture",
            "dev-primary-r1-c18.capture",
            "dev-primary-r1-c19.capture",
            "dev-primary-r1-c20.capture",
            "dev-primary-r1-c21.capture",
            "dev-primary-r1-c22.capture",
            "dev-primary-r1-c23.capture",
            "dev-primary-r1-c24.capture",
        ]
    },
    "host_status_name": {
        "enum": [
            "dev-compat-r1-c01.status.json",
            "dev-compat-r1-c08.status.json",
            "dev-compat-r1-c13.status.json",
            "dev-compat-r1-c18.status.json",
            "dev-primary-r1-c01.status.json",
            "dev-primary-r1-c02.status.json",
            "dev-primary-r1-c03.status.json",
            "dev-primary-r1-c04.status.json",
            "dev-primary-r1-c05.status.json",
            "dev-primary-r1-c06.status.json",
            "dev-primary-r1-c07.status.json",
            "dev-primary-r1-c08.status.json",
            "dev-primary-r1-c09.status.json",
            "dev-primary-r1-c10.status.json",
            "dev-primary-r1-c11.status.json",
            "dev-primary-r1-c12.status.json",
            "dev-primary-r1-c13.status.json",
            "dev-primary-r1-c14.status.json",
            "dev-primary-r1-c15.status.json",
            "dev-primary-r1-c16.status.json",
            "dev-primary-r1-c17.status.json",
            "dev-primary-r1-c18.status.json",
            "dev-primary-r1-c19.status.json",
            "dev-primary-r1-c20.status.json",
            "dev-primary-r1-c21.status.json",
            "dev-primary-r1-c22.status.json",
            "dev-primary-r1-c23.status.json",
            "dev-primary-r1-c24.status.json",
        ]
    },
}

_SCHEMAS = {
    17: {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "arm_states": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "arm": {"enum": ["C", "C-custom", "T"]},
                        "state": {"enum": ["unstarted", "started", "finished", "aborted"]},
                    },
                    "required": ["arm", "state"],
                },
                "minItems": 3,
                "maxItems": 3,
            },
            "originals": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "id": {"type": "integer", "minimum": 1, "maximum": 16},
                        "state": {"enum": ["missing", "complete", "partial", "rejected"]},
                        "logical_bytes": {
                            "anyOf": [
                                {"type": "integer", "minimum": 0, "maximum": 18446744073709551615},
                                {"type": "null"},
                            ]
                        },
                        "retained_bytes": {"type": "integer", "minimum": 0, "maximum": 2097152},
                        "retained_sha256": {
                            "anyOf": [
                                {
                                    "type": "string",
                                    "minLength": 1,
                                    "maxLength": 64,
                                    "pattern": "^[0-9a-f]{64}$",
                                },
                                {"type": "null"},
                            ]
                        },
                        "regular_nlink1_verified": {"type": "boolean"},
                        "source_stable_verified": {"type": "boolean"},
                    },
                    "required": [
                        "id",
                        "state",
                        "logical_bytes",
                        "retained_bytes",
                        "retained_sha256",
                        "regular_nlink1_verified",
                        "source_stable_verified",
                    ],
                },
                "minItems": 16,
                "maxItems": 16,
            },
            "generated_presence": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "id": {"type": "integer", "minimum": 17, "maximum": 23},
                        "state": {"enum": ["missing", "complete", "partial", "rejected"]},
                    },
                    "required": ["id", "state"],
                },
                "minItems": 7,
                "maxItems": 7,
            },
        },
        "required": [
            "version",
            "E_sha256",
            "phase",
            "wire_ordinal",
            "slot_manifest_sha256",
            "arm_states",
            "originals",
            "generated_presence",
            "case_ordinal",
            "case_id",
            "slot",
            "host_capture_name",
            "host_status_name",
        ],
    },
    18: {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "first_fault": {
                "enum": [
                    "NONE",
                    "NOT_STARTED",
                    "EXPECTED_MISSING",
                    "READ_FAILURE",
                    "LOGICAL_OVERCAP",
                    "UNSAFE_SOURCE",
                    "UNSTABLE_SOURCE",
                    "SOURCE_HASH_FAILURE",
                    "GENERATION_FAILED",
                    "IDENTITY_UNKNOWN",
                    "WIRE_SYNTAX",
                    "FRAME_HASH",
                    "TRAILING",
                    "HOST_IO",
                    "HOST_WRITE_UNKNOWN",
                    "FLUSH_FAILED",
                    "READBACK_FAILED",
                    "CUSTODY_UNKNOWN",
                    "NATIVE_FAILURE",
                    "ATTACH_DISCONNECT",
                    "ATTACH_OVERCAP",
                    "STATUS_IO",
                    "JOURNAL_IO",
                    "CLOSURE_UNPROVEN",
                ]
            },
            "errors": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "record_id": {"type": "integer", "minimum": 0, "maximum": 23},
                        "code": {
                            "enum": [
                                "NONE",
                                "NOT_STARTED",
                                "EXPECTED_MISSING",
                                "READ_FAILURE",
                                "LOGICAL_OVERCAP",
                                "UNSAFE_SOURCE",
                                "UNSTABLE_SOURCE",
                                "SOURCE_HASH_FAILURE",
                                "GENERATION_FAILED",
                                "IDENTITY_UNKNOWN",
                                "WIRE_SYNTAX",
                                "FRAME_HASH",
                                "TRAILING",
                                "HOST_IO",
                                "HOST_WRITE_UNKNOWN",
                                "FLUSH_FAILED",
                                "READBACK_FAILED",
                                "CUSTODY_UNKNOWN",
                                "NATIVE_FAILURE",
                                "ATTACH_DISCONNECT",
                                "ATTACH_OVERCAP",
                                "STATUS_IO",
                                "JOURNAL_IO",
                                "CLOSURE_UNPROVEN",
                            ]
                        },
                    },
                    "required": ["record_id", "code"],
                },
                "minItems": 0,
                "maxItems": 32,
            },
        },
        "required": [
            "version",
            "E_sha256",
            "phase",
            "wire_ordinal",
            "slot_manifest_sha256",
            "first_fault",
            "errors",
            "case_ordinal",
            "case_id",
            "slot",
            "host_capture_name",
            "host_status_name",
        ],
    },
    19: {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "I_sha256": {
                "type": "string",
                "minLength": 1,
                "maxLength": 64,
                "pattern": "^[0-9a-f]{64}$",
            },
            "B_sha256": {
                "type": "string",
                "minLength": 1,
                "maxLength": 64,
                "pattern": "^[0-9a-f]{64}$",
            },
            "P_index_sha256": {
                "type": "string",
                "minLength": 1,
                "maxLength": 64,
                "pattern": "^[0-9a-f]{64}$",
            },
            "Gsha": {
                "type": "string",
                "minLength": 1,
                "maxLength": 64,
                "pattern": "^[0-9a-f]{64}$",
            },
            "H_sha256": {
                "type": "string",
                "minLength": 1,
                "maxLength": 64,
                "pattern": "^[0-9a-f]{64}$",
            },
            "invocations": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "arm": {"enum": ["C", "C-custom", "T"]},
                        "invocation_sha256": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 64,
                            "pattern": "^[0-9a-f]{64}$",
                        },
                    },
                    "required": ["arm", "invocation_sha256"],
                },
                "minItems": 3,
                "maxItems": 3,
            },
        },
        "required": [
            "version",
            "E_sha256",
            "phase",
            "wire_ordinal",
            "slot_manifest_sha256",
            "I_sha256",
            "B_sha256",
            "P_index_sha256",
            "Gsha",
            "H_sha256",
            "invocations",
            "case_ordinal",
            "case_id",
            "slot",
            "host_capture_name",
            "host_status_name",
        ],
    },
    20: {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "writer_id": {
                "type": "string",
                "minLength": 1,
                "maxLength": 64,
                "pattern": "^[0-9a-f]{64}$",
            },
            "holder_id": {
                "type": "string",
                "minLength": 1,
                "maxLength": 64,
                "pattern": "^[0-9a-f]{64}$",
            },
            "exporter_id": {
                "type": "string",
                "minLength": 1,
                "maxLength": 64,
                "pattern": "^[0-9a-f]{64}$",
            },
            "results_mount_token": {
                "type": "string",
                "minLength": 1,
                "maxLength": 64,
                "pattern": "^[0-9a-f]{64}$",
            },
            "helper_uid": {"const": 65532},
            "helper_gid": {"const": 65532},
            "results_consumer_read_only": {"type": "boolean"},
            "continuous_same_mount_verified": {"type": "boolean"},
            "all_writers_quiescent_verified": {"type": "boolean"},
            "no_rw_attachment_verified": {"type": "boolean"},
        },
        "required": [
            "version",
            "E_sha256",
            "phase",
            "wire_ordinal",
            "slot_manifest_sha256",
            "writer_id",
            "holder_id",
            "exporter_id",
            "results_mount_token",
            "helper_uid",
            "helper_gid",
            "results_consumer_read_only",
            "continuous_same_mount_verified",
            "all_writers_quiescent_verified",
            "no_rw_attachment_verified",
            "case_ordinal",
            "case_id",
            "slot",
            "host_capture_name",
            "host_status_name",
        ],
    },
    21: {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "capture_reserved_bytes": {"const": 16777216},
            "external_status_reserved_bytes": {"const": 65536},
            "phase_allocated_bytes": {"enum": [536870912, 201326592]},
            "global_allocated_bytes": {"const": 738197504},
            "observed_capture_bytes_before_record21": {
                "type": "integer",
                "minimum": 0,
                "maximum": 16777216,
            },
            "outer_elapsed_ns": {
                "anyOf": [
                    {"type": "integer", "minimum": 0, "maximum": 18446744073709551615},
                    {"type": "null"},
                ]
            },
            "native_elapsed_ns": {
                "type": "array",
                "items": {
                    "anyOf": [
                        {"type": "integer", "minimum": 0, "maximum": 18446744073709551615},
                        {"type": "null"},
                    ]
                },
                "minItems": 3,
                "maxItems": 3,
            },
            "native_cpu_metric": {"type": "null"},
            "native_memory_metric": {"type": "null"},
        },
        "required": [
            "version",
            "E_sha256",
            "phase",
            "wire_ordinal",
            "slot_manifest_sha256",
            "capture_reserved_bytes",
            "external_status_reserved_bytes",
            "phase_allocated_bytes",
            "global_allocated_bytes",
            "observed_capture_bytes_before_record21",
            "outer_elapsed_ns",
            "native_elapsed_ns",
            "native_cpu_metric",
            "native_memory_metric",
            "case_ordinal",
            "case_id",
            "slot",
            "host_capture_name",
            "host_status_name",
        ],
    },
    22: {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "snapshot_kind": {"const": "PRECOMMIT_OBSERVATION"},
            "available_preservation": {"enum": ["complete-candidate", "incomplete", "unknown"]},
            "required_capture": {"enum": ["complete-candidate", "incomplete", "unknown"]},
            "original_execution": {"enum": ["candidate", "ineligible", "unknown"]},
            "original_failure_observed": {"type": "boolean"},
        },
        "required": [
            "version",
            "E_sha256",
            "phase",
            "wire_ordinal",
            "slot_manifest_sha256",
            "snapshot_kind",
            "available_preservation",
            "required_capture",
            "original_execution",
            "original_failure_observed",
            "case_ordinal",
            "case_id",
            "slot",
            "host_capture_name",
            "host_status_name",
        ],
    },
    23: {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "driver_terminal": {"enum": ["normal", "error", "not-started", "unknown"]},
            "attach_stdout_complete": {"type": "boolean"},
            "attach_stderr_complete": {"type": "boolean"},
            "source_read_complete": {"type": "boolean"},
            "continuous_same_mount_verified": {"type": "boolean"},
            "all_writers_quiescent_verified": {"type": "boolean"},
            "no_rw_attachment_verified": {"type": "boolean"},
        },
        "required": [
            "version",
            "E_sha256",
            "phase",
            "wire_ordinal",
            "slot_manifest_sha256",
            "driver_terminal",
            "attach_stdout_complete",
            "attach_stderr_complete",
            "source_read_complete",
            "continuous_same_mount_verified",
            "all_writers_quiescent_verified",
            "no_rw_attachment_verified",
            "case_ordinal",
            "case_id",
            "slot",
            "host_capture_name",
            "host_status_name",
        ],
    },
}

for _rule in _SCHEMAS.values():
    _rule["properties"].update(_IDENTITY_SCHEMA)
del _rule
