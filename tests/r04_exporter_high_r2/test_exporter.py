"""API-informed tests; normative controls were frozen before new source reads.

Standalone explicit test functions, no pytest/plugin/cache/cleanup machinery.
Candidate modules supplied by the reviewed source-only loader in run.py.
"""
import dataclasses
import hashlib
import json
import stat


def require(value, detail="control failed"):
    if not value:
        raise AssertionError(detail)


def setup(exporter, wire, receiver, oracle, literals, output):
    global X, W, R, O, L, OUT
    X, W, R, O, L, OUT = exporter, wire, receiver, oracle, literals, output


def identity(header):
    return W.Identity("dev-primary-r1" if header[2] else "dev-compat-r1",
                      header[3], header[6].hex(), header[7].hex())


def records(rows, reader=None):
    return tuple(X.ExportRecord(rid, state, reason, logical,
                 (reader(payload) if reader else X.BytesReader(payload)) if state in (1, 2) else None)
                 for rid, state, reason, logical, payload in rows)


def vector(name="V01_ALL_MISSING"):
    item = next(v for v in L if v["id"] == name)
    header, rows = O.split(bytes.fromhex(item["hex"]))
    return header, rows


def encode(rows, header=None, **kwargs):
    if header is None:
        header = vector()[0]
    return X.encode_capture(records(rows), expected=identity(header), deadline=100,
                            clock=lambda: 0, **kwargs)


def refuses(call, code=None, step=None):
    try:
        call()
    except X.ExportError as exc:
        require(code is None or exc.code == code, (code, exc.code))
        require(step is None or exc.wire_step == step, (step, exc.wire_step))
        require(str(exc) == exc.code)
        require("SECRET" not in str(exc) and "sensitive" not in str(exc))
        return exc
    raise AssertionError("refusal control returned output")


def test_six_literal_exact_bytes():
    for item in L:
        if not (item["framing_valid"] and item["state_valid"]):
            continue
        raw = bytes.fromhex(item["hex"])
        header, rows = O.split(raw)
        require(hashlib.sha256(raw).hexdigest() == item["sha256"])
        require(O.build(header, rows) == raw, item["id"])
        require(encode(rows, header) == raw, item["id"])
        require(len(raw) == 1326 + sum(len(r[4]) for r in rows))


def test_all_invalid_wire_literals_retain_stage():
    expected = identity(vector()[0])
    for item in L:
        if item["framing_valid"]:
            continue
        try:
            W.decode_framing(bytes.fromhex(item["hex"]), expected=expected)
        except W.WireError as exc:
            require((exc.code, exc.step) == (item["error"], item["step"]), item["id"])
        else:
            raise AssertionError(item["id"])


def test_transport_valid_semantics_invalid_is_not_output():
    h, rows = vector("S01_TRANSPORT_VALID_STATE_INVALID_LEGACY_V03")
    refuses(lambda: encode(rows, h), "STATE_OR_CLOSURE_INCOMPLETE", 11)


def test_roster_exact_tuple_ids_before_any_source_call():
    h, rows = vector("V02_ACTUAL_EMPTY_DISTINCT")
    class Forbidden:
        def snapshot(self):
            raise AssertionError("source called before roster rejected")
        def read(self, maximum):
            raise AssertionError("source called before roster rejected")
    good = records(rows, lambda _: Forbidden())
    for bad in (good[:-1], good + good[:1], list(good), iter(good)):
        refuses(lambda bad=bad: X.encode_capture(bad, expected=identity(h), deadline=10,
                                                clock=lambda: 0), "RECORD_COUNT", 3)
    for rid in (0, 2, 24, True):
        bad = (dataclasses.replace(good[0], record_id=rid),) + good[1:]
        refuses(lambda: X.encode_capture(bad, expected=identity(h), deadline=10,
                                         clock=lambda: 0), "RECORD_ORDINAL", 3)
    bad = (good[1], good[0]) + good[2:]
    refuses(lambda: X.encode_capture(bad, expected=identity(h), deadline=10,
                                     clock=lambda: 0), "RECORD_ORDINAL", 3)


def test_raw_octets_empty_and_partial_are_exact():
    h, rows = vector("V03_EXACT_READ_FAILURE_PREFIX")
    payload = b"\x00\xff\r\n  \t\n"
    rows[3] = (4, 2, 3, len(payload) + 1, payload)
    raw = encode(rows, h)
    require(raw == O.build(h, rows))
    parsed = W.decode_framing(raw, expected=identity(h))
    require(parsed.records[3].payload == payload)
    require(parsed.records[6].retained_sha256 == "00" * 32)
    h, rows = vector("V02_ACTUAL_EMPTY_DISTINCT")
    raw = encode(rows, h)
    parsed = W.decode_framing(raw, expected=identity(h))
    # V02 fixed literal ordinals: C streams4/7 are present empty, terminal10 is x.
    # Record2 is genuinely missing; zero-based index9 is complete record10.
    # Expectations come from frozen literal bytes + v3 state table, never output.
    require(rows[1] == (2, 0, 1, None, b""))
    require(rows[3] == (4, 1, 0, 0, b""))
    require(rows[6] == (7, 1, 0, 0, b""))
    require(rows[9] == (10, 1, 0, 1, b"x"))
    require(raw == O.build(h, rows))
    for index in (3, 6):
        require(parsed.records[index].state == 1)
        require(parsed.records[index].payload == b"")
        require(parsed.records[index].retained_sha256 == hashlib.sha256(b"").hexdigest())
    require(parsed.records[9].state == 1 and parsed.records[9].payload == b"x")
    require(parsed.records[9].retained_sha256 == hashlib.sha256(b"x").hexdigest())
    require(parsed.records[1].state == 0 and parsed.records[1].payload == b"")
    require(parsed.records[1].retained_sha256 == "00" * 32)


def test_state_length_and_source_matrix():
    h, rows = vector()
    base = records(rows)
    mutations = [dict(state=True), dict(reason=True), dict(logical_bytes=True),
                 dict(state=4), dict(logical_bytes=-1), dict(logical_bytes=1 << 64),
                 dict(source=X.BytesReader(b"")), dict(state=1, reason=0, logical_bytes=0),
                 dict(state=3, reason=4, logical_bytes=None),
                 dict(state=3, reason=4, logical_bytes=16384),
                 dict(state=3, reason=4, logical_bytes=16383)]
    for change in mutations:
        bad = (dataclasses.replace(base[0], **change),) + base[1:]
        refuses(lambda: X.encode_capture(bad, expected=identity(h), deadline=10, clock=lambda: 0))
    for length in (0, 7, (1 << 64) - 1):
        # Unknown rejected start means remaining same-arm missing use reason2.
        current = list(rows)
        current[0] = (1, 3, 5, length, b"")
        for n in (3, 6, 9):
            r = current[n]
            current[n] = (r[0], 0, 2, None, b"")
        require(encode(current, h) == O.build(h, current))


def test_caps_before_payload_and_all_in_arithmetic():
    h, rows = vector("V02_ACTUAL_EMPTY_DISTINCT")
    class Oversize:
        def snapshot(self):
            return X.InputSnapshot("immutable-bytes", (1,), 2097153)
        def read(self, maximum):
            raise AssertionError("overcap source read")
    bad = list(records(rows))
    bad[3] = X.ExportRecord(4, 1, 0, 2097153, Oversize())
    refuses(lambda: X.encode_capture(tuple(bad), expected=identity(h), deadline=10,
                                     clock=lambda: 0), "LENGTH_CAP", 5)
    require(80 + 23 * 52 + 50 == 1326)
    require(12156928 + 1326 == 12158254 < 16777216)
    # Maximum regular source4 (2MiB) preserved exactly; original missing terminal remains missing.
    rows[3] = (4, 1, 0, 2097152, b"\x00" * 2097152)
    require(encode(rows, h) == O.build(h, rows))


class Reader:
    def __init__(self, payload, snapshot=None, read_fault=None, mutate=None, clock=None):
        self.data, self.position, self.observations = payload, 0, 0
        self.metadata, self.read_fault, self.mutate, self.clock = snapshot, read_fault, mutate, clock
        self.requests = []
    def snapshot(self):
        self.observations += 1
        value = self.metadata or X.InputSnapshot("immutable-bytes", (1,), len(self.data))
        if self.clock:
            self.clock[0] = 100
        return self.mutate(value, self.observations) if self.mutate else value
    def read(self, maximum):
        require(type(maximum) is int and 1 <= maximum <= 65536)
        self.requests.append(maximum)
        if self.read_fault:
            return self.read_fault(maximum)
        part = self.data[self.position:self.position + maximum]
        self.position += len(part)
        return part


def single_reader(reader, **kwargs):
    h, rows = vector("V02_ACTUAL_EMPTY_DISTINCT")
    current = list(records(rows))
    current[0] = dataclasses.replace(current[0], source=reader)
    return X.encode_capture(tuple(current), expected=identity(h), deadline=100,
                            clock=kwargs.pop("clock", lambda: 0), **kwargs)


def test_snapshot_kind_owner_nlink_reparse():
    original = X.InputSnapshot("ordinary-file", (5, 7), 1, stat.S_IFREG | 0o600, 1, 42, False)
    require(type(single_reader(Reader(b"x", original), owner_uid=42)) is bytes)
    for change in (dict(mode=stat.S_IFDIR), dict(nlink=2), dict(nlink=True),
                   dict(owner_uid=41), dict(owner_uid=None), dict(reparse=True),
                   dict(reparse=None), dict(kind="symlink"), dict(token=()),
                   dict(token=(float("nan"),)), dict(token=(True,)), dict(logical_bytes=True)):
        refuses(lambda: single_reader(Reader(b"x", dataclasses.replace(original, **change)),
                                      owner_uid=42))
    refuses(lambda: single_reader(Reader(b"x", original)))
    refuses(lambda: single_reader(Reader(b"x", X.InputSnapshot("immutable-bytes", (1,), 1,
                                                               nlink=1))))


def test_snapshot_changes_at_postread_and_final_observation():
    for after in (2, 3):
        for field, value in (("token", (2,)), ("logical_bytes", 2)):
            reader = Reader(b"x", mutate=lambda s, n: dataclasses.replace(s, **{field: value})
                            if n >= after else s)
            refuses(lambda: single_reader(reader), "INPUT_CHANGED")
    ordinary = X.InputSnapshot("ordinary-file", (1,), 1, stat.S_IFREG | 0o600, 1, 42, False)
    for field, value in (("owner_uid", 41), ("nlink", 2), ("reparse", True)):
        reader = Reader(b"x", ordinary,
                        mutate=lambda s, n: dataclasses.replace(s, **{field: value}) if n > 1 else s)
        refuses(lambda: single_reader(reader, owner_uid=42), "INPUT_METADATA")


def test_read_bound_short_overrun_type_and_sanitized_exception():
    def crash(_):
        raise OSError("SECRET sensitive/path payload")
    for fault in (lambda _: b"", lambda n: b"z" * (n + 1), lambda _: bytearray(b"x"), crash):
        refuses(lambda: single_reader(Reader(b"x", read_fault=fault)))
    reader = Reader(b"xx", snapshot=X.InputSnapshot("immutable-bytes", (1,), 1))
    refuses(lambda: single_reader(reader), "INPUT_LENGTH")
    class BadSnapshot(Reader):
        def snapshot(self):
            raise OSError("SECRET sensitive/path")
    refuses(lambda: single_reader(BadSnapshot(b"x")), "INPUT_IO")


def test_finite_deadline_and_clock_before_source():
    h, rows = vector()
    for value in (float("nan"), float("inf"), -float("inf"), True, None, 0):
        refuses(lambda: X.encode_capture(records(rows), expected=identity(h), deadline=value,
                                         clock=lambda: 0), "DEADLINE")
    for now in (float("nan"), float("inf"), True):
        refuses(lambda: X.encode_capture(records(rows), expected=identity(h), deadline=100,
                                         clock=lambda: now), "CLOCK")
    clock = [0]
    reader = Reader(b"x", clock=clock)
    refuses(lambda: single_reader(reader, clock=lambda: clock[0]), "DEADLINE")
    require(not reader.requests)


def test_expiry_after_read_hash_decode_and_state_validation():
    clock = [0]
    class Expiring(Reader):
        def read(self, maximum):
            part = super().read(maximum)
            clock[0] = 100
            return part
    refuses(lambda: single_reader(Expiring(b"x"), clock=lambda: clock[0]), "DEADLINE")
    # Transparent test-only wrappers preserve dependency behavior, expire only AFTER returning.
    # Originals always restored; no file mutation/private state edits/changed expected outcomes.
    for module, name in ((X, "sha256"), (W, "decode_framing"), (W, "validate_state")):
        original = getattr(module, name)
        clock[0] = 0
        def wrapper(*args, _original=original, **kwargs):
            result = _original(*args, **kwargs)
            clock[0] = 100
            return result
        setattr(module, name, wrapper)
        try:
            h, rows = vector()
            refuses(lambda: X.encode_capture(records(rows), expected=identity(h), deadline=100,
                                             clock=lambda: clock[0]), "DEADLINE")
        finally:
            setattr(module, name, original)
    for target in ("payload", "trailer"):
        original = X.sha256
        clock[0] = 0
        class Hash:
            def __init__(self, data):
                self.data, self.actual = data, original(data)
            def digest(self):
                result = self.actual.digest()
                if ((target == "payload" and len(self.data) == 1)
                        or (target == "trailer" and bytes(self.data).startswith(b"M4CAP02\n"))):
                    clock[0] = 100
                return result
        X.sha256 = Hash
        try:
            refuses(lambda: single_reader(Reader(b"x"), clock=lambda: clock[0]), "DEADLINE")
        finally:
            X.sha256 = original


def test_external_identity_header_fields_and_generated_partial():
    h, rows = vector()
    for phase, ordinal in ((0, 2), (0, 4), (1, 24)):
        current = list(h)
        current[2], current[3] = phase, ordinal
        current[6], current[7] = bytes.fromhex("ab" * 32), bytes.fromhex("cd" * 32)
        current = tuple(current)
        require(encode(rows, current) == O.build(current, rows))
    h, rows = vector("V06_CLOSED_METADATA_INCOMPLETE")
    changed = list(rows)
    row = changed[16]
    changed[16] = (17, 2, 3, len(row[4]) + 1, row[4])
    refuses(lambda: encode(changed, h), "STATE_ENCODING", 4)


def test_generated_identity_schema_and_failed_attempt_not_upgraded():
    h, rows = vector("V06_CLOSED_METADATA_INCOMPLETE")
    for payload in (b"{}\n", b"[]\n", rows[16][4] + b"\n"):
        changed = list(rows)
        changed[16] = (17, 1, 0, len(payload), payload)
        refuses(lambda: encode(changed, h), "GENERATED_SCHEMA_OR_CANONICAL", 8)
    for index in range(16, 23):
        original = rows[index]
        metadata = json.loads(original[4])
        metadata["case_ordinal"] = 8
        changed = list(rows)
        payload = (json.dumps(metadata, sort_keys=True, separators=(",", ":")) + "\n").encode()
        changed[index] = (original[0], 1, 0, len(payload), payload)
        refuses(lambda: encode(changed, h), "GENERATED_SCHEMA_OR_CANONICAL", 8)
    decoded = W.decode_framing(encode(rows, h), expected=identity(h))
    result = W.validate_state(decoded)
    require(result.native_eligible is False and result.durable_verified is False)
    status = json.loads(rows[21][4])
    require(status["original_execution"] == "ineligible")
    status["original_execution"] = "candidate"
    payload = (json.dumps(status, sort_keys=True, separators=(",", ":")) + "\n").encode()
    rows[21] = (22, 1, 0, len(payload), payload)
    refuses(lambda: encode(rows, h), "STATE_OR_CLOSURE_INCOMPLETE", 11)


def test_separate_receiver_copy_flags_always_false():
    h, rows = vector("V03_EXACT_READ_FAILURE_PREFIX")
    raw = encode(rows, h)
    root = OUT / "receiver-copy"
    root.mkdir()
    expected = identity(h)
    destination = R.bind_destination(root, expected=expected)
    result = R.receive_capture(R.BytesReader(raw), expected=expected, destination=destination,
                               reservation=R.CaseReservation(), deadline=100, clock=lambda: 0)
    require(result.outcome == "COMPLETE", result)
    require(result.native_eligible is False and result.durable_verified is False)
    require(result.capture_path.read_bytes() == O.build(h, rows))
