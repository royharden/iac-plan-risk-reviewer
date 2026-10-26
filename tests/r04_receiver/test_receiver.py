"""Contract-derived public receiver controls; all outputs retained by our runner."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import types
import uuid

import pytest

HERE = Path(__file__).resolve().parent
LITERAL_SHA = "be38f3976be3d0d93f60f6db763f9ea1733b11bd017cfe8a8bf1c6aab01cc13a"
raw = (HERE / "literal_examples.json").read_bytes()
assert hashlib.sha256(raw).hexdigest() == LITERAL_SHA
EXAMPLES = json.loads(raw)
VALID = bytes.fromhex(EXAMPLES[0]["hex"])


@pytest.fixture
def tmp_path():
    """Retained ordinary path: no pytest cleanup, symlink or shared temp state."""
    root = Path(os.environ["RV4_OUTPUT_ROOT"]) / ("case-" + uuid.uuid4().hex)
    root.mkdir()
    return root


@pytest.fixture(scope="session")
def module():
    """Require exact immutable source closure; never import mutable branch HEAD."""
    root = Path(os.environ["RV4_SOURCE_ROOT"])
    pins = json.loads(os.environ["RV4_SOURCE_PINS"])
    package = types.ModuleType("_rv4_receiver_candidate")
    package.__path__ = []
    sys.modules[package.__name__] = package
    modules = {}
    for leaf in ("storage_wire", "storage_receiver"):
        path = root / (leaf + ".py")
        data = path.read_bytes()
        assert hashlib.sha256(data).hexdigest() == pins[leaf]
        name = package.__name__ + "." + leaf
        value = types.ModuleType(name)
        value.__file__ = str(path)
        value.__package__ = package.__name__
        sys.modules[name] = value
        exec(compile(data, str(path), "exec"), value.__dict__)
        setattr(package, leaf, value)
        modules[leaf] = value
    yield modules["storage_receiver"]
    for leaf, expected in pins.items():
        assert hashlib.sha256((root / (leaf + ".py")).read_bytes()).hexdigest() == expected


class Clock:
    def __init__(self):
        self.now = 1.0

    def __call__(self):
        return self.now


class FS:
    """Trusted ordinary-file adapter with explicit single-fault injection."""
    def __init__(self, module, clock, fault=None):
        self.real = module.OrdinaryFS()
        self.clock = clock
        self.fault = fault
        self.events = []
        self.fired = False

    def invoke(self, method, *args):
        handle = args[0] if args else None
        path = Path(handle.name) if hasattr(handle, "name") and isinstance(handle.name, str) else handle
        self.events.append((method, str(path), self.clock.now))
        if method == self.fault and not self.fired:
            self.fired = True
            raise OSError("synthetic secret MUST_NOT_ECHO")
        result = getattr(self.real, method)(*args)
        if self.fault == "expire-" + method and not self.fired:
            self.fired = True
            self.clock.now = 10.0
        return result

    def lstat(self, path): return self.invoke("lstat", path)
    def fstat(self, handle): return self.invoke("fstat", handle)
    def open_exclusive(self, path): return self.invoke("open_exclusive", path)
    def open_read(self, path): return self.invoke("open_read", path)
    def read(self, handle, count):
        if self.fault == "readback-mismatch" and not self.fired:
            self.fired = True
            return b"X" * count
        if self.fault == "readback-short" and not self.fired:
            self.fired = True
            return b""
        return self.invoke("read", handle, count)
    def write(self, handle, data):
        self.events.append(("write", str(handle.name), self.clock.now))
        if not self.fired:
            if self.fault == "short":
                self.fired = True
                return self.real.write(handle, data[:7])
            if self.fault in ("unknown", "negative", "boolean", "overcount", "none"):
                self.fired = True
                self.real.write(handle, data[:3])
                if self.fault == "unknown": raise OSError("MUST_NOT_ECHO")
                return {"negative": -1, "boolean": True, "overcount": len(data) + 1,
                        "none": None}[self.fault]
        result = self.real.write(handle, data)
        if self.fault == "expire-write" and not self.fired:
            self.fired = True
            self.clock.now = 10.0
        return result
    def flush(self, handle): return self.invoke("flush", handle)
    def fsync(self, handle): return self.invoke("fsync", handle)
    def close(self, handle):
        # Close real handles even when injecting a close error; no leaked resource.
        if self.fault == "close" and not self.fired:
            self.fired = True
            self.real.close(handle)
            raise OSError("MUST_NOT_ECHO")
        return self.invoke("close", handle)


def setup(module, tmp_path, fault=None):
    clock = Clock()
    fs = FS(module, clock, fault)
    identity = module.storage_wire.Identity("dev-compat-r1", 1, "00" * 32, "11" * 32)
    destination = module.bind_destination(tmp_path, expected=identity, filesystem=fs)
    fs.events.clear()
    return clock, fs, identity, destination


def receive(module, tmp_path, *, data=VALID, fault=None, reader=None, reservation=None):
    clock, fs, identity, destination = setup(module, tmp_path, fault)
    result = module.receive_capture(
        reader or module.BytesReader(data), expected=identity, destination=destination,
        reservation=reservation or module.CaseReservation(), deadline=10.0, clock=clock,
    )
    assert result.native_eligible is False and result.durable_verified is False
    assert "MUST_NOT_ECHO" not in repr(result)
    return result, fs, identity


@pytest.mark.parametrize("example", EXAMPLES, ids=lambda x: x["id"])
def test_frozen_32_wire_specimens(module, tmp_path, example):
    """Catch malformed wire being retained before validation, or valid wire lost."""
    data = bytes.fromhex(example["hex"])
    assert hashlib.sha256(data).hexdigest() == example["sha256"]
    result, fs, identity = receive(module, tmp_path, data=data)
    if example["framing_valid"] and example["state_valid"]:
        assert result.outcome == "COMPLETE"
        assert result.complete_sha256 == hashlib.sha256(data).hexdigest()
        assert result.capture_path.read_bytes() == data
        assert result.capture_bytes == result.capture_charged_bytes == len(data)
    else:
        assert result.outcome != "COMPLETE" and result.complete_sha256 is None
        assert (result.code, result.wire_step) == (example["error"], example["step"])
        assert not (tmp_path / identity.host_capture_name).exists()
        assert not any(event[0] == "open_exclusive" and event[1].endswith(identity.host_capture_name)
                       for event in fs.events)


@pytest.mark.parametrize("cut", [0, 1, 7, 79, 80, 81, 100, 131, 132, -51, -1])
def test_truncation_never_creates_capture(module, tmp_path, cut):
    result, fs, identity = receive(module, tmp_path, data=VALID[:cut])
    assert result.outcome != "COMPLETE" and result.complete_sha256 is None
    assert result.capture_charged_bytes == 0
    assert not (tmp_path / identity.host_capture_name).exists()


@pytest.mark.parametrize("limit", [True, False, 0, -1, 16777217, 1.0, None, "1"])
def test_capture_budget_exact_bounds(module, limit):
    with pytest.raises(module.ReceiverError): module.CaseReservation(capture_limit=limit)


@pytest.mark.parametrize("limit", [True, False, 0, -1, 65537, 1.0, None, "1"])
def test_status_budget_exact_bounds(module, limit):
    with pytest.raises(module.ReceiverError): module.CaseReservation(status_limit=limit)


def test_short_write_is_counted_without_retry(module, tmp_path):
    result, fs, _ = receive(module, tmp_path, fault="short")
    assert result.code == "SHORT_WRITE" and result.complete_sha256 is None
    assert result.capture_charged_bytes == result.capture_bytes == 7
    assert result.capture_path.read_bytes() == VALID[:7]
    assert result.prefix_sha256 in (None, hashlib.sha256(VALID[:7]).hexdigest())


@pytest.mark.parametrize("fault", ["unknown", "negative", "boolean", "overcount", "none"])
def test_unknown_count_stops_all_host_writes(module, tmp_path, fault):
    result, fs, _ = receive(module, tmp_path, fault=fault)
    assert result.outcome == "UNKNOWN" and result.complete_sha256 is None
    assert result.capture_bytes is None and result.capture_charged_bytes == len(VALID)
    assert result.status_path is None and not result.status_committed
    assert sum(e[0] == "write" for e in fs.events) == 1
    assert result.capture_path.read_bytes() == VALID[:3]


@pytest.mark.parametrize("fault", ["open_exclusive", "flush", "fsync", "open_read", "read",
                                    "readback-mismatch", "readback-short", "close"])
def test_local_io_fault_never_completes(module, tmp_path, fault):
    result, _, _ = receive(module, tmp_path, fault=fault)
    assert result.outcome != "COMPLETE" and result.complete_sha256 is None


@pytest.mark.parametrize("operation", ["open_exclusive", "write", "flush", "fsync", "open_read", "read"])
def test_deadline_after_operation_stops_subsequent_writes(module, tmp_path, operation):
    result, fs, _ = receive(module, tmp_path, fault="expire-" + operation)
    assert result.code == "DEADLINE" and result.complete_sha256 is None
    assert not any(method in ("write", "open_exclusive") and when >= 10
                   for method, _, when in fs.events)
    assert not result.status_committed


def test_one_use_reservation_on_refusal(module, tmp_path):
    clock, fs, identity, destination = setup(module, tmp_path)
    budget = module.CaseReservation()
    module.receive_capture(module.BytesReader(b""), expected=identity, destination=destination,
                           reservation=budget, deadline=10, clock=clock)
    before = list(fs.events)
    with pytest.raises(module.ReceiverError):
        module.receive_capture(module.BytesReader(VALID), expected=identity, destination=destination,
                               reservation=budget, deadline=10, clock=clock)
    assert fs.events == before and budget.used


@pytest.mark.parametrize("name", ["capture", "status"])
def test_existing_output_refuses_without_overwrite(module, tmp_path, name):
    identity = module.storage_wire.Identity("dev-compat-r1", 1, "00" * 32, "11" * 32)
    filename = identity.host_capture_name if name == "capture" else identity.host_status_name
    path = tmp_path / filename
    path.write_bytes(b"retain-me")
    with pytest.raises(module.ReceiverError): module.bind_destination(tmp_path, expected=identity)
    assert path.read_bytes() == b"retain-me"


@pytest.mark.parametrize("deadline", [True, None, float("nan"), float("inf"), "10"])
def test_deadline_type_refuses_before_host_io(module, tmp_path, deadline):
    clock, fs, identity, destination = setup(module, tmp_path)
    with pytest.raises(module.ReceiverError):
        module.receive_capture(module.BytesReader(VALID), expected=identity, destination=destination,
                               reservation=module.CaseReservation(), deadline=deadline, clock=clock)
    assert not any(e[0] in ("write", "open_exclusive") for e in fs.events)


def test_status_is_distinct_local_diagnostic(module, tmp_path):
    result, _, _ = receive(module, tmp_path)
    assert result.status_committed and result.status_path
    raw = result.status_path.read_bytes()
    status = json.loads(raw)
    assert len(raw) == result.status_bytes == result.status_charged_bytes <= 65536
    assert status["kind"] == "local-receiver-v1-diagnostic"
    assert status["native_eligible"] is False and status["durable_verified"] is False
    assert not ({"reservation_index_sha256", "capture_verification_event_sha256"} & status.keys())
    assert "FINAL_COMPLETE" not in raw.decode() and "ExternalStatus" not in raw.decode()


def test_small_status_budget_never_borrows_capture_budget(module, tmp_path):
    result, _, _ = receive(module, tmp_path, reservation=module.CaseReservation(status_limit=1))
    assert result.outcome != "COMPLETE" and result.code == "STATUS_CAP"
    assert result.status_charged_bytes == 0 and result.status_path is None
    assert result.capture_charged_bytes == len(VALID)
    assert result.complete_sha256 is None


@pytest.mark.parametrize("mode", ["overreturn", "nonbytes", "exception", "changed", "length", "overcap"])
def test_reader_fault_prevents_capture_creation(module, tmp_path, mode):
    class Reader:
        calls = 0
        snapshots = 0
        def snapshot(self):
            self.snapshots += 1
            length = len(VALID) + (1 if mode == "length" else 0)
            token = (self.snapshots,) if mode == "changed" else (length,)
            return module.InputSnapshot("immutable-bytes", token, length)
        def read(self, maximum):
            assert type(maximum) is int and 1 <= maximum <= 16777217
            self.calls += 1
            if mode == "overreturn": return b"x" * (maximum + 1)
            if mode == "nonbytes": return "x"
            if mode == "exception": raise OSError("MUST_NOT_ECHO")
            if mode == "overcap": return b"x" * maximum
            return VALID if self.calls == 1 else b""
    result, _, identity = receive(module, tmp_path, reader=Reader())
    assert result.outcome != "COMPLETE" and result.complete_sha256 is None
    assert not (tmp_path / identity.host_capture_name).exists()


def test_expired_at_entry_never_creates_any_host_file(module, tmp_path):
    clock, fs, identity, destination = setup(module, tmp_path)
    clock.now = 10
    result = module.receive_capture(module.BytesReader(VALID), expected=identity,
        destination=destination, reservation=module.CaseReservation(), deadline=10, clock=clock)
    assert result.code == "DEADLINE" and result.complete_sha256 is None
    assert not any(e[0] in ("open_exclusive", "write") for e in fs.events)
    assert list(tmp_path.iterdir()) == []


def test_capture_budget_overflow_never_creates_capture(module, tmp_path):
    result, _, identity = receive(module, tmp_path,
                                  reservation=module.CaseReservation(capture_limit=1))
    assert result.code == "INPUT_CAP" and result.complete_sha256 is None
    assert result.capture_charged_bytes == 0
    assert not (tmp_path / identity.host_capture_name).exists()


def test_changed_anchor_after_binding_refuses(module, tmp_path):
    clock, fs, identity, destination = setup(module, tmp_path)
    original = fs.lstat
    def changed(path):
        info = original(path)
        if path == tmp_path:
            fields = list(info)
            fields[1] += 1
            return os.stat_result(fields)
        return info
    fs.lstat = changed
    result = module.receive_capture(module.BytesReader(VALID), expected=identity,
        destination=destination, reservation=module.CaseReservation(), deadline=10, clock=clock)
    assert result.outcome != "COMPLETE" and result.complete_sha256 is None
    assert not any(e[0] in ("open_exclusive", "write") for e in fs.events)


@pytest.mark.parametrize("kind", ["relative", "missing", "regular-file"])
def test_destination_shape_refuses(module, tmp_path, kind):
    identity = module.storage_wire.Identity("dev-compat-r1", 1, "00" * 32, "11" * 32)
    path = Path("relative") if kind == "relative" else tmp_path / "missing"
    if kind == "regular-file": path.write_bytes(b"retained")
    with pytest.raises(module.ReceiverError): module.bind_destination(path, expected=identity)


def test_first_fault_survives_status_unknown_write(module, tmp_path):
    clock, fs, identity, destination = setup(module, tmp_path)
    writes = []
    def write(handle, data):
        writes.append(len(data))
        if len(writes) == 1: return fs.real.write(handle, data[:7])
        fs.real.write(handle, data[:3])
        raise OSError("MUST_NOT_ECHO")
    fs.write = write
    result = module.receive_capture(module.BytesReader(VALID), expected=identity,
        destination=destination, reservation=module.CaseReservation(), deadline=10, clock=clock)
    assert result.code == "SHORT_WRITE" and result.outcome == "UNKNOWN"
    assert result.complete_sha256 is None and not result.status_committed
    assert result.capture_bytes == result.capture_charged_bytes == 7
    assert result.status_bytes is None and result.status_charged_bytes == writes[1]
    assert len(writes) == 2


@pytest.mark.parametrize("field,value", [("mode", stat.S_IFDIR), ("nlink", 2),
    ("owner_uid", -9876), ("reparse", True), ("logical_bytes", True), ("token", (True,)),
    ("token", ()), ("kind", "unsupported")])
def test_input_metadata_rejects_unqualified_snapshots(module, tmp_path, field, value):
    class Reader:
        def snapshot(self):
            values = dict(kind="ordinary-file", token=(1,), logical_bytes=len(VALID),
                          mode=stat.S_IFREG | 0o600, nlink=1,
                          owner_uid=os.getuid() if hasattr(os, "getuid") else 0, reparse=False)
            values[field] = value
            return module.InputSnapshot(**values)
        def read(self, maximum): raise AssertionError("must reject before reading")
    result, _, identity = receive(module, tmp_path, reader=Reader())
    assert result.outcome != "COMPLETE" and result.complete_sha256 is None
    assert not (tmp_path / identity.host_capture_name).exists()
