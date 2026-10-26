"""Independent finite storage-v3 conformance with preserved oracle chronology.

Original provenance predates source inspection. The High repair is issue-informed;
its length-stage expectations follow INT's normative addendum, not source output.

These are pure byte tests. Neither framing nor semantic success proves native
eligibility, staging, receiver effects, custody, retention, or durability.
Builders serialize finite trusted vectors; they do not parse candidate output.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import types

import pytest

FIXTURES = Path(__file__).with_name("storage_wire_v3_fixtures")
LITERALS = json.loads((FIXTURES / "literal_examples.json").read_bytes())
VECTORS = json.loads((FIXTURES / "finite_vectors.json").read_bytes())
TUPLES = json.loads((FIXTURES / "identity_tuples.json").read_bytes())
CAPS = (16384,) * 3 + (2097152,) * 3 + (262144,) * 3 + (16384,) * 3 + (
    2097152, 2097152, 65536, 65536, 262144, 65536, 65536, 65536,
    65536, 65536, 65536,
)
E = "00" * 32
MANIFEST = "11" * 32


@pytest.fixture(scope="module")
def wire():
    """Portable default; any external candidate requires an explicit exact SHA.

    Read/compile fresh bytes, never stale imported modules or pyc. The reviewer
    binds the external selector only after receiving the frozen candidate grant.
    """
    external = os.environ.get("STORAGE_WIRE_V3_TARGET")
    target = Path(external) if external else Path(__file__).resolve().parents[2] / "evals/scanners/storage_wire.py"
    if external:
        expected = os.environ.get("STORAGE_WIRE_V3_SHA256")
        assert expected and len(expected) == 64, "external target requires SHA256"
    else:
        expected = None
    before = target.read_bytes()
    digest = hashlib.sha256(before).hexdigest()
    if expected:
        assert digest == expected, "candidate bytes differ from bound SHA256"
    name = "_reviewer_storage_wire_v3_candidate"
    module = types.ModuleType(name)
    module.__file__ = str(target.resolve())
    sys.modules[name] = module
    exec(compile(before, str(target.resolve()), "exec"), module.__dict__)
    assert target.read_bytes() == before, "candidate changed during fresh compilation"
    print(f"STORAGE_CANDIDATE origin={module.__file__} sha256={digest}")
    yield module
    assert hashlib.sha256(target.read_bytes()).hexdigest() == digest


def identity(wire, phase="dev-compat-r1", ordinal=1, **overrides):
    values = dict(phase=phase, wire_ordinal=ordinal, e_sha256=E, slot_manifest_sha256=MANIFEST)
    values.update(overrides)
    return wire.Identity(**values)


def header(phase=0, ordinal=1):
    return struct.pack(">8sHBBHH32s32s", b"M4CAP02\n", 2, phase, ordinal, 23, 0,
                       bytes.fromhex(E), bytes.fromhex(MANIFEST))


def frame(value):
    payload = bytes.fromhex(value["payload_hex"])
    state = value["state"]
    digest = bytes(32) if state in (0, 3) else hashlib.sha256(payload).digest()
    return struct.pack(">BBBBQQ32s", value["id"], state, value["reason"], value["known"],
                       value["logical"], len(payload), digest) + payload


def finish(prefix):
    return prefix + struct.pack(">8sHQ32s", b"M4END02\n", 23, len(prefix), hashlib.sha256(prefix).digest())


def build(values, phase=0, ordinal=1):
    return finish(header(phase, ordinal) + b"".join(frame(v) for v in values))


def vectors(name="V01_ALL_MISSING"):
    return deepcopy(VECTORS[name])


def complete(values, rid, payload):
    values[rid - 1].update(state=1, reason=0, known=1, logical=len(payload), payload_hex=payload.hex())


def expect_error(wire, blob, step, code, record_id=None, expected=None):
    with pytest.raises(wire.FramingError) as caught:
        wire.decode_framing(blob, expected=expected or identity(wire))
    error = caught.value
    assert isinstance(error, wire.WireError)
    assert isinstance(error, ValueError)
    assert (error.step, error.code) == (step, code)
    if record_id is not None:
        assert error.record_id == record_id


def not_accepted(wire, capture):
    state = wire.validate_state(capture)
    assert state.native_eligible is False
    assert state.durable_verified is False
    return state


@pytest.mark.parametrize("example", LITERALS, ids=lambda x: x["id"])
def test_all_literal_examples(wire, example):
    """Catch incompatibility with any of the 32 immutable DATA specimens."""
    blob = bytes.fromhex(example["hex"])
    assert hashlib.sha256(blob).hexdigest() == example["sha256"]
    if not example["framing_valid"]:
        expect_error(wire, blob, example["step"], example["error"])
        return
    capture = wire.decode_framing(blob, expected=identity(wire))
    assert capture.sha256 == example["sha256"]
    assert len(capture.records) == 23
    assert tuple(r.record_id for r in capture.records) == tuple(range(1, 24))
    if not example["state_valid"]:
        with pytest.raises(wire.StateError) as caught:
            wire.validate_state(capture)
        assert (caught.value.step, caught.value.code) == (11, "STATE_OR_CLOSURE_INCOMPLETE")
    else:
        state = not_accepted(wire, capture)
        assert state.required_records_present is False
        if example["declared_arm_states"]:
            assert state.arm_states == tuple(example["declared_arm_states"][a] for a in ("C", "C-custom", "T"))


@pytest.mark.parametrize("row", TUPLES, ids=lambda r: f'{r["phase"]}-wire{r["wire_ordinal"]}-case{r["case_ordinal"]}')
def test_exact_identity_bijection(wire, row):
    """Catch silent compatibility case renumbering or filename derivation."""
    expected = identity(wire, row["phase"], row["wire_ordinal"])
    for field in ("case_ordinal", "case_id", "host_capture_name", "host_status_name"):
        assert getattr(expected, field) == row[field]
    capture = wire.decode_framing(build(vectors(), int(row["phase"] == "dev-primary-r1"), row["wire_ordinal"]), expected=expected)
    assert capture.identity == expected
    assert not_accepted(wire, capture).arm_states == ("unstarted",) * 3


@pytest.mark.parametrize("offset,value", [(0,0),(8,1),(9,3),(10,2),(11,0),(11,5),(12,1),(13,22),(14,1),(15,1)])
def test_bad_header_before_records(wire, offset, value):
    blob = bytearray(build(vectors())); blob[offset] = value
    expect_error(wire, bytes(blob), 1, "HEADER_SYNTAX")


@pytest.mark.parametrize("length", [0,1,7,8,9,12,16,47,79])
def test_truncated_fixed_header(wire, length):
    expect_error(wire, header()[:length], 1, "HEADER_SYNTAX")


@pytest.mark.parametrize("offset", [16,47,48,79])
def test_both_raw_digest_identity_domains(wire, offset):
    blob = bytearray(build(vectors())); blob[offset] ^= 1
    expect_error(wire, bytes(blob), 2, "IDENTITY_BINDING")


@pytest.mark.parametrize("phase,ordinal", [(1,1),(0,2)])
def test_header_request_identity_mismatch(wire, phase, ordinal):
    expect_error(wire, build(vectors(),phase,ordinal), 2,"IDENTITY_BINDING")


@pytest.mark.parametrize("rid,new_id", [(1,0),(1,24),(2,1),(2,3),(23,22)])
def test_order_duplicate_unknown_id(wire, rid, new_id):
    values = vectors(); values[rid-1]["id"] = new_id
    expect_error(wire, build(values),3,"RECORD_ORDINAL")


@pytest.mark.parametrize("rid,changes", [
    (1,{"state":4}),(1,{"reason":10}),(1,{"reason":0}),(1,{"reason":8}),
    (17,{"reason":1}),(1,{"known":1}),(1,{"logical":1}),
    (1,{"payload_hex":"61"}),
    (1,{"state":1,"reason":1,"known":1}),(1,{"state":1,"reason":0}),
    (1,{"state":2,"reason":2,"known":1,"logical":1}),
    (1,{"state":2,"reason":3,"logical":1}),
    (17,{"state":2,"reason":3,"known":1,"logical":1}),
    (1,{"state":3,"reason":0}),(1,{"state":3,"reason":5,"payload_hex":"61"}),
    (1,{"state":3,"reason":5,"logical":1}),
    (1,{"state":3,"reason":4}),
], ids=lambda x: str(x))
def test_per_frame_state_encoding(wire, rid, changes):
    values=vectors(); values[rid-1].update(changes)
    expect_error(wire,build(values),4,"STATE_ENCODING",rid)


@pytest.mark.parametrize("rid", range(1,24))
@pytest.mark.parametrize("delta", [-1,0,1], ids=["cap-minus1","cap","cap-plus1"])
def test_role_length_before_payload_read(wire,rid,delta):
    """Tiny actual input catches unsafe allocation/read before declared cap check."""
    prefix=header()+b"".join(frame(v) for v in vectors()[:rid-1])
    n=CAPS[rid-1]+delta
    malicious=prefix+struct.pack(">BBBBQQ32s",rid,1,0,1,n,n,hashlib.sha256(b"").digest())
    expect_error(wire,malicious,5 if delta==1 else 6,"LENGTH_CAP" if delta==1 else "PAYLOAD_EOF_OR_IO",rid)


@pytest.mark.parametrize("n", [2**32,2**63,2**64-1])
def test_huge_declared_length_stays_small(wire,n):
    blob=header()+struct.pack(">BBBBQQ32s",1,1,0,1,n,n,bytes(32))
    assert len(blob)==132
    expect_error(wire,blob,5,"LENGTH_CAP",1)


@pytest.mark.parametrize("rid", [1,7,16])
@pytest.mark.parametrize("length", [0,1,19,20,51])
def test_record_header_prefix(wire,rid,length):
    values=vectors(); prefix=header()+b"".join(frame(v) for v in values[:rid-1])
    # INT frozen error-stage addendum: step3 owns the fixed52B header read.
    expect_error(wire,prefix+frame(values[rid-1])[:length],3,"RECORD_ORDINAL")


@pytest.mark.parametrize("rid", [1,4,7,10,13,14,15,16])
@pytest.mark.parametrize("payload", [b"",b"\0a\0",b"\xff\xfe", "é雪".encode(),b"a\r\n b\n"])
def test_originals_are_opaque_exact_bytes(wire,rid,payload):
    values=vectors(); complete(values,rid,payload)
    capture=wire.decode_framing(build(values),expected=identity(wire))
    record=capture.records[rid-1]
    assert record.payload==payload
    assert record.retained_length==record.logical_length==len(payload)
    assert record.retained_sha256==hashlib.sha256(payload).hexdigest()
    assert record.state==1


def test_missing_empty_and_partial_never_collapse(wire):
    missing=wire.decode_framing(build(vectors()),expected=identity(wire)).records[0]
    values=vectors();complete(values,1,b"")
    empty=wire.decode_framing(build(values),expected=identity(wire)).records[0]
    assert missing.payload==empty.payload==b""
    assert missing.state==0 and missing.retained_sha256=="00"*32
    assert empty.state==1 and empty.retained_sha256==hashlib.sha256(b"").hexdigest()
    values=vectors("V03_EXACT_READ_FAILURE_PREFIX")
    part=wire.decode_framing(build(values),expected=identity(wire)).records[3]
    assert part.state==2 and part.retained_length==1 and part.logical_length==3
    assert part.payload==bytes.fromhex(values[3]["payload_hex"])
    assert part.retained_sha256==hashlib.sha256(part.payload).hexdigest()
    assert part.retained_sha256!=hashlib.sha256(part.payload+b"\0\0").hexdigest()


@pytest.mark.parametrize("payload", [b"\0a",b"\xff\xfe", "é雪".encode(),b"a\r\n"])
def test_stale_payload_hash_rejected_before_trailer(wire,payload):
    values=vectors();complete(values,1,payload);blob=bytearray(build(values));blob[132]^=1
    expect_error(wire,bytes(blob),7,"PAYLOAD_HASH",1)


@pytest.mark.parametrize("length", [0,1,8,9,10,17,18,49])
def test_truncated_trailer(wire,length):
    blob=build(vectors());expect_error(wire,blob[:-50]+blob[-50:][:length],9,"TRAILER")


@pytest.mark.parametrize("offset", [0,7,8,9,10,17,18,49])
def test_trailer_fields_and_hash_domains(wire,offset):
    blob=bytearray(build(vectors()));blob[len(blob)-50+offset]^=1
    expect_error(wire,bytes(blob),9,"TRAILER")


@pytest.mark.parametrize("suffix", [b"\0",b"\n",b"extra",header()])
def test_immediate_eof(wire,suffix):
    expect_error(wire,build(vectors())+suffix,10,"TRAILING_BYTES")


@pytest.mark.parametrize("rid", [4,7,10])
def test_complete_start_forbids_not_started(wire,rid):
    values=vectors("V04_UNDERCAP_LOGICAL_ZEROS")
    values[rid-1].update(state=0,reason=1,known=0,logical=0,payload_hex="")
    capture=wire.decode_framing(build(values),expected=identity(wire))
    with pytest.raises(wire.StateError) as caught:wire.validate_state(capture)
    assert (caught.value.step,caught.value.code)==(11,"STATE_OR_CLOSURE_INCOMPLETE")


def test_rejected_start_is_unknown(wire):
    capture=wire.decode_framing(build(vectors("V05_LOGICAL_OVERCAP_REJECTED")),expected=identity(wire))
    state=not_accepted(wire,capture)
    assert state.arm_states==("unknown","unstarted","unstarted")
    assert state.required_records_present is False


@pytest.mark.parametrize("value,expected", [
    ({},b"{}\n"),({"b":False,"a":None},b'{"a":null,"b":false}\n'),
    ({"x":[True,False,None,0,18446744073709551615]},b'{"x":[true,false,null,0,18446744073709551615]}\n'),
    ({"quote":'"',"slash":"/","backslash":"\\"},b'{"backslash":"\\\\","quote":"\\\"","slash":"/"}\n'),
])
def test_canonical_serializer_exact_bytes(wire,value,expected):
    assert wire.canonical_json(value)==expected


@pytest.mark.parametrize("value", [
    {"x":"é"},{"x":"雪"},{"x":"\ud800"},{"x":"\n"},{"x":"\x7f"},
    {"x":1.0},{"x":float("nan")},{"x":float("inf")},{"x":2**64},
    {"x":"a"*257},{"a"*65:0},{1:"x"},{"x":b"a"},
])
def test_canonical_serializer_rejects_unicode_coercion_and_overflow(wire,value):
    with pytest.raises(wire.FramingError) as caught:wire.canonical_json(value)
    assert (caught.value.step,caught.value.code)==(8,"GENERATED_SCHEMA_OR_CANONICAL")


def json_bytes(value):
    """Serialize our finite ASCII test vectors independently of product code."""
    return (json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True)+"\n").encode()


def generated_mutation(kind):
    values=vectors("V06_CLOSED_METADATA_INCOMPLETE")
    payload=bytes.fromhex(values[16]["payload_hex"])
    obj=json.loads(payload)
    if kind=="invalid_utf8":payload=b'\xff'+payload[1:]
    elif kind=="BOM":payload=b'\xef\xbb\xbf'+payload
    elif kind=="non_ascii":payload=payload.replace(b'"version":3',b'"version":"\xc3\xa9"')
    elif kind=="unicode_escape":payload=payload.replace(b'"phase":',b'"\\u0070hase":')
    elif kind=="slash_escape":payload=payload.replace(b'"version":3',b'"version":"\\/"')
    elif kind=="control_escape":payload=payload.replace(b'"version":3',b'"version":"\\n"')
    elif kind=="duplicate_key":payload=payload.replace(b'"version":3',b'"version":3,"version":3')
    elif kind=="whitespace":payload=payload.replace(b'"version":3',b'"version": 3')
    elif kind=="key_order":payload=(json.dumps(dict(reversed(list(obj.items()))),separators=(",",":"))+"\n").encode()
    elif kind=="missing_LF":payload=payload[:-1]
    elif kind=="double_LF":payload+=b"\n"
    elif kind=="trailing_space":payload+=b" "
    elif kind in ("float","exponent","negative_zero","leading_zero","NaN","Infinity"):
        token={"float":b"3.0","exponent":b"3e0","negative_zero":b"-0","leading_zero":b"03","NaN":b"NaN","Infinity":b"Infinity"}[kind]
        payload=payload.replace(b'"version":3',b'"version":'+token)
    else:
        if kind=="unknown_field":obj["extension"]=False
        elif kind=="missing_field":del obj["originals"]
        elif kind=="bool_as_int":obj["wire_ordinal"]=True
        elif kind=="null_as_int":obj["wire_ordinal"]=None
        elif kind=="string_as_int":obj["wire_ordinal"]="1"
        elif kind=="too_deep":obj["extension"]={"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":{"i":0}}}}}}}}}
        elif kind=="key_too_long":obj["a"*65]=0
        elif kind=="string_too_long":obj["case_id"]="a"*257
        elif kind=="integer_overflow":obj["originals"][0]["logical_bytes"]=2**64
        elif kind=="wrong_version":obj["version"]=2
        elif kind=="wrong_arm_order":obj["arm_states"].reverse()
        elif kind=="original_order":obj["originals"].reverse()
        elif kind=="generated_order":obj["generated_presence"].reverse()
        elif kind=="metadata_identity":obj["case_ordinal"]=8
        elif kind=="original_observation":obj["originals"][0]["logical_bytes"]=0
        elif kind=="generated_presence":obj["generated_presence"][1]["state"]="missing"
        else:raise AssertionError(kind)
        payload=json_bytes(obj)
    complete(values,17,payload)
    if kind=="generated_presence":
        # Keep the intended planned/observed mismatch, with honest prefix length.
        refresh_accounting(values)
    return build(values)


@pytest.mark.parametrize("kind", [
    "invalid_utf8","BOM","non_ascii","unicode_escape","slash_escape","control_escape",
    "duplicate_key","whitespace","key_order","missing_LF","double_LF","trailing_space",
    "float","exponent","negative_zero","leading_zero","NaN","Infinity",
    "unknown_field","missing_field","bool_as_int","null_as_int","string_as_int",
    "too_deep","key_too_long","string_too_long","integer_overflow","wrong_version",
    "wrong_arm_order","original_order","generated_order","metadata_identity",
    "original_observation","generated_presence",
])
def test_generated_closed_canonical_schema(wire,kind):
    """Honest recomputed wire hashes cannot bless noncanonical/false metadata."""
    # No cross-record diagnostic record-ID precedence is specified for this join.
    expect_error(wire,generated_mutation(kind),8,"GENERATED_SCHEMA_OR_CANONICAL",
                 None if kind=="generated_presence" else 17)


def refresh_accounting(values):
    """Recompute only the honest prefix observation in our finite fixture."""
    obj=json.loads(bytes.fromhex(values[20]["payload_hex"]))
    obj["observed_capture_bytes_before_record21"]=80+sum(len(frame(v)) for v in values[:20])
    complete(values,21,json_bytes(obj))


@pytest.mark.parametrize("declared,expected", [("unstarted",("unstarted",)*3),("aborted",("aborted","unstarted","unstarted"))])
def test_declared_failed_state_does_not_create_eligibility(wire,declared,expected):
    values=vectors("V06_CLOSED_METADATA_INCOMPLETE")
    obj=json.loads(bytes.fromhex(values[16]["payload_hex"]))
    obj["arm_states"][0]["state"]=declared
    if declared=="aborted":
        for rid in (1,4,7,10):values[rid-1]["reason"]=2
    complete(values,17,json_bytes(obj));refresh_accounting(values)
    capture=wire.decode_framing(build(values),expected=identity(wire))
    state=not_accepted(wire,capture)
    assert state.arm_states==expected
    assert state.required_records_present is False


@pytest.mark.parametrize("field,value", [("driver_terminal","error"),("source_read_complete",False)])
def test_error_transport_metadata_cannot_upgrade(wire,field,value):
    values=vectors("V06_CLOSED_METADATA_INCOMPLETE")
    obj=json.loads(bytes.fromhex(values[22]["payload_hex"]))
    obj[field]=value;complete(values,23,json_bytes(obj))
    state=not_accepted(wire,wire.decode_framing(build(values),expected=identity(wire)))
    assert state.required_records_present is False


@pytest.mark.parametrize("declared", ["started","finished"])
def test_declared_start_or_finish_cannot_synthesize_missing_originals(wire,declared):
    values=vectors("V06_CLOSED_METADATA_INCOMPLETE")
    obj=json.loads(bytes.fromhex(values[16]["payload_hex"]))
    obj["arm_states"][0]["state"]=declared
    complete(values,17,json_bytes(obj));refresh_accounting(values)
    capture=wire.decode_framing(build(values),expected=identity(wire))
    with pytest.raises(wire.StateError) as caught:wire.validate_state(capture)
    assert (caught.value.step,caught.value.code)==(11,"STATE_OR_CLOSURE_INCOMPLETE")


def test_accounting_prefix_is_observed_not_final_size(wire):
    values=vectors("V06_CLOSED_METADATA_INCOMPLETE")
    obj=json.loads(bytes.fromhex(values[20]["payload_hex"]))
    obj["observed_capture_bytes_before_record21"]+=1
    complete(values,21,json_bytes(obj))
    expect_error(wire,build(values),8,"GENERATED_SCHEMA_OR_CANONICAL",21)


@pytest.mark.parametrize("value", [None,True,0,"x",[],[{}]])
def test_canonical_payload_requires_top_object(wire,value):
    with pytest.raises(wire.FramingError) as caught:wire.canonical_json(value)
    assert (caught.value.step,caught.value.code)==(8,"GENERATED_SCHEMA_OR_CANONICAL")


def test_canonical_nesting_bound(wire):
    value={"x":0}
    for _ in range(9):value={"x":value}
    with pytest.raises(wire.FramingError) as caught:wire.canonical_json(value)
    assert (caught.value.step,caught.value.code)==(8,"GENERATED_SCHEMA_OR_CANONICAL")


@pytest.mark.parametrize("row", TUPLES, ids=lambda r:f'{r["phase"]}-metadata-wire{r["wire_ordinal"]}')
def test_all_generated_metadata_preserve_original_case_tuple(wire,row):
    """All seven metadata joins, not just Identity properties, preserve cases."""
    values=vectors("V06_CLOSED_METADATA_INCOMPLETE")
    for rid in range(17,24):
        obj=json.loads(bytes.fromhex(values[rid-1]["payload_hex"]))
        obj.update(row)
        if rid==21:obj["phase_allocated_bytes"]=201326592 if row["phase"]=="dev-compat-r1" else 536870912
        complete(values,rid,json_bytes(obj))
    refresh_accounting(values)
    capture=wire.decode_framing(build(values,int(row["phase"]=="dev-primary-r1"),row["wire_ordinal"]),expected=identity(wire,row["phase"],row["wire_ordinal"]))
    state=not_accepted(wire,capture)
    assert state.required_records_present is False


def test_payload_hash_error_does_not_echo_opaque_content(wire):
    marker=b"SYNTHETIC_OPAQUE_PAYLOAD_DO_NOT_ECHO"
    values=vectors();complete(values,1,marker)
    blob=bytearray(build(values));blob[100]^=1
    with pytest.raises(wire.FramingError) as caught:wire.decode_framing(bytes(blob),expected=identity(wire))
    assert (caught.value.step,caught.value.code,caught.value.record_id)==(7,"PAYLOAD_HASH",1)
    assert marker.decode() not in str(caught.value)
    assert marker.decode() not in repr(caught.value.args)


def test_rejected_observed_start_cannot_prove_not_started(wire):
    values=vectors("V05_LOGICAL_OVERCAP_REJECTED")
    values[3]["reason"]=1
    capture=wire.decode_framing(build(values),expected=identity(wire))
    with pytest.raises(wire.StateError) as caught:wire.validate_state(capture)
    assert (caught.value.step,caught.value.code)==(11,"STATE_OR_CLOSURE_INCOMPLETE")


@pytest.mark.parametrize("logical,retained",[(0,1),(2,1),(1,2)])
def test_complete_length_relation_is_checked_before_payload(wire,logical,retained):
    blob=header()+struct.pack(">BBBBQQ32s",1,1,0,1,logical,retained,bytes(32))
    expect_error(wire,blob,5,"LENGTH_CAP",1)


@pytest.mark.parametrize("logical,retained",[(0,0),(1,1),(1,2)])
def test_partial_length_relation_is_checked_before_payload(wire,logical,retained):
    blob=header()+struct.pack(">BBBBQQ32s",1,2,3,1,logical,retained,bytes(32))
    expect_error(wire,blob,5,"LENGTH_CAP",1)


@pytest.mark.parametrize("rid",[1,4,17,23])
def test_overcap_rejection_is_zero_payload_and_keeps_unknown_state(wire,rid):
    values=vectors();values[rid-1].update(state=3,reason=4,known=1,logical=CAPS[rid-1]+1)
    if rid in (1,4):
        for arm_id in (1,4,7,10):
            if arm_id!=rid:values[arm_id-1]["reason"]=2
    capture=wire.decode_framing(build(values),expected=identity(wire))
    record=capture.records[rid-1]
    assert record.state==3 and record.payload==b"" and record.retained_length==0
    assert record.retained_sha256=="00"*32
    assert record.logical_length==CAPS[rid-1]+1
    assert not_accepted(wire,capture).required_records_present is False


def test_omitted_required_identity_is_python_call_binding_failure(wire):
    with pytest.raises(TypeError):wire.decode_framing(build(vectors()))


@pytest.mark.parametrize("expected",[None,False,0,"",[],{},object()])
def test_explicit_invalid_identity_is_not_coerced(wire,expected):
    with pytest.raises(wire.FramingError) as caught:wire.decode_framing(build(vectors()),expected=expected)
    assert (caught.value.step,caught.value.code)==(2,"IDENTITY_BINDING")


@pytest.mark.parametrize("changes",[
    {"phase":"other"},{"phase":None},{"wire_ordinal":True},{"wire_ordinal":1.0},
    {"wire_ordinal":"1"},{"wire_ordinal":0},{"wire_ordinal":5},
    {"e_sha256":None},{"e_sha256":"00"*31},{"e_sha256":"AA"*32},
    {"slot_manifest_sha256":bytes.fromhex(MANIFEST)},{"slot_manifest_sha256":"gg"*32},
])
def test_invalid_identity_fields_are_not_coerced(wire,changes):
    with pytest.raises(wire.FramingError) as caught:
        expected=identity(wire,**changes)
        wire.decode_framing(build(vectors()),expected=expected)
    assert (caught.value.step,caught.value.code)==(2,"IDENTITY_BINDING")


def test_header_syntax_precedes_explicit_bad_identity(wire):
    with pytest.raises(wire.FramingError) as caught:wire.decode_framing(b"",expected=None)
    assert (caught.value.step,caught.value.code)==(1,"HEADER_SYNTAX")


@pytest.mark.parametrize("phase,ordinal",[(1,0),(1,25),(1,255),(0,255)])
def test_phase_specific_wire_ordinal_limits(wire,phase,ordinal):
    expect_error(wire,header(phase,ordinal),1,"HEADER_SYNTAX")


@pytest.mark.parametrize("reason",[5,6,7,9])
@pytest.mark.parametrize("known,logical",[(0,0),(1,0),(1,2**64-1)])
def test_rejected_source_observation_is_not_fabricated_payload(wire,reason,known,logical):
    values=vectors();values[0].update(state=3,reason=reason,known=known,logical=logical)
    for rid in (4,7,10):values[rid-1]["reason"]=2
    capture=wire.decode_framing(build(values),expected=identity(wire))
    record=capture.records[0]
    assert record.logical_length==logical and record.logical_known is bool(known)
    assert record.payload==b"" and record.retained_sha256=="00"*32
    assert not_accepted(wire,capture).arm_states==("unknown","unstarted","unstarted")


@pytest.mark.parametrize("rid", [1,4,17,23])
@pytest.mark.parametrize("delta", [-1,0,1], ids=["below-cap","at-cap","above-cap"])
def test_rejected_overcap_numeric_stage(wire,rid,delta):
    """INT length-stage addendum: known numerical IDcap predicates belong to5."""
    values=vectors();values[rid-1].update(state=3,reason=4,known=1,logical=CAPS[rid-1]+delta)
    blob=build(values)
    if delta<=0:
        expect_error(wire,blob,5,"LENGTH_CAP",rid)
    else:
        record=wire.decode_framing(blob,expected=identity(wire)).records[rid-1]
        assert record.state==3 and record.reason==4 and record.logical_known is True
        assert record.logical_length==CAPS[rid-1]+1
        assert record.retained_length==0 and record.payload==b""
        assert record.retained_sha256=="00"*32


@pytest.mark.parametrize("logical", [16383,16384,16385])
def test_rejected_overcap_unknown_length_is_structural_stage4(wire,logical):
    values=vectors();values[0].update(state=3,reason=4,known=0,logical=logical)
    expect_error(wire,build(values),4,"STATE_ENCODING",1)


@pytest.mark.parametrize("earlier,step,code", [
    ({"id":2},3,"RECORD_ORDINAL"),
    ({"reason":10},4,"STATE_ENCODING"),
    ({"known":0},4,"STATE_ENCODING"),
])
def test_rejected_overcap_earlier_error_precedence(wire,earlier,step,code):
    values=vectors();values[0].update(state=3,reason=4,known=1,logical=16384)
    values[0].update(earlier)
    expect_error(wire,build(values),step,code)


def complete_candidate_values(driver_terminal="normal"):
    """Finite synthetic step11 operand, never original execution/custody proof.

    CONTRACT-v3 presence/driver13_14, two_completenesses and validation_order11;
    SCHEMAS-v3 record17..23 and canonical tuple_rules determine each declaration.
    Only the requested driver enum differs across the four candidate specimens.
    """
    values=vectors("V06_CLOSED_METADATA_INCOMPLETE")
    for rid in range(1,17):
        complete(values,rid,f"SYNTHETIC-ORIGINAL-{rid:02d}\n".encode("ascii"))
    inventory=json.loads(bytes.fromhex(values[16]["payload_hex"]))
    for arm in inventory["arm_states"]:arm["state"]="finished"
    for observed,value in zip(inventory["originals"],values[:16]):
        payload=bytes.fromhex(value["payload_hex"])
        observed.update(state="complete",logical_bytes=len(payload),retained_bytes=len(payload),
                        retained_sha256=hashlib.sha256(payload).hexdigest(),
                        regular_nlink1_verified=True,source_stable_verified=True)
    complete(values,17,json_bytes(inventory))
    fault=json.loads(bytes.fromhex(values[17]["payload_hex"]))
    fault.update(first_fault="NONE",errors=[])
    complete(values,18,json_bytes(fault))
    custody=json.loads(bytes.fromhex(values[19]["payload_hex"]))
    for key in ("results_consumer_read_only","continuous_same_mount_verified",
                "all_writers_quiescent_verified","no_rw_attachment_verified"):
        custody[key]=True
    complete(values,20,json_bytes(custody))
    closure=json.loads(bytes.fromhex(values[21]["payload_hex"]))
    closure.update(available_preservation="complete-candidate",required_capture="complete-candidate",
                   original_execution="candidate",original_failure_observed=False)
    complete(values,22,json_bytes(closure))
    transport=json.loads(bytes.fromhex(values[22]["payload_hex"]))
    transport["driver_terminal"]=driver_terminal
    for key in ("attach_stdout_complete","attach_stderr_complete","source_read_complete",
                "continuous_same_mount_verified","all_writers_quiescent_verified",
                "no_rw_attachment_verified"):
        transport[key]=True
    complete(values,23,json_bytes(transport))
    refresh_accounting(values)
    return values


@pytest.mark.parametrize("driver_terminal", ["normal","not-started","unknown","error"])
def test_complete_candidate_requires_normal_finished_driver(wire,driver_terminal):
    """Catch SW-M-01 without interpreting any opaque original as native proof."""
    values=complete_candidate_values(driver_terminal)
    capture=wire.decode_framing(build(values),expected=identity(wire))
    assert all(record.state==1 for record in capture.records)
    if driver_terminal=="normal":
        state=not_accepted(wire,capture)
        assert state.arm_states==("finished",)*3
        assert state.required_records_present is True
    else:
        with pytest.raises(wire.StateError) as caught:wire.validate_state(capture)
        assert isinstance(caught.value,wire.WireError)
        assert (caught.value.step,caught.value.code)==(11,"STATE_OR_CLOSURE_INCOMPLETE")


@pytest.mark.parametrize("driver_terminal", ["not-started","unknown","error"])
def test_incomplete_driver_observation_remains_valid_ineligible(wire,driver_terminal):
    """Missing originals plus incomplete claims do not pretend a finished driver."""
    values=vectors("V06_CLOSED_METADATA_INCOMPLETE")
    obj=json.loads(bytes.fromhex(values[22]["payload_hex"]))
    obj["driver_terminal"]=driver_terminal
    complete(values,23,json_bytes(obj))
    state=not_accepted(wire,wire.decode_framing(build(values),expected=identity(wire)))
    assert state.arm_states==("unstarted",)*3
    assert state.required_records_present is False
