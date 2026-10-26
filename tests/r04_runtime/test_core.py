"""Contract-derived inert controls; never instantiate an operational context."""

from copy import deepcopy
from pathlib import Path, PureWindowsPath
from subprocess import CompletedProcess

import pytest

from . import fixture_data as data


class Receipts:
    def __init__(self):
        self.pre, self.post, self.unknown = {}, {}, []
        self.corrupt_post = False

    def create_pre(self, slot, value):
        assert slot["slot"] not in self.pre
        self.pre[slot["slot"]] = deepcopy(value)
        return data.sha(data.canonical(value))

    def read_pre(self, slot):
        return deepcopy(self.pre[slot["slot"]])

    def create_post(self, slot, value):
        assert slot["slot"] not in self.post
        self.post[slot["slot"]] = deepcopy(value)
        return data.sha(data.canonical(value))

    def read_post(self, slot):
        value = deepcopy(self.post[slot["slot"]])
        if self.corrupt_post:
            value["synthetic"] = False
        return value

    def mark_unknown(self, slot, reason):
        self.unknown.append((slot["slot"], reason))


@pytest.fixture
def model():
    from runtime_v1 import context
    from runtime_v1 import runtime_manifest as rm

    # Pins are synthetic reader DATA, not filesystem admission or external trust.
    pins = {"context.py": "1" * 64}
    manifest, grant, invocation, tokens = data.original_documents(pins)
    m = rm.parse_manifest(
        data.canonical(manifest), expected_harness_pins=pins, frozen=rm.load_frozen_bindings()
    )
    g = rm.parse_grant(data.canonical(grant), manifest=m)
    i = rm.parse_invocation(data.canonical(invocation), manifest=m, grant=g)
    expected = {
        str(PureWindowsPath(manifest["runroot"]) / "OWNERSHIP.json"): manifest[
            "namespace_ownership_sha256"
        ]
    }
    expected.update(
        {
            str(PureWindowsPath(manifest["snapshot"]).joinpath(*name.split("/"))): row["sha256"]
            for name, row in manifest["closure32"].items()
        }
    )
    expected.update(
        {
            str(PureWindowsPath(str(Path(context.__file__).parent)) / name): value
            for name, value in pins.items()
        }
    )
    for field in ("interpreter", "powershell"):
        expected[manifest[field]["path"]] = manifest[field]["sha256"]
    expected[manifest["powershell"]["resolved_path"]] = manifest["powershell"]["sha256"]
    store = Receipts()
    state = {"slot": None, "changes": {}}

    def observe(relation, result, error):
        selected = state["slot"]
        if relation is None:
            return data.original_relation(manifest, selected)
        result = data.original_post_state(selected, relation)
        result.update(state["changes"])
        return result

    ctx = context.InertContext(
        m,
        g,
        i,
        tokens=tokens,
        pin_reader=lambda path: expected[path],
        observation_reader=observe,
        receipt_store=store,
    )
    return {
        "context": ctx,
        "module": context,
        "rm": rm,
        "manifest": manifest,
        "grant": grant,
        "invocation": invocation,
        "m": m,
        "g": g,
        "i": i,
        "store": store,
        "state": state,
        "expected": expected,
    }


def run_slot(model, index=0, *, events="valid", error=None):
    slot = model["manifest"]["slots"][index]
    model["state"]["slot"] = slot
    relation = data.original_relation(model["manifest"], slot)
    call = data.original_call(model["manifest"], slot, relation)
    result = None if slot["kind"] == "symlink" else CompletedProcess(call["args"][0], 0, b"", b"")
    event = data.expected_event(call)
    injected = (
        (event,)
        if events == "valid"
        else (
            ()
            if events == "missing"
            else (event, event)
            if events == "double"
            else (("socket.connect", ()),)
        )
    )
    marker = model["module"].InertDispatchMarker(injected, result, error)
    model["context"].current_node = slot["nodeid"]
    return model["context"].handle_inert(slot["nodeid"], call, marker)


def test_all_eight_finalize_after_post_readback(model):
    for index in range(8):
        run_slot(model, index)
        assert model["context"].pending_action is None
        assert len(model["store"].post) == index + 1
    assert not model["context"].poisoned


@pytest.mark.parametrize("has_fail", [False, True])
@pytest.mark.parametrize("reverse", [False, True])
def test_complete_canonical_order_and_fail_never_green(model, has_fail, reverse):
    for index in range(8):
        run_slot(model, index)
    ordered = data.frozen_data("ordered103.json")
    failed = ordered[17]
    for node in reversed(ordered) if reverse else ordered:
        model["context"].record_result_inert(
            node, "FAIL" if has_fail and node == failed else "PASS"
        )
    result = model["context"].check_complete_inert()
    assert list(result["results"]) == ordered
    assert result["complete_data"] is True
    assert result["success"] is (not has_fail)
    assert result["all_passed"] is (not has_fail)
    assert result["failed"] == ([failed] if has_fail else [])
    assert result["actual_runtime_verified"] is False
    assert result["synthetic"] is True


@pytest.mark.parametrize("count", [0, 7])
def test_complete_requires_all_slots(model, count):
    for index in range(count):
        run_slot(model, index)
    for node in data.frozen_data("ordered103.json"):
        model["context"].record_result_inert(node, "PASS")
    with pytest.raises(model["rm"].Denied):
        model["context"].check_complete_inert()
    assert model["context"].poisoned


@pytest.mark.parametrize("fault", ["missing", "extra", "duplicate", "status", "boolean"])
def test_result_domain_failures_poison(model, fault):
    ordered = data.frozen_data("ordered103.json")
    ctx = model["context"]
    with pytest.raises(model["rm"].Denied):
        if fault == "missing":
            for index in range(8):
                run_slot(model, index)
            for node in ordered[:-1]:
                ctx.record_result_inert(node, "PASS")
            ctx.check_complete_inert()
        elif fault == "extra":
            ctx.record_result_inert("foreign-node", "PASS")
        elif fault == "duplicate":
            ctx.record_result_inert(ordered[0], "PASS")
            ctx.record_result_inert(ordered[0], "PASS")
        else:
            ctx.record_result_inert(ordered[0], True if fault == "boolean" else "SKIP")
    assert ctx.poisoned
    with pytest.raises(model["rm"].Denied):
        ctx.require_exact()


@pytest.mark.parametrize("fault", ["missing", "double", "foreign"])
def test_audit_fault_persists_after_catch(model, fault):
    with pytest.raises((model["rm"].Denied, model["module"].Unknown)):
        run_slot(model, events=fault)
    assert model["context"].poisoned
    with pytest.raises(model["rm"].Denied):
        model["context"].require_exact()


def test_slot_replay_is_denied(model):
    run_slot(model)
    with pytest.raises(model["rm"].Denied):
        run_slot(model)
    assert model["context"].poisoned


def test_known_original_error_identity_and_stop(model):
    error = OSError("synthetic-original-error")
    with pytest.raises(OSError) as caught:
        run_slot(model, error=error)
    assert caught.value is error
    assert model["context"].poisoned
    assert len(model["store"].post) == 1
    with pytest.raises(model["rm"].Denied):
        run_slot(model, 1)


@pytest.mark.parametrize(
    "change",
    [
        {"known": False},
        {"ordinary": False},
        {"target_identity": "foreign"},
        {"link_kind": "file"},
        {"link_target": "C:\\foreign"},
        {"child_terminated": False},
    ],
)
def test_uncertain_observation_retains_original_cause(model, change):
    model["state"]["changes"] = change
    error = OSError("synthetic-cause")
    with pytest.raises(model["module"].Unknown) as caught:
        run_slot(model, error=error)
    assert caught.value.__cause__ is error
    assert model["context"].poisoned
    assert model["context"].pending_action is not None


def test_post_readback_failure_never_finalizes(model):
    model["store"].corrupt_post = True
    with pytest.raises(model["module"].Unknown):
        run_slot(model)
    assert model["context"].poisoned
    assert model["context"].pending_action is not None


def test_require_exact_both_forms(model):
    ctx = model["context"]
    ctx.require_exact()
    ctx.require_exact(model["m"].sha256, model["g"].sha256)
    assert not ctx.poisoned


@pytest.mark.parametrize(
    "arguments", [(), ("0" * 64,), ("0" * 64, "1" * 64), ("0" * 64, "1" * 64, "2" * 64)]
)
def test_invalid_hash_arity_or_join_refuses(model, arguments):
    if not arguments:
        arguments = (model["m"].sha256, "f" * 64)
    with pytest.raises(model["rm"].Denied):
        model["context"].require_exact(*arguments)
    assert model["context"].poisoned


@pytest.mark.parametrize("mutation", ["extra", "missing", "source", "slot", "token"])
def test_exact_seven_key_grant(model, mutation):
    value = deepcopy(model["grant"])
    if mutation == "extra":
        value["nonce_metadata_sha256"] = "0" * 64
    elif mutation == "missing":
        value.pop("purpose")
    elif mutation == "source":
        value["source_commit"] = "0" * 40
    elif mutation == "slot":
        value["slots"]["01"]["extra"] = True
    else:
        value["slots"]["01"]["token_sha256"] = "A" * 64
    with pytest.raises(model["rm"].Denied):
        model["rm"].parse_grant(data.canonical(value), manifest=model["m"])


@pytest.mark.parametrize(
    "raw", [b'{"a":1,"a":1}', b'{ "a":1}', b'{"a":NaN}', b'{"a":Infinity}', b"{}\n", b"\xff", b"[]"]
)
def test_canonical_decoder_refuses(model, raw):
    with pytest.raises(model["rm"].Denied):
        model["rm"].decode_canonical(raw)


@pytest.mark.parametrize(
    "field,value",
    [
        ("pin_source", "self-approved"),
        ("current_dispatch_purpose", "construction-only"),
        ("runtime_approved_digest", "0" * 64),
        ("extra", None),
    ],
)
def test_descriptive_authority_is_closed_null_data(model, field, value):
    manifest = deepcopy(model["manifest"])
    manifest["grant_authority"][field] = value
    with pytest.raises(model["rm"].Denied):
        model["rm"].parse_manifest(
            data.canonical(manifest),
            expected_harness_pins=manifest["harness_pins"],
            frozen=model["rm"].load_frozen_bindings(),
        )


def test_actual_entry_refuses_before_backend(model, monkeypatch):
    from runtime_v1 import guarded_context, metadata_backend

    def forbidden(*args, **kwargs):
        raise AssertionError("actual backend touched")

    monkeypatch.setattr(metadata_backend.LocalMetadataBackend, "__init__", forbidden)
    with pytest.raises(model["module"].ActualTrustUnavailable):
        guarded_context.load_actual_context()
    with pytest.raises(model["module"].ActualTrustUnavailable):
        model["module"].load_actual_context({"caller_approved": True})


@pytest.mark.parametrize("kind", ["file", "symlink", "junction", "absent"])
def test_ordinary_chain_refuses_nonordinary_injected_metadata(model, kind):
    from runtime_v1.metadata_backend import Metadata, ordinary_chain

    class Fake:
        def metadata(self, path):
            return Metadata(path, kind, "inert-identity")

    with pytest.raises(model["rm"].Denied):
        ordinary_chain(Fake(), "C:\\inert\\target")


def test_ordinary_chain_accepts_injected_directory(model):
    from runtime_v1.metadata_backend import Metadata, ordinary_chain

    class Fake:
        def metadata(self, path):
            return Metadata(path, "directory", "inert-identity")

    ordinary_chain(Fake(), "C:\\inert\\target")


@pytest.mark.parametrize("has_fail", [False, True])
def test_pure_completion_summary_is_not_slot_or_authority_proof(model, has_fail):
    ordered = data.frozen_data("ordered103.json")
    rows = [
        {"nodeid": node, "status": "FAIL" if has_fail and node == ordered[3] else "PASS"}
        for node in reversed(ordered)
    ]
    summary = model["rm"].summarize_results(rows)
    assert list(summary["results"]) == ordered
    assert summary["all_passed"] is (not has_fail)
    assert summary["success"] is (not has_fail)
    # Pure DATA acceptance has not completed any slots.
    with pytest.raises(model["rm"].Denied):
        model["context"].check_complete_inert()


@pytest.mark.parametrize("mutation", ["extra", "duplicate", "missing", "boolean", "unknown"])
def test_pure_summary_domain_closed(model, mutation):
    rows = [{"nodeid": node, "status": "PASS"} for node in data.frozen_data("ordered103.json")]
    if mutation == "extra":
        rows[0]["extra"] = None
    elif mutation == "duplicate":
        rows[-1] = deepcopy(rows[0])
    elif mutation == "missing":
        rows.pop()
    else:
        rows[0]["status"] = True if mutation == "boolean" else "SKIP"
    with pytest.raises(model["rm"].Denied):
        model["rm"].summarize_results(rows)


@pytest.mark.parametrize(
    "field,value",
    [
        ("pid", True),
        ("parent_pid", 0),
        ("image_sha256", "f" * 64),
        ("argv", ["x\x00y"]),
        ("environment", {"X": 1}),
    ],
)
def test_process_finite_origin_shape_refuses(model, field, value):
    from runtime_v1.origin_validation import validate_process

    process = {
        "pid": 101,
        "parent_pid": 102,
        "image": model["manifest"]["interpreter"]["path"],
        "image_sha256": model["manifest"]["interpreter"]["sha256"],
        "argv": ["inert-data"],
        "environment": {"INERT": "true"},
        "cwd": model["manifest"]["snapshot"],
    }
    validate_process(process)
    process[field] = value
    with pytest.raises(model["rm"].Denied):
        validate_process(process)


@pytest.mark.parametrize("fault", ["target", "link", "termination"])
def test_owned_observer_injected_metadata_refuses_and_retains_cause(model, fault):
    from runtime_v1.metadata_backend import Metadata
    from runtime_v1.origin_validation import observe_owned

    slot = model["manifest"]["slots"][0]
    relation = data.original_relation(model["manifest"], slot)
    pending = {
        "slot": slot,
        "relation": relation,
        "target_identity": relation["target_identity"],
        "pre_sha256": "a" * 64,
    }

    class Fake:
        def metadata(self, path):
            if path == relation["link"]:
                return Metadata(
                    path,
                    "symlink",
                    "inert-link",
                    "C:\\foreign" if fault == "link" else relation["target"],
                )
            return Metadata(
                path,
                "directory",
                "foreign"
                if fault == "target" and path == relation["target"]
                else relation["target_identity"],
            )

    error = OSError("inert-original-error")
    with pytest.raises(model["module"].Unknown) as caught:
        observe_owned(
            pending, relation, None, error, Fake(), child_terminated=fault != "termination"
        )
    assert caught.value.__cause__ is error


def test_public_stop_keeps_first_cause_and_blocks_rewrap(model):
    from runtime_launch.adapter import InertSession

    cause = OSError("first-inert-cause")
    assert model["context"].stop_inert("post-receipt-failure", cause) is None
    assert model["context"].stop_inert("protocol-failure", OSError("later")) is None
    with pytest.raises(model["rm"].Denied) as caught:
        model["context"].require_exact()
    assert caught.value.__cause__ is cause
    with pytest.raises(model["rm"].Denied):
        InertSession(
            model["context"],
            ordered=data.frozen_data("ordered103.json"),
            manifest_sha256=model["m"].sha256,
            grant_sha256=model["g"].sha256,
        )


def test_stop_does_not_stringify_untrusted_reason_or_cause(model):
    class NoString:
        def __str__(self):
            raise AssertionError("unexpected stringification")

    assert model["context"].stop_inert(NoString(), NoString()) is None
    with pytest.raises(model["rm"].Denied):
        model["context"].require_exact()
