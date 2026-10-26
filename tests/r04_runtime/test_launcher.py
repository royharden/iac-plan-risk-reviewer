"""Public inert launcher composition; no original body or audit hook executes."""

from subprocess import CompletedProcess

import pytest

from . import fixture_data as data
from . import test_core

model = test_core.model


@pytest.mark.parametrize("has_fail", [False, True])
def test_session_uses_outer_handle_and_canonical_complete(model, has_fail):
    from runtime_launch.adapter import InertSession
    from runtime_v1.context import InertDispatchMarker

    ordered = data.frozen_data("ordered103.json")
    session = InertSession(
        model["context"],
        ordered=ordered,
        manifest_sha256=model["m"].sha256,
        grant_sha256=model["g"].sha256,
    )
    session.validate_collection(ordered)
    for slot in model["manifest"]["slots"]:
        model["state"]["slot"] = slot
        relation = data.original_relation(model["manifest"], slot)
        call = data.original_call(model["manifest"], slot, relation)
        result = (
            None if slot["kind"] == "symlink" else CompletedProcess(call["args"][0], 0, b"", b"")
        )
        returned = session.handle(
            slot["nodeid"], call, InertDispatchMarker((data.expected_event(call),), result)
        )
        assert returned is result
        assert model["context"].pending_action is None
    for node in reversed(ordered):
        session.record_result(node, "FAIL" if has_fail and node == ordered[0] else "PASS")
    result = session.complete()
    assert list(result["results"]) == ordered
    assert result["all_passed"] is (not has_fail)
    assert result["success"] is (not has_fail)
    assert result["full103_green"] is False
    assert result["actual_runtime_verified"] is False
    with pytest.raises(model["rm"].Denied):
        session.complete()


@pytest.mark.parametrize("arguments", [[], ["--activate"], ["--context", "caller-digest"]])
def test_command_entry_refuses_without_issuance(model, arguments, capsys):
    # No supplied context/trust/environment flag becomes root admission.
    from runtime_launch.entrypoint import main

    assert main(arguments) == 2
    output = capsys.readouterr().out
    import json

    result = json.loads(output)
    assert result["status"] == "REFUSED"
    assert result["test_bodies_executed"] == result["native_dispatches"] == 0
    assert result["full103_green"] is False


@pytest.mark.parametrize("event", ["os.remove", "socket.connect", "subprocess.Popen"])
def test_audit_router_failure_latches(model, event):
    from runtime_launch.audit import AuditRouter

    class Refuser:
        def audit(self, event, args):
            raise model["rm"].Denied("synthetic controlled-event refusal")

    router = AuditRouter(Refuser())
    with pytest.raises(model["rm"].Denied):
        router.audit(event, ())
    assert router.blocked
    with pytest.raises(model["rm"].Denied):
        router.audit("ordinary.data", ())
    with pytest.raises(model["module"].ActualTrustUnavailable):
        router.install()
