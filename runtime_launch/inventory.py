"""Read-only inventory of the pinned historical real-clock reporter.

This does not execute tests, reinterpret results, or change the frozen oracle.
"""

from hashlib import sha256
import json
from pathlib import Path
from xml.etree import ElementTree

_PINS = {
    "result.xml": "50ca7cbd59fb51806dc99ee026482c7a0e000cd0656e76dbb1e53148148a63fc",
    "execution.json": "9bca26ef2e4f987edfdf6424fffeaa2787e167f147b9a4fe7474dff503705ac9",
    "collected.json": "1d7eab290e804bcdb15ca3467e09e5952d72db6cc64bfb115abecc1214ad9df3",
}


def historical_failures(directory):
    """Require exact reporter bytes before deriving counts and ordered IDs."""
    root = Path(directory)
    data = {}
    for name, expected in _PINS.items():
        raw = (root / name).read_bytes()
        if len(raw) > 2_000_000 or sha256(raw).hexdigest() != expected:
            raise ValueError("historical reporter pin differs")
        data[name] = raw
    xml = ElementTree.fromstring(data["result.xml"])
    cases = list(xml.iter("testcase"))
    ordered = json.loads(data["collected.json"])
    execution = json.loads(data["execution.json"])
    if (type(ordered) is not list or len(ordered) != 103
            or len(set(ordered)) != 103 or len(cases) != 103):
        raise ValueError("historical original103 inventory differs")
    rows = []
    seen = set()
    failed = []
    failure_kinds = {}
    skipped = errors = 0
    for case in cases:
        node = case.attrib["classname"].replace(".", "/") + ".py::" + case.attrib["name"]
        if node not in ordered or node in seen:
            raise ValueError("historical reporter ID differs")
        seen.add(node)
        if case.find("error") is not None:
            errors += 1
        elif case.find("skipped") is not None:
            skipped += 1
        elif case.find("failure") is not None:
            failed.append(node)
            text = case.find("failure").text or ""
            if 'TimeoutError: scanner attempt deadline exhausted' in text:
                failure_kinds[node] = "approval-time original real-clock deadline exhausted"
            elif 'assert 0 == 1' in text and 'len(calls)' in text:
                failure_kinds[node] = "expected fake-Popen call absent (0 versus1)"
            else:
                raise ValueError("historical failure shape differs")
    if len(failed) != 12 or errors or skipped or set(ordered) != seen:
        raise ValueError("historical91/12 reporter differs")
    for node in ordered:
        if node in failed:
            rows.append({
                "nodeid": node, "historical_status": "FAIL",
                "classification": failure_kinds[node],
                "effect_prerequisites": (
                    "retained ordinary UUID workspace mkdir, pinned synthetic files, fake Popen, original0.1s budget"
                    if "test_ordinary_workspace_" in node else
                    "ordinary retained tmp_path, pinned synthetic files, fake Popen, original0.1s budget"
                ),
                "link_or_junction_fixture": False,
                "safe_next_step": "review exact body/fixtures; fresh real-clock execution only after independent effect preflight",
                "waived": False,
            })
    return {
        "kind": "historical-real-clock-failure-inventory",
        "source": "f1972071188a8cc5f3a2a9ae04086de87be07f0f (historical report, not924 rerun)",
        "reporter_pins": dict(_PINS), "execution": execution,
        "collected": 103, "passed": 91, "failed": 12, "errors": 0, "skipped": 0,
        "failures": rows, "new_test_bodies_executed": 0,
        "failure_shapes": {"approval_deadline_exhausted": 10, "fake_popen_absent": 2},
        "legacy103_green": False,
        "limits": "Inventory only. No assertion/clock/UUID change, no waiver, native activation or new execution.",
    }
