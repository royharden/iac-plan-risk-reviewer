"""Dormant original pytest adapter. Installation is separately held.

There is no clock, UUID, predicate, timeout, fixture or test-body replacement.
Construction checks must not instantiate a real guarded context or invoke these
hooks against original tests. InertPlugin is the separate nonexecuting seam.
"""

import os
from pathlib import Path
import subprocess
import time

from runtime_v1.audit_window import ORIGINAL_CLOCK
from runtime_v1.errors import ActualTrustUnavailable, Denied
from runtime_v1.runtime_manifest import exact_value, load_frozen_bindings
from .protocol import OriginalProtocol


class OriginalPlugin:
    def __init__(self, protocol):
        if type(protocol) is not OriginalProtocol:
            raise ActualTrustUnavailable("original issued protocol required")
        protocol.require_exact()
        self._protocol = protocol
        self._ordered = load_frozen_bindings().ordered
        self._root = Path(protocol.manifest.document["snapshot"])
        self._reports = {}
        self._restore = None
        self.result = None

    def install(self):
        raise ActualTrustUnavailable("original plugin installation/preflight not admitted")

    def _deny(self, message):
        self._protocol.stop()
        raise Denied(message)

    def pytest_configure(self, config):
        self._protocol.require_exact()
        if (str(config.rootpath) != str(self._root) or config.option.capture != "no"
                or Path.cwd() != self._root or time.monotonic is not ORIGINAL_CLOCK):
            self._deny("original runtime root/capture/clock tuple differs")

    def pytest_collection_finish(self, session):
        self._protocol.require_exact()
        if not exact_value([item.nodeid for item in session.items], self._ordered):
            self._deny("exact ordered103 selection required")

    def pytest_runtest_setup(self, item):
        protocol = self._protocol
        protocol.require_exact()
        if item.nodeid not in self._ordered or self._restore is not None:
            self._deny("unknown node or prior setup still active")
        context = protocol.context
        context.current_node = item.nodeid
        slots = [s for s in protocol.manifest.document["slots"] if s["nodeid"] == item.nodeid]
        if not slots:
            return
        slot = slots[0]
        token = context.token(slot)
        if time.monotonic is not ORIGINAL_CLOCK:
            self._deny("original setup clock differs")
        if slot["kind"] == "symlink":
            original = os.symlink

            def wrapped(src, dst, target_is_directory=False, *, dir_fd=None):
                if dir_fd is not None:
                    self._deny("original symlink has no dir_fd")
                call = {"api": "os.symlink", "args": [os.fspath(src), os.fspath(dst)],
                        "kwargs": {"target_is_directory": target_is_directory}}
                return protocol.handle(item.nodeid, "os.symlink", call, token)

            self._restore = (os, "symlink", original)
            os.symlink = wrapped
        else:
            original = subprocess.run

            def wrapped(*args, **kwargs):
                call = {"api": "subprocess.run", "args": list(args), "kwargs": kwargs,
                        "inherited_cwd": str(Path.cwd()), "stdin": "original-default-inheritance"}
                return protocol.handle(item.nodeid, "subprocess.run", call, token)

            self._restore = (subprocess, "run", original)
            subprocess.run = wrapped

    def pytest_runtest_teardown(self, item, nextitem):
        if self._restore is not None:
            module, name, original = self._restore
            setattr(module, name, original)
            self._restore = None
        # A poisoned context may refuse this public operation. It is never
        # repaired by clearing a pending action or changing private state.
        self._protocol.context.current_node = None
        if time.monotonic is not ORIGINAL_CLOCK:
            self._deny("original real clock changed")

    def pytest_runtest_logreport(self, report):
        if (report.nodeid not in self._ordered or report.when not in ("setup", "call", "teardown")
                or report.outcome not in ("passed", "failed", "skipped")):
            self._deny("unknown original result record")
        phases = self._reports.setdefault(report.nodeid, {})
        if report.when in phases:
            self._deny("duplicate original result phase")
        phases[report.when] = report.outcome

    def pytest_sessionfinish(self, session, exitstatus):
        self._protocol.require_exact()
        rows = []
        if set(self._reports) != set(self._ordered):
            self._deny("missing original103 results")
        for node in self._ordered:
            phases = self._reports[node]
            if "failed" in phases.values():
                status = "FAIL"
            elif (set(phases) == {"setup", "call", "teardown"}
                    and all(value == "passed" for value in phases.values())):
                status = "PASS"
            else:
                self._deny("skipped/incomplete original result cannot be green")
            rows.append({"nodeid": node, "status": status})
        core = self._protocol.context.check_complete(rows)
        self.result = dict(core, native_exit=int(exitstatus), full103_green=False)
        if int(exitstatus) != 0 and core["success"]:
            self.result["success"] = False
            self.result["all_passed"] = False


# Equivalent to pytest.hookimpl markers without importing pytest on an inert
# module import. No hooks are registered here.
OriginalPlugin.pytest_runtest_setup.pytest_impl = {"tryfirst": True}
OriginalPlugin.pytest_runtest_teardown.pytest_impl = {"trylast": True}
