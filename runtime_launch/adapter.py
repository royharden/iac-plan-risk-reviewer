"""Composition with the public inert core; no native dispatch callbacks."""

from copy import deepcopy

from runtime_v1.context import InertContext, InertDispatchMarker
from runtime_v1.errors import Denied
from runtime_v1.runtime_manifest import exact_value, hex64, load_frozen_bindings


class InertSession:
    """One-use synchronous data session, never an operational capability.

    Failure permanently blocks the adapter as well as any core poison. Only the
    public outer handle owns observation and retained post-readback finalization.
    No private core state is read, cleared or changed.
    """

    def __init__(self, context, *, ordered, manifest_sha256, grant_sha256):
        self._blocked = True
        frozen = load_frozen_bindings()
        if type(context) is not InertContext:
            raise Denied("exact inert context required")
        if (type(ordered) is not list or not exact_value(ordered, frozen.ordered)
                or not hex64(manifest_sha256) or not hex64(grant_sha256)):
            context.stop_inert("adapter-input-failure")
            raise Denied("exact original103 and two pins required")
        context.require_exact(manifest_sha256, grant_sha256)
        self._context = context
        self._pins = (manifest_sha256, grant_sha256)
        self._ordered = tuple(ordered)
        self._results = {}
        self._finished = False
        self._blocked = False

    @property
    def blocked(self):
        return self._blocked

    def stop(self, cause=None):
        self._blocked = True
        self._context.stop_inert("adapter-input-failure", cause)

    def _require(self):
        if self._blocked or self._finished:
            raise Denied("session blocked or completed")
        self._context.require_exact(*self._pins)

    def validate_collection(self, nodeids):
        try:
            self._require()
            if type(nodeids) is not list or not exact_value(nodeids, list(self._ordered)):
                raise Denied("exact ordered103 collection required")
        except BaseException as exc:
            self.stop(exc)
            raise

    def handle(self, nodeid, call, marker):
        try:
            self._require()
            if (type(nodeid) is not str or nodeid not in self._ordered
                    or type(marker) is not InertDispatchMarker or callable(marker)):
                raise Denied("exact node and noncallable inert marker required")
            self._context.current_node = nodeid
            result = self._context.handle_inert(nodeid, call, marker)
            # Do not clear a pending action; successful public handle already
            # finalized it. Clearing current_node is a public binding operation.
            self._context.current_node = None
            return result
        except BaseException as exc:
            self.stop(exc)
            # Preserve the exact original exception/cause. No cleanup/retry.
            raise

    def record_result(self, nodeid, status):
        try:
            self._require()
            if (type(nodeid) is not str or nodeid not in self._ordered
                    or nodeid in self._results or type(status) is not str
                    or status not in ("PASS", "FAIL")):
                raise Denied("unique original node and exact PASS/FAIL required")
            self._context.record_result_inert(nodeid, status)
            self._results[nodeid] = status
        except BaseException as exc:
            self.stop(exc)
            raise

    def complete(self):
        try:
            self._require()
            if set(self._results) != set(self._ordered):
                raise Denied("all original103 results required")
            core = self._context.check_complete_inert()
            results = {node: self._results[node] for node in self._ordered}
            failed = [node for node, status in results.items() if status == "FAIL"]
            expected = {
                "synthetic": True, "actual_runtime_verified": False, "slots": 8,
                "results": results, "complete_data": True,
                "all_passed": not failed, "success": not failed, "failed": failed,
            }
            if not exact_value(core, expected) or list(core["results"]) != list(self._ordered):
                raise Denied("core completion differs from canonical result evidence")
            self._finished = True
            return deepcopy(dict(expected, full103_green=False))
        except BaseException as exc:
            self.stop(exc)
            raise
