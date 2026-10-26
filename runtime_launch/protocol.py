"""Dormant original Protocol successor; never issued under current admission.

The flow follows frozen0105 pre_effect.Protocol.handle, with runtime-v1 parsing
and composition, rather than changing construction-only metadata into authority.
No original action, filesystem observer or receipt writer is run at import.
"""

import base64
from hashlib import sha256
import os
from pathlib import Path
import re
import subprocess

from runtime_v1.audit_window import render_call
from runtime_v1.errors import ActualTrustUnavailable, Denied, Unknown
from runtime_v1.guarded_context import GuardedContext
from runtime_v1.metadata_backend import LocalMetadataBackend, ordinary_chain
from runtime_v1.runtime_manifest import (
    canonical, digest, exact_value, lexical, load_frozen_bindings, parse_manifest,
)

_CAP = 65_536
_SYMLINK = os.symlink
_RUN = subprocess.run


def _outcome(slot, call, result, error):
    if error is not None:
        return {"error_type": type(error).__name__, "error_message": str(error)}
    if slot["kind"] == "junction":
        if (type(result) is not subprocess.CompletedProcess
                or type(result.returncode) is not int
                or type(result.stdout) is not bytes or type(result.stderr) is not bytes
                or not exact_value(result.args, call["args"][0])):
            raise Unknown("original junction result differs")
        return {"returncode": result.returncode,
                "stdout_base64": base64.b64encode(result.stdout).decode("ascii"),
                "stderr_base64": base64.b64encode(result.stderr).decode("ascii")}
    if result is not None:
        raise Unknown("original symlink result differs")
    return {"return_value": None}


class OriginalProtocol:
    """Operational objects cannot be supplied by the inert test seam.

    Only the independently issued exact guarded context can reach real IO.
    Its factory currently refuses before IO. Cooperative filesystem checks do
    not establish adversarial isolation, OS qualification or physical durability.
    """

    def __init__(self, context):
        if type(context) is not GuardedContext:
            raise ActualTrustUnavailable("independently issued guarded context required")
        try:
            self._initialize(context)
        except BaseException as exc:
            context.stop_original("protocol-failure", exc)
            raise

    def _initialize(self, context):
        context.require_exact()
        self.context = context
        self.manifest = parse_manifest(
            context.manifest_raw,
            expected_harness_pins=self._harness_pins(context.manifest_raw),
            frozen=load_frozen_bindings(),
        )
        context.require_exact(self.manifest.sha256, context.grant_sha256)
        self._pins = (self.manifest.sha256, context.grant_sha256)
        self._backend = LocalMetadataBackend()
        self._receipts = Path(self.manifest.document["runroot"]) / "live-action-receipts"
        # Installation is a separate independently admitted exclusive step.
        ordinary_chain(self._backend, str(self._receipts))
        self.used = set()
        self.blocked = False

    @staticmethod
    def _harness_pins(raw):
        from runtime_v1.runtime_manifest import decode_canonical
        return decode_canonical(raw)["harness_pins"]

    def require_exact(self):
        if self.blocked:
            raise Denied("original protocol permanently stopped")
        self.context.require_exact(*self._pins)

    def stop(self, reason="protocol-failure", cause=None):
        self.blocked = True
        self.context.stop_original(reason, cause)

    def _relationship(self, slot, call):
        if slot["kind"] == "symlink":
            src, dst = call["args"]
        else:
            command = call["args"][0][-1]
            # Same bounded original command grammar; no shell/general commands.
            match = re.fullmatch(
                r"\$ErrorActionPreference='Stop'; \$null=New-Item -ItemType Junction -Path '([^']*)' -Target '([^']*)'",
                command,
            )
            if match is None:
                raise Denied("original junction command required")
            dst, src = match.groups()
        target, link = lexical(src), lexical(dst)
        root = link.parent
        prefix = lexical(self.manifest.document["snapshot"]) / ".agent-work" / "RV2-0040-junction-regression"
        if (root.parent != prefix or target != root / "target" or link != root / "linked"
                or re.fullmatch(re.escape(slot["kind"] + "-" + slot["position"] + "-")
                                + r"[0-9a-f]{32}", root.name) is None):
            raise Denied("original owned UUID relationship required")
        physical = target if slot["position"] == "direct" else target / "ordinary-child"
        logical = link if slot["position"] == "direct" else link / "ordinary-child"
        checked = []
        for path in (root, target, physical):
            ordinary_chain(self._backend, str(path))
            checked.append(str(path))
        metadata = self._backend.metadata(str(target))
        if self._backend.metadata(str(link)).kind != "absent":
            raise Denied("original destination must be absent")
        relation = {"fixture_root": str(root), "target": str(target), "link": str(link),
                    "physical": str(physical), "logical": str(logical),
                    "checked_ordinary_ancestors": checked}
        augmented = dict(relation, ordinary=True, target_identity=metadata.identity, link_absent=True)
        if not exact_value(call, render_call(self.manifest, slot, augmented)):
            raise Denied("original raw call differs")
        return relation

    def _write(self, path, value):
        raw = canonical(value)
        if len(raw) > _CAP:
            raise Unknown("receipt exceeds finite cap")
        ordinary_chain(self._backend, str(self._receipts))
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags, 0o600)
        with os.fdopen(fd, "wb", buffering=0) as stream:
            offset = 0
            while offset < len(raw):
                written = stream.write(raw[offset:])
                if type(written) is not int or not 0 < written <= len(raw) - offset:
                    raise Unknown("receipt write count unknown")
                offset += written
            stream.flush()
            os.fsync(stream.fileno())
        if self._backend.read_file(str(path), _CAP) != raw:
            raise Unknown("receipt independent readback differs")
        return sha256(raw).hexdigest()

    def handle(self, nodeid, event, call, token):
        error = None
        result = None
        stage = "protocol-failure"
        try:
            self.require_exact()
            slots = [s for s in self.manifest.document["slots"]
                     if s["nodeid"] == nodeid and s["event"] == event]
            if len(slots) != 1:
                raise Denied("exact original setup slot required")
            slot = slots[0]
            if (slot["slot"] in self.used or type(token) is not str
                    or self.context.token(slot) != token):
                raise Denied("replayed or unbound original token")
            relation = self._relationship(slot, call)
            m = self.manifest.document
            pre = {"schema": "legacy103-action-pre-r2", "slot": slot, "nodeid": nodeid,
                   "event": event, "nonce_sha256": digest(token.encode("utf-8")),
                   "manifest_sha256": self.manifest.sha256,
                   "external_grant_sha256": self.context.grant_sha256,
                   "source_commit": m["source_commit"], "source_tree": m["source_tree"],
                   "harness_pins": m["harness_pins"], "relation": relation,
                   "actual_call": call, "powershell": m["powershell"],
                   "status": "CONSUMED_BEFORE_EFFECT_NOT_SUCCESS"}
            path = self._receipts / ("slot-" + slot["slot"] + "-pre.json")
            stage = "pre-receipt-failure"
            pre_hash = self._write(path, pre)
            stage = "protocol-failure"
            self.used.add(slot["slot"])
            with self.context.effect_window(slot, call, pre_hash):
                # Catch original errors inside the window so post-window
                # observation can retain the original outcome before poisoning.
                try:
                    api = _SYMLINK if slot["kind"] == "symlink" else _RUN
                    result = api(*call["args"], **call["kwargs"])
                except BaseException as exc:
                    error = exc
            observed = self.context.observe_original(relation, result, error)
            if (type(observed) is not dict or observed.get("synthetic") is not False
                    or observed.get("known") is not True):
                raise Unknown("qualified original observation unavailable")
            if self._backend.read_file(str(path), _CAP) != canonical(pre):
                raise Unknown("retained pre changed after original action")
            post = {"schema": "legacy103-action-post-r2", "pre_receipt_sha256": pre_hash,
                    "slot": slot["slot"], "result": _outcome(slot, call, result, error),
                    "observation": observed,
                    "status": "ORIGINAL_API_ERROR_RECORDED" if error is not None else "ORIGINAL_API_RETURN_RECORDED"}
            stage = "post-receipt-failure"
            self._write(self._receipts / ("slot-" + slot["slot"] + "-post.json"), post)
            stage = "protocol-failure"
            try:
                self.context.require_exact(*self._pins)
            except BaseException as exc:
                if error is not None and exc is error:
                    raise
                raise Unknown("retained post finalization unknown") from (error if error is not None else exc)
        except BaseException as exc:
            self.stop(stage, error if error is not None else exc)
            if error is not None and exc is not error:
                raise Unknown("original action outcome unknown; later actions stopped") from error
            raise
        if error is not None:
            self.stop(cause=error)
            raise error
        if observed.get("actual_link_verified") is not True:
            self.stop()
            raise Unknown("original effect not verified")
        return result
