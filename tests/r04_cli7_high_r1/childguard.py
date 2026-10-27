"""Cooperative audit policy. No claim of a hostile-native or OS sandbox.

Initial import is guarded by bootstrap. Every cleanup permission is finite and
requires the whole-journey activation gate in the supervisor and this module.
"""
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

REPORT = frozenset(("private.json", "private.html", "shareable.json", "shareable.html",
                    "run-manifest.json", "manifest.json", "manifest.sha256"))
SHARE = frozenset(("shareable.json", "shareable.html", "manifest.json", "manifest.sha256"))
MUTATIONS = frozenset(("os.mkdir", "os.remove", "os.rmdir", "os.rename"))
FORBIDDEN = frozenset(("os.symlink", "os.link", "os.system", "os.exec", "os.spawn",
                       "os.fork", "shutil.rmtree", "os.chdir", "os.putenv", "os.unsetenv"))
MAX_FILE = 64 * 1024 * 1024


def key(path):
    value = os.fspath(path)
    if not isinstance(value, str) or not os.path.isabs(value):
        raise RuntimeError("absolute ordinary path required")
    if ".." in value.replace("/", "\\").split("\\"):
        raise RuntimeError("parent path segment denied")
    value = os.path.abspath(value)
    if value.startswith(("\\\\", "\\?", "\\.")) or ":" in value[2:]:
        raise RuntimeError("UNC/device/alternate stream denied")
    return value.lower()


def within(path, root):
    return path == root or path.startswith(root + "\\")


def ordinary(path):
    """lstat each existing ancestor; never resolve through a link/junction."""
    path = Path(path)
    for item in reversed((path, *path.parents)):
        try:
            info = os.lstat(item)
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise RuntimeError("reparse ancestry denied")
        if item != path and not stat.S_ISDIR(info.st_mode):
            raise RuntimeError("non-directory ancestor")
    return key(path)


class Guard:
    def __init__(self, stream, config_path, role, call_id):
        self.stream = stream
        self.config = json.loads(Path(config_path).read_bytes())
        self.role, self.call_id = role, call_id
        self.root = ordinary(self.config["output"])
        self.cases_root = key(Path(self.root) / "cases")
        self.control = key(Path(self.root) / "control")
        self.evidence = key(Path(self.root) / "evidence")
        self.command = None if role == "worker" else self.config["calls"][call_id - 1]
        self.seq = 0
        self.archive_seq = 0
        self.internal = None
        self.created = set()
        self.read_identities = {}
        self.failed = False
        self.pins = {key(row["path"]): row for row in self.config["pins"]}
        self.import_dirs = {key(p) for p in self.config["import_dirs"]}

    def emit(self, data):
        data = {"role": self.role, "call": self.call_id, "sequence": self.seq, **data}
        self.seq += 1
        self.stream.write((json.dumps(data, ensure_ascii=True, sort_keys=True) + "\n").encode("ascii"))
        self.stream.flush()
        os.fsync(self.stream.fileno())  # failure propagates; never permit an effect afterward

    def internal_read(self, path):
        path = ordinary(path)
        previous = self.internal
        self.internal = ("read", path)
        try:
            with open(path, "rb") as source:
                value = source.read(MAX_FILE + 1)
            if len(value) > MAX_FILE:
                raise RuntimeError("preimage exceeds bounded receipt size")
            return value
        finally:
            self.internal = previous

    def preimage(self, path, archive=False):
        path = ordinary(path)
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            return {"path": path, "state": "ABSENT", "bytes": None, "sha256": None}
        if stat.S_ISDIR(info.st_mode):
            return {"path": path, "state": "DIRECTORY", "bytes": None, "sha256": None}
        if not stat.S_ISREG(info.st_mode):
            raise RuntimeError("ordinary file required")
        raw = self.internal_read(path)
        result = {"path": path, "state": "FILE", "bytes": len(raw),
                  "sha256": hashlib.sha256(raw).hexdigest()}
        if archive:
            self.archive_seq += 1
            dest = key(Path(self.evidence) / "preimages" /
                       f"{self.role}-{self.call_id:02d}-{self.archive_seq:06d}.bin")
            previous = self.internal
            self.internal = ("archive", dest)
            try:
                with open(dest, "xb") as sink:
                    sink.write(raw)
                    sink.flush()
                    os.fsync(sink.fileno())
            finally:
                self.internal = previous
            result["retained_bytes"] = dest
        return result

    def validate(self):
        if not (sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode):
            raise RuntimeError("isolation flags missing")
        expected_cache = self.config["cache_prefixes"]["worker" if self.role == "worker"
                                                       else f"cli-{self.call_id:02d}"]
        if key(sys.pycache_prefix) != key(expected_cache) or os.path.lexists(expected_cache):
            raise RuntimeError("cache prefix must be fresh and absent")
        if not self.config["whole_journey_admitted"]:
            raise RuntimeError("NOT_ADMITTED: final-marker replacement and payload rollback")
        if self.config["activation_status"] != "EXACT_INDEPENDENT_REVIEW_AND_INT_ACTIVATION_REQUIRED":
            raise RuntimeError("unrecognized activation template")
        for path in self.config["absent"]:
            if os.path.lexists(path):
                raise RuntimeError("required absence drift")
        self.rehash()
        self.emit({"event": "guard-ready", "hostname": "NOT_COLLECTED",
                   "sandbox": "cooperative pinned-code ordinary-exclusive-footprint only"})

    def rehash(self):
        for path, row in self.pins.items():
            raw = self.internal_read(path)
            if len(raw) != row["bytes"] or hashlib.sha256(raw).hexdigest() != row["sha256"]:
                raise RuntimeError("frozen input drift")

    def creation_class(self, path):
        # Worker creates only its original synthetic case fixture and protocol/receipts.
        if self.role == "worker":
            for case in self.config["cases"]:
                root = key(Path(self.cases_root) / case["case"])
                if path == root or path == key(Path(root) / "public-synthetic.json"):
                    return "synthetic-fixture"
            if path == key(Path(self.evidence) / "case-results.json") or any(
                    path == key(Path(self.control) / f"request-{number:02d}.{suffix}")
                    for number in range(1, 26) for suffix in ("json", "ready")):
                return "owned-protocol-or-evidence"
            return None
        case = self.command["case"]
        root = key(Path(self.cases_root) / case)
        target = key(Path(root) / ("private-report" if self.command["verb"] == "inspect" else "safe-export"))
        if self.command["verb"] not in ("inspect", "share"):
            return None
        names = REPORT if self.command["verb"] == "inspect" else SHARE
        if path in (target, key(Path(target) / ".pending")):
            return "new-report-directory"
        if any(path == key(Path(target) / part / name) for part in ("", ".pending") for name in names):
            return "new-final-payload" if Path(path).parent == Path(target) else "new-staging-payload"
        if path in (key(Path(target) / "export-state.json"), key(Path(target) / ".export-state.pending")):
            return "new-state-marker"
        return None

    def cleanup_class(self, path):
        if self.role != "cli" or self.command["verb"] not in ("inspect", "share"):
            return None
        root = key(Path(self.cases_root) / self.command["case"] /
                   ("private-report" if self.command["verb"] == "inspect" else "safe-export"))
        names = REPORT if self.command["verb"] == "inspect" else SHARE
        if path == key(Path(root) / ".pending") or any(
                path == key(Path(root) / ".pending" / name) for name in names):
            return "staging-only-admitted"
        if path == key(Path(root) / ".export-state.pending"):
            return "temporary-state-cleanup-PROPOSED"
        if any(path == key(Path(root) / name) for name in names):
            return "final-payload-rollback-PROPOSED"
        return None

    def audit(self, event, args):
        if self.failed:
            raise RuntimeError("receipt/policy failed; no further effects")
        writing = event == "open" and bool(args[2] & (os.O_WRONLY | os.O_RDWR | os.O_CREAT |
                                                      os.O_TRUNC | os.O_APPEND))
        if self.internal is not None:
            # Reentrancy permits exactly the one observer read/archive open, never all events.
            if event == "open" and isinstance(args[0], (str, bytes, os.PathLike)):
                kind, path = self.internal
                if key(args[0]) == path and ((kind == "read" and not writing) or
                        (kind == "archive" and writing and args[2] & os.O_EXCL)):
                    return
            if event in MUTATIONS or writing or event in FORBIDDEN or event.startswith(
                    ("socket.", "ctypes.", "winreg.", "subprocess.")):
                raise RuntimeError("observer reentrant effect denied")
            return
        try:
            denied = event in FORBIDDEN or event.startswith(("socket.", "ctypes.", "winreg.", "subprocess."))
            if event == "import" and args[0].split(".")[0] in (
                    "pytest", "_pytest", "colorama", "platform", "ctypes", "winreg"):
                denied = True
            if event == "open":
                if type(args[0]) is int:
                    # Original read_source_bytes uses os.open(path), then os.fdopen(fd).
                    # Preserve that route without monkeypatching either function. Bind
                    # the descriptor's ordinary identity to an earlier permitted path.
                    info = os.fstat(args[0])
                    identity = (info.st_dev, info.st_ino)
                    matched = self.read_identities.get(identity)
                    permitted = not writing and matched is not None and stat.S_ISREG(info.st_mode)
                    if permitted:
                        current = os.lstat(ordinary(matched))
                        permitted = identity == (current.st_dev, current.st_ino)
                    self.emit({"event": event, "kind": "FD_READ_ATTEMPT", "descriptor": args[0],
                               "bound_path": matched, "permitted": bool(permitted)})
                    denied |= not permitted
                elif not isinstance(args[0], (str, bytes, os.PathLike)):
                    denied = True
                else:
                    path = key(args[0])  # lexical admission BEFORE stat/open/preimage
                    if any(part.startswith((".env", ".credentials")) or part in
                           ("auth.json", "id_rsa", "id_ed25519") for part in Path(path).parts):
                        denied = True
                    if path.endswith((".pyc", ".pth")):
                        denied = True
                    if writing:
                        effect = self.creation_class(path)
                        if denied or effect is None:
                            self.emit({"event": event, "kind": "DENIED_BEFORE_PREIMAGE", "path": path})
                            raise RuntimeError("write outside owned declared footprint")
                        ordinary(path)
                        before = self.preimage(path, archive=True)
                        # Synthetic source append is the only worker overwrite from the unchanged body.
                        overwrite = self.role == "worker" and effect == "synthetic-fixture" and path in self.created
                        permitted = effect is not None and not denied and (
                            before["state"] == "ABSENT" or overwrite)
                        self.emit({"event": event, "kind": "ATTEMPT", "effect_class": effect,
                                   "preimages": [before], "permitted": permitted})
                        if not permitted:
                            raise RuntimeError("write not admitted")
                        self.created.add(path)  # attempted create; existence is checked again before cleanup
                    elif not (path in self.pins or within(path, self.root)):
                        denied = True
                    elif not denied:
                        ordinary(path)
                        info = os.lstat(path)
                        if stat.S_ISREG(info.st_mode):
                            self.read_identities[(info.st_dev, info.st_ino)] = path
            elif event in MUTATIONS:
                path = key(args[0])
                effect = self.creation_class(path) if event == "os.mkdir" else self.cleanup_class(path)
                if event != "os.rename" and effect is None:
                    self.emit({"event": event, "kind": "DENIED_BEFORE_PREIMAGE", "path": path})
                    raise RuntimeError("mutation outside owned declared footprint")
                if event == "os.rename":
                    destination = key(args[1])
                    if (self.creation_class(path) != "new-state-marker" or
                            self.creation_class(destination) != "new-state-marker" or
                            Path(path).name != ".export-state.pending" or
                            destination != key(Path(path).parent / "export-state.json")):
                        self.emit({"event": event, "kind": "DENIED_BEFORE_PREIMAGE", "path": path,
                                   "destination": destination})
                        raise RuntimeError("replacement outside owned marker pair")
                ordinary(path)
                before = self.preimage(path, archive=event != "os.mkdir")
                preimages = [before]
                permitted = False
                if event == "os.mkdir":
                    permitted = effect is not None and before["state"] == "ABSENT" and args[-1] in (-1, None)
                elif event in ("os.remove", "os.rmdir"):
                    # dir_fd rewriting is not part of the declared writer routes.
                    if args[-1] not in (-1, None):
                        raise RuntimeError("relative descriptor cleanup denied")
                    permitted = effect is not None and (path in self.created or before["state"] == "ABSENT")
                    if effect != "staging-only-admitted":
                        permitted &= self.config["whole_journey_admitted"]
                else:
                    destination = ordinary(args[1])
                    preimages.append(self.preimage(destination, archive=True))
                    permitted = (self.config["whole_journey_admitted"] and
                                 Path(path).name == ".export-state.pending" and path in self.created and
                                 destination == key(Path(path).parent / "export-state.json") and
                                 destination in self.created and before["state"] == "FILE" and
                                 preimages[1]["state"] == "FILE" and
                                 all(value in (-1, None) for value in args[2:]))
                    effect = "new-ABORTED-marker-replacement-PROPOSED"
                permitted &= not denied
                self.emit({"event": event, "kind": "ATTEMPT", "effect_class": effect,
                           "preimages": preimages, "permitted": bool(permitted)})
                if not permitted:
                    raise RuntimeError("mutation not admitted")
                if event == "os.mkdir":
                    self.created.add(path)
            elif event in ("os.listdir", "os.scandir"):
                path = ordinary(args[0])
                denied |= not (within(path, self.root) or path in self.import_dirs)
            if denied:
                self.emit({"event": event, "kind": "DENIED", "argument_type": type(args[0]).__name__ if args else None})
                raise RuntimeError("child effect denied")
        except BaseException:
            self.failed = True
            raise

    def inventory(self, path):
        root = ordinary(path)
        records = []
        if not os.path.lexists(root):
            return [{"path": root, "state": "ABSENT"}]
        for current, dirs, files in os.walk(root, followlinks=False):
            ordinary(current)
            for name in sorted(dirs + files):
                records.append(self.preimage(Path(current) / name))
        return records

    def origins(self):
        result = []
        for name, module in tuple(sys.modules.items()):
            path = getattr(module, "__file__", None)
            if path is not None:
                canonical = key(path)
                if canonical not in self.pins:
                    raise RuntimeError("unqualified module origin")
                result.append({"module": name, "path": canonical, "sha256": self.pins[canonical]["sha256"]})
        return result

    def finish(self, code):
        self.rehash()
        self.emit({"event": "process-completed", "exit": code, "origins": self.origins(),
                   "observed_output": self.inventory(Path(self.cases_root))})

    def fail(self, kind):
        # A failed receipt stream cannot be repaired or replaced. Stderr/native exit survives.
        if not self.failed:
            self.emit({"event": "process-error", "error_type": kind, "outcome": "FAILED_NOT_PASS"})
