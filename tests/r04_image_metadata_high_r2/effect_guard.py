"""Deny and retain unexpected Python-visible effects; static review also required.

Audit hooks cannot observe every OS metadata syscall. This is an additional
bounded denial control, never a security sandbox or native effect qualification.
"""
import json
import os
from pathlib import Path
import sys


class Guard:
    def __init__(self, output, source, files):
        self.output, self.source = output, source
        self.files = set(files) | {source}
        self.python = Path(sys.base_prefix)
        self.absent_cache = Path(sys.pycache_prefix) if sys.pycache_prefix else None
        self.denials = []
        self.logging = False

    def within(self, path, root):
        return path == root or root in path.parents

    def deny(self, event, args):
        record = {"event": event, "arguments": repr(args)[:1024]}
        self.denials.append(record)
        self.logging = True
        try:
            with (self.output / "denied-effects.jsonl").open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(record, sort_keys=True) + "\n")
                stream.flush()
        finally:
            self.logging = False
        raise RuntimeError("denied effect: " + event)

    def hook(self, event, args):
        if self.logging:
            return
        if event.startswith(("subprocess.", "socket.", "ctypes.", "winreg.")) or event in {
            "os.remove", "os.rmdir", "os.rename", "os.link", "os.symlink", "os.system",
            "os.startfile", "os.truncate", "os.chmod", "os.chown", "os.utime",
            "os.exec", "os.fork", "os.spawn", "os.kill", "shutil.rmtree",
        }:
            self.deny(event, args)
        if event == "open":
            name, mode, flags = args
            if isinstance(name, int):
                self.deny(event, args)
            path = Path(os.fsdecode(name)).absolute()
            writing = (type(mode) is str and any(c in mode for c in "wax+")) or bool(
                flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))
            if writing:
                if not self.within(path, self.output):
                    self.deny(event, args)
            elif path not in self.files and not self.within(path, self.python) and not self.within(path, self.output) and not (self.absent_cache is not None and self.within(path, self.absent_cache)):
                self.deny(event, args)
        elif event in ("os.listdir", "os.scandir"):
            path = Path(os.fsdecode(args[0])).absolute()
            if not self.within(path, self.python):
                self.deny(event, args)
        elif event == "os.mkdir":
            path = Path(os.fsdecode(args[0])).absolute()
            if not self.within(path, self.output):
                self.deny(event, args)
