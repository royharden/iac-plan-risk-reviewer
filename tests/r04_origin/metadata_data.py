"""Inert public observation dependency; no real stat/open/readlink calls."""

import stat
from copy import deepcopy
from types import SimpleNamespace

FILE = r"C:\INERT-ORIGIN-DATA-RV3\public.bin"
PARENT = r"C:\INERT-ORIGIN-DATA-RV3"
TARGET = r"C:\INERT-ORIGIN-DATA-RV3\target"


def snapshot(*, mode=stat.S_IFREG | 0o600, size=5, dev=1, ino=2, attrs=0, tag=0, mtime=123):
    return SimpleNamespace(
        st_dev=dev,
        st_ino=ino,
        st_mode=mode,
        st_size=size,
        st_mtime_ns=mtime,
        st_file_attributes=attrs,
        st_reparse_tag=tag,
    )


class Observations:
    def __init__(self, raw=b"abcde", *, initial=None):
        self.raw = raw
        self.initial = initial or snapshot(size=len(raw))
        self.after_path = None
        self.after_fd = None
        self.parent_after = None
        self.initial_error = None
        self.after_error = None
        self.read_done = False
        self.calls = []
        self.targets = [TARGET, TARGET]
        self.target_index = 0

    def lstat(self, path):
        self.calls.append(("lstat", path))
        if path == FILE:
            error = self.after_error if self.read_done else self.initial_error
            if error is not None:
                raise error
            return deepcopy(
                self.after_path if self.read_done and self.after_path is not None else self.initial
            )
        if path == PARENT and self.read_done and self.parent_after is not None:
            return deepcopy(self.parent_after)
        return snapshot(mode=stat.S_IFDIR | 0o700, size=0, ino=3)

    def readlink(self, path):
        self.calls.append(("readlink", path))
        assert path == FILE
        result = self.targets[min(self.target_index, len(self.targets) - 1)]
        self.target_index += 1
        return result

    def open_read(self, path):
        self.calls.append(("open_read", path))
        assert path == FILE
        return Stream(self)

    def fstat(self, stream):
        self.calls.append(("fstat", type(stream).__name__))
        assert type(stream) is Stream
        return deepcopy(
            self.after_fd if self.read_done and self.after_fd is not None else self.initial
        )


class Stream:
    def __init__(self, observations):
        self.observations = observations

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self, count):
        self.observations.calls.append(("read", count))
        self.observations.read_done = True
        return self.observations.raw
