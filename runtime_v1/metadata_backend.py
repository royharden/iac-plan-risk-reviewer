"""Dormant local no-follow metadata adapter. Not OS-qualified; never auto-run."""
from dataclasses import dataclass
from hashlib import sha256
import os
import stat

from .errors import Unknown
from .runtime_manifest import lexical, need


@dataclass(frozen=True)
class Metadata:
    path: str
    kind: str
    identity: str
    link_target: str | None = None


def ordinary_chain(backend, path, *, include_self=True):
    path = lexical(path)
    chain = [path, *path.parents] if include_self else list(path.parents)
    for item in reversed(chain):
        row = backend.metadata(str(item))
        need(type(row) is Metadata and row.path == str(item) and row.kind == 'directory'
             and type(row.identity) is str and bool(row.identity) and row.link_target is None, 'ordinary ancestor required')


class LocalMetadataBackend:
    """Cooperative stable filesystem checks; no SID/ACL or hostile-writer claim."""

    def _stat(self, path):
        lexical(path)
        if os.name != 'nt':
            raise Unknown('Windows representation is unavailable')
        return os.lstat(path)

    @staticmethod
    def _identity(value):
        if type(value.st_dev) is not int or type(value.st_ino) is not int or not value.st_dev or not value.st_ino:
            raise Unknown('stable device/inode identity unavailable')
        return f'{value.st_dev}:{value.st_ino}'

    @staticmethod
    def _ordinary(value):
        return not (getattr(value, 'st_file_attributes', 0) & 0x400) and not stat.S_ISLNK(value.st_mode)

    def metadata(self, path):
        try:
            before = self._stat(path)
        except FileNotFoundError:
            return Metadata(path, 'absent', 'absent')
        try:
            identity = self._identity(before)
            target = None
            if not self._ordinary(before):
                tag = getattr(before, 'st_reparse_tag', None)
                junction = getattr(stat, 'IO_REPARSE_TAG_MOUNT_POINT', None)
                symlink = getattr(stat, 'IO_REPARSE_TAG_SYMLINK', None)
                if junction is not None and tag == junction:
                    kind = 'junction'
                elif symlink is not None and tag == symlink:
                    kind = 'symlink'
                else:
                    raise Unknown('unsupported/unqualified reparse representation')
                target = os.readlink(path)
                # Windows readlink may return the local extended-length spelling.
                if target.startswith('\\\\?\\') and not target.startswith('\\\\?\\UNC\\'):
                    target = target[4:]
                lexical(target)
            elif stat.S_ISDIR(before.st_mode):
                kind = 'directory'
            elif stat.S_ISREG(before.st_mode):
                kind = 'file'
            else:
                raise Unknown('unsupported metadata kind')
            after = self._stat(path)
            if (self._identity(after), after.st_mode, getattr(after, 'st_reparse_tag', None)) != (identity, before.st_mode, getattr(before, 'st_reparse_tag', None)):
                raise Unknown('metadata changed during observation')
            return Metadata(path, kind, identity, target)
        except Unknown:
            raise
        except BaseException as exc:
            raise Unknown('bounded no-follow metadata unavailable') from exc

    def read_file(self, path, cap):
        need(type(cap) is int and 0 < cap <= 8 * 1024 * 1024, 'bounded file cap')
        ordinary_chain(self, path, include_self=False)
        before = self._stat(path)
        need(self._ordinary(before) and stat.S_ISREG(before.st_mode) and before.st_size <= cap, 'ordinary bounded file required')
        before_id = self._identity(before)
        flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0)
        # No actual file read is performed merely by importing/constructing this adapter.
        with os.fdopen(os.open(path, flags), 'rb') as stream:
            opened = os.fstat(stream.fileno())
            need(self._ordinary(opened) and self._identity(opened) == before_id and opened.st_size == before.st_size, 'opened file identity differs')
            raw = stream.read(cap + 1)
            final_fd = os.fstat(stream.fileno())
        after = self._stat(path)
        need(len(raw) == before.st_size <= cap and self._ordinary(after)
             and self._identity(after) == before_id == self._identity(final_fd)
             and after.st_size == final_fd.st_size == before.st_size
             and after.st_mtime_ns == final_fd.st_mtime_ns == before.st_mtime_ns, 'file changed during bounded read')
        return raw

    def file_digest(self, path, size):
        need(type(size) is int and 0 <= size <= 8 * 1024 * 1024, 'exact bounded file size')
        raw = self.read_file(path, max(1, size))
        need(len(raw) == size, 'exact file size differs')
        return sha256(raw).hexdigest()
