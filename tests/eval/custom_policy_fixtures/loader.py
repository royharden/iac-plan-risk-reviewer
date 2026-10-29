"""Load validated exact candidate bytes, bypassing all import bytecode caches.

Identity selection is supplied by the caller; this module does not approve it.
Path/hash rechecks detect ordinary mutation, not adversarial atomic races.
"""
import hashlib
import os
from pathlib import Path
import re
import stat
import sys
import types
import uuid


def ordinary_absolute(value, *, file=True, absent=False):
    path = Path(value)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('absolute path without parent traversal required')
    for part in reversed((path, *path.parents)):
        if part == path and absent:
            if os.path.lexists(part):
                raise ValueError('output must be absent and exclusive')
            continue
        info = part.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 1024:
            raise ValueError('symlink/reparse path rejected')
        want_file = part == path and file
        if not (stat.S_ISREG(info.st_mode) if want_file else stat.S_ISDIR(info.st_mode)):
            raise ValueError('ordinary file/directory required')
    return path


def validated_bytes(candidate, expected_sha256):
    if not isinstance(expected_sha256, str) or not re.fullmatch('[0-9a-f]{64}', expected_sha256):
        raise ValueError('external lowercase SHA256 required')
    path = ordinary_absolute(candidate)
    before = path.stat()
    with path.open('rb') as stream:
        opened = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode) or not os.path.samestat(before, opened):
            raise ValueError('candidate changed while opening')
        data = stream.read()
        after = os.fstat(stream.fileno())
    ordinary_absolute(str(path))
    current = path.stat()
    identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns)
    if identity(before) != identity(after) or identity(after) != identity(current):
        raise ValueError('candidate mutation detected')
    if hashlib.sha256(data).hexdigest() != expected_sha256:
        raise ValueError('candidate SHA256 mismatch')
    return path, data


def load_candidate(candidate, expected_sha256):
    path, data = validated_bytes(candidate, expected_sha256)
    name = 'rv0077_candidate_' + uuid.uuid4().hex
    module = types.ModuleType(name)
    module.__file__ = str(path)
    module.__package__ = ''
    sys.modules[name] = module
    try:
        exec(compile(data, str(path), 'exec', dont_inherit=True), module.__dict__)
        recheck_candidate(module, str(path), expected_sha256)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


def recheck_candidate(module, candidate, expected_sha256):
    path, data = validated_bytes(candidate, expected_sha256)
    if module.__file__ != str(path) or sys.modules.get(module.__name__) is not module:
        raise ValueError('import origin/module identity mismatch')
    return {'candidate_path': str(path), 'expected_sha256': expected_sha256,
            'actual_sha256': hashlib.sha256(data).hexdigest(),
            'module_file': module.__file__, 'module_name': module.__name__,
            'loader': 'compile validated exact bytes; no pyc/cache',
            'mutation_limit': 'pre/open/post/import/teardown rechecks are not atomic; frozen ordinary candidate required'}


def load_policy():
    """Select the pure policy in this checkout; never import Checkov callbacks."""
    candidate = Path(__file__).parents[3] / 'policies' / 'checkov-custom' / 'm4_policy.py'
    path = ordinary_absolute(str(candidate))
    expected = hashlib.sha256(path.read_bytes()).hexdigest()
    return load_candidate(str(path), expected), path, expected
