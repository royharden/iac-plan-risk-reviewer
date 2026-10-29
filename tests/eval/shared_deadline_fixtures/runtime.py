"""Per-case fake-only runtime; pytest MonkeyPatch restores all replacements."""
import os
import socket
import subprocess
import pytest


@pytest.fixture(autouse=True)
def deny_real_effects(monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError('real process/network/link/deletion forbidden in portable deadline tests')

    for name in ('Popen', 'run', 'call', 'check_call', 'check_output'):
        monkeypatch.setattr(subprocess, name, denied)
    for name in ('system', 'remove', 'unlink', 'rmdir', 'rename', 'replace', 'symlink', 'link',
                 'spawnl', 'spawnle', 'spawnlp', 'spawnlpe', 'spawnv', 'spawnve', 'spawnvp', 'spawnvpe'):
        if hasattr(os, name):
            monkeypatch.setattr(os, name, denied)
    for name in ('connect', 'connect_ex', 'bind', 'listen'):
        monkeypatch.setattr(socket.socket, name, denied)
