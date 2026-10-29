"""Pinned receiver test runner, isolated worker, 180s real parent watchdog.

Run with -I -B. Required flags bind immutable source directory and both byte hashes.
Outputs use exclusive creation beneath a fresh directory; never delete or reuse.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--receiver-sha", required=True)
    parser.add_argument("--wire-sha", required=True)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--worker", action="store_true")
    args = parser.parse_args()
    pins = {"storage_receiver": args.receiver_sha, "storage_wire": args.wire_sha}
    source = args.source.resolve(strict=True)
    for name, expected in pins.items():
        data = (source / (name + ".py")).read_bytes()
        assert hashlib.sha256(data).hexdigest() == expected
        tree = ast.parse(data)
        forbidden = {"subprocess", "socket", "ctypes", "shutil", "requests", "http", "urllib"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert not any(alias.name.split(".")[0] in forbidden for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                assert (node.module or "").split(".")[0] not in forbidden
    out = args.out.absolute()
    if not args.worker:
        out.mkdir(exist_ok=False)
        env = {key: value for key, value in os.environ.items()
               if key not in ("PYTHONPATH", "PYTHONSTARTUP", "PYTEST_ADDOPTS", "PYTEST_PLUGINS")}
        env.update(PYTEST_DISABLE_PLUGIN_AUTOLOAD="1", PYTHONDONTWRITEBYTECODE="1",
                   RV4_SOURCE_ROOT=str(source), RV4_SOURCE_PINS=json.dumps(pins),
                   RV4_OUTPUT_ROOT=str(out))
        command = [sys.executable, "-I", "-B", str(Path(__file__).resolve()),
                   "--source", str(source), "--receiver-sha", args.receiver_sha,
                   "--wire-sha", args.wire_sha, "--out", str(out), "--worker"]
        started = time.monotonic()
        timeout = False
        try:
            result = subprocess.run(command, env=env, capture_output=True, timeout=180, check=False)
            stdout, stderr, code = result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired as exc:
            stdout, stderr, code, timeout = exc.stdout or b"", exc.stderr or b"", 124, True
        for filename, raw in (("stdout.txt", stdout), ("stderr.txt", stderr)):
            with (out / filename).open("xb") as stream: stream.write(raw)
        unchanged = all(hashlib.sha256((source / (name + ".py")).read_bytes()).hexdigest() == sha
                        for name, sha in pins.items())
        record = {"command": command, "source": str(source), "pins": pins,
                  "exit_code": code, "watchdog_fired": timeout,
                  "elapsed_seconds": time.monotonic() - started, "source_unchanged": unchanged,
                  "test_pins": {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                for p in HERE.iterdir() if p.is_file()},
                  "product_acceptance": False}
        with (out / "execution.json").open("x", encoding="utf-8") as stream:
            json.dump(record, stream, indent=2)
        print(json.dumps(record, indent=2))
        return code if unchanged else 125

    import pytest
    import _pytest.junitxml
    import types
    # JUnit's platform.node() may spawn cmd.exe on Windows. Hostname is unrelated
    # to the oracle: explicitly omit it without weakening candidate effect guards.
    _pytest.junitxml.platform = types.SimpleNamespace(node=lambda: "not-collected")
    # Python-level effect guard, not hostile-code isolation. Candidate closure was
    # statically inspected first. Only fresh owned output may be written.
    denied = []
    def audit(event, values):
        if event in {"os.remove", "os.rmdir", "os.rename", "os.link", "os.symlink",
                     "subprocess.Popen", "os.system", "socket.connect", "socket.bind"}:
            denied.append(event)
            raise RuntimeError("RV4 forbidden effect: " + event)
        if event == "open" and isinstance(values[0], (str, bytes, os.PathLike)):
            path = Path(os.fsdecode(values[0])).absolute()
            flags = values[2]
            writing = isinstance(flags, int) and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC)
            if writing and not path.is_relative_to(out):
                denied.append("open-outside-owned-output")
                raise RuntimeError("RV4 write outside output")
        if event == "os.mkdir":
            path = Path(values[0]).absolute()
            if not path.is_relative_to(out):
                denied.append("mkdir-outside-owned-output")
                raise RuntimeError("RV4 mkdir outside output")
    sys.addaudithook(audit)
    code = pytest.main(["-s", "-o", "addopts=", "-o", "pythonpath=", "--import-mode=importlib",
                        "-p", "no:cacheprovider", "-p", "no:logging", "--assert=plain",
                        "--basetemp=" + str(out / "retained-cases"),
                        "--junitxml=" + str(out / "result.xml"), "-q", str(HERE / "test_receiver.py")])
    with (out / "effects.json").open("x", encoding="utf-8") as stream:
        json.dump({"denied": denied, "guard": "python audit, cooperative closure"}, stream)
    return code if not denied else 126


if __name__ == "__main__":
    raise SystemExit(main())
