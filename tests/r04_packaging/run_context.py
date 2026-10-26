"""Supervise an exact-context metadata CLI invocation with a real 180s timeout."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
parser = argparse.ArgumentParser()
parser.add_argument("--context", type=Path, required=True)
parser.add_argument("--packaging-commit", required=True)
parser.add_argument("--pins-sha", required=True)
parser.add_argument("--source-sha", required=True)
parser.add_argument("--out", type=Path, required=True)
args = parser.parse_args()
args.out.mkdir(exist_ok=False)
command = [sys.executable, "-I", "-B", str(HERE / "verify_context.py"),
           "--context", str(args.context.absolute()),
           "--packaging-commit", args.packaging_commit,
           "--pins-sha", args.pins_sha, "--source-sha", args.source_sha,
           "--out", str(args.out.absolute() / "result.json")]
env = {key: os.environ[key] for key in ("PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP")
       if key in os.environ}
started = time.monotonic()
try:
    result = subprocess.run(command, env=env, capture_output=True, timeout=180, check=False)
    stdout, stderr, code, timeout = result.stdout, result.stderr, result.returncode, False
except subprocess.TimeoutExpired as error:
    stdout, stderr, code, timeout = error.stdout or b"", error.stderr or b"", 124, True
for name, data in (("stdout.txt", stdout), ("stderr.txt", stderr)):
    with (args.out / name).open("xb") as stream:
        stream.write(data)
record = {"command": command, "exit_code": code, "watchdog_seconds": 180,
          "watchdog_fired": timeout, "elapsed_seconds": time.monotonic() - started,
          "validator_sha256": hashlib.sha256((HERE / "verify_context.py").read_bytes()).hexdigest(),
          "candidate_imports": 0, "docker_runs": 0, "product_acceptance": False}
with (args.out / "execution.json").open("x", encoding="utf-8") as stream:
    json.dump(record, stream, indent=2)
print(json.dumps(record, indent=2))
raise SystemExit(code)
