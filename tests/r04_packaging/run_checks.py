"""180s public validator regression runner; no candidate imports or Docker."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
parser = argparse.ArgumentParser()
parser.add_argument("--out", type=Path, required=True)
args = parser.parse_args()
args.out.mkdir(exist_ok=False)
env = {key: os.environ[key] for key in ("PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP")
       if key in os.environ}
env.update(PYTEST_DISABLE_PLUGIN_AUTOLOAD="1", PYTHONDONTWRITEBYTECODE="1",
           RV4_PACKAGING_OUTPUT=str(args.out.absolute()))
command = [sys.executable, "-I", "-B", "-m", "pytest", "-s", "-q", "-p", "no:cacheprovider",
           "-p", "no:logging", "--assert=plain", "-o", "addopts=", "-o", "pythonpath=",
           "--junitxml=" + str(args.out.absolute() / "junit.xml"),
           "--confcutdir=" + str(HERE), str(HERE / "test_verify_context.py")]
started = time.monotonic()
try:
    result = subprocess.run(command, env=env, capture_output=True, timeout=180, check=False)
    stdout, stderr, code, timeout = result.stdout, result.stderr, result.returncode, False
except subprocess.TimeoutExpired as error:
    stdout, stderr, code, timeout = error.stdout or b"", error.stderr or b"", 124, True
for name, data in (("stdout.txt", stdout), ("stderr.txt", stderr)):
    with (args.out / name).open("xb") as stream: stream.write(data)
record = {"command": command, "exit_code": code, "watchdog_fired": timeout, "watchdog_seconds": 180,
          "elapsed_seconds": time.monotonic() - started,
          "pins": {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                   for p in HERE.iterdir() if p.is_file()}, "candidate_imports": 0,
          "docker_runs": 0, "product_acceptance": False}
if (args.out / "junit.xml").is_file():
    suites = ET.parse(args.out / "junit.xml").getroot().iter("testsuite")
    record["junit"] = {key: 0 for key in ("tests", "failures", "errors", "skipped")}
    for suite in suites:
        for key in record["junit"]:
            record["junit"][key] += int(suite.get(key, "0"))
with (args.out / "execution.json").open("x", encoding="utf-8") as stream:
    json.dump(record, stream, indent=2)
print(json.dumps(record, indent=2))
raise SystemExit(code)
