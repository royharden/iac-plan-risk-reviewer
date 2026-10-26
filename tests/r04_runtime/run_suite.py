"""180s supervisor and explicit-scope worker. Never discovers historical suites."""

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import time
from pathlib import Path


def pins(root):
    paths = [
        *root.glob("*.py"),
        *root.glob("*.ini"),
        *root.glob("bindings/*.json"),
        *root.glob("data/*.json"),
    ]
    return {str(p.resolve()): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths)}


def worker(args):
    output = Path(args.output).resolve()
    candidate = Path(args.candidate).resolve()
    suite = Path(__file__).resolve().parent

    def source_pins():
        result = {**pins(candidate / "runtime_v1"), **pins(candidate / "runtime_launch")}
        for path in sorted((candidate / "src/iac_review").rglob("*.py")):
            result[str(path.resolve())] = hashlib.sha256(path.read_bytes()).hexdigest()
        return result

    def test_pins():
        return {**pins(suite), **pins(suite.parent / "r04_cli")}

    source_before = source_pins()
    test_before = test_pins()
    sys.dont_write_bytecode = True
    os.environ["R04_TEST_OUTPUT"] = str(output)
    sys.path[:0] = [str(candidate), str(candidate / "src"), str(suite.parent)]
    denials = []

    def audit(event, values):
        denied = event.startswith(("socket.", "ctypes.", "winreg.")) or event in (
            "os.symlink",
            "os.link",
            "os.remove",
            "os.rmdir",
            "os.rename",
            "os.system",
            "os.exec",
            "os.spawn",
            "os.fork",
            "shutil.rmtree",
        )
        if event == "subprocess.Popen":
            command = values[1]
            prefix = [sys.executable, "-B", "-m", "iac_review"]
            allowed = isinstance(command, (list, tuple)) and list(command[:4]) == prefix
            if os.name == "nt" and type(command) is str:
                allowed = any(
                    command.startswith(subprocess.list2cmdline(prefix + [verb]) + " ")
                    for verb in ("inspect", "verify-report", "share")
                )
            denied = not (args.scope == "cli" and allowed)
        if event == "open" and isinstance(values[0], (str, bytes, os.PathLike)):
            path = Path(os.fsdecode(values[0]))
            parts = [part.lower() for part in path.parts]
            denied |= any(
                part.startswith((".env", ".credentials"))
                or part == "auth.json"
                or part in ("id_rsa", "id_ed25519")
                for part in parts
            )
            flags = values[2]
            writing = isinstance(flags, int) and bool(
                flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)
            )
            if writing:
                denied |= not path.resolve().is_relative_to(output)
        if event == "os.mkdir":
            denied |= not Path(values[0]).resolve().is_relative_to(output)
        if denied:
            denials.append(event)
            raise RuntimeError("R04 test effect denied: " + event)

    # Import pytest before effect guard; candidate imports occur only inside tests.
    import pytest

    # Windows pytest terminal support loads colorama lazily; preload test-tool
    # support before the candidate effect window, keeping candidate ctypes denied.
    if os.name == "nt":
        import colorama  # noqa: F401
    platform.uname()  # JUnit hostname metadata is test tooling, not candidate networking.
    sys.addaudithook(audit)
    targets = (
        [suite / "test_core.py", suite / "test_launcher.py"]
        if args.scope == "runtime"
        else [suite.parent / "r04_cli/test_journey.py"]
    )
    started = time.monotonic()
    code = pytest.main(
        [
            "-c",
            str(suite / "pytest.ini"),
            "--rootdir",
            str(suite.parent),
            "--basetemp",
            str(output / "retained-temp"),
            "--junitxml",
            str(output / "junit.xml"),
            "-s",
            "-p",
            "no:logging",
            "-q",
            *map(str, targets),
        ]
    )
    result = {
        "exit_code": code,
        "scope": args.scope,
        "elapsed_seconds": time.monotonic() - started,
        "effect_denials": denials,
        "source_before": source_before,
        "source_after": source_pins(),
        "tests_before": test_before,
        "tests_after": test_pins(),
        "actual_runtime_verified": False,
        "product_acceptance": False,
    }
    origins = {
        name: str(Path(module.__file__).resolve())
        for name, module in tuple(sys.modules.items())
        if name.split(".")[0] in ("runtime_v1", "runtime_launch", "iac_review")
        and getattr(module, "__file__", None)
    }
    result["import_origins"] = origins
    integrity = (
        result["source_before"] == result["source_after"]
        and result["tests_before"] == result["tests_after"]
        and all(Path(path).is_relative_to(candidate) for path in origins.values())
        and not denials
    )
    result["integrity_passed"] = integrity
    if not integrity:
        result["exit_code"] = 3
    (output / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return int(result["exit_code"])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--scope", choices=["runtime", "cli"], required=True)
    parser.add_argument("--worker", action="store_true")
    args = parser.parse_args()
    if args.worker:
        return worker(args)
    output = Path(args.output).resolve()
    output.mkdir(parents=False, exist_ok=False)
    environment = {
        key: os.environ[key] for key in ("SystemRoot", "PATH", "TEMP", "TMP") if key in os.environ
    }
    environment.update(
        PYTHONDONTWRITEBYTECODE="1", PYTEST_DISABLE_PLUGIN_AUTOLOAD="1", PYTHONUTF8="1"
    )
    command = [
        sys.executable,
        "-I",
        "-B",
        str(Path(__file__).resolve()),
        "--worker",
        "--candidate",
        args.candidate,
        "--output",
        str(output),
        "--scope",
        args.scope,
    ]
    (output / "command.json").write_text(json.dumps(command), encoding="utf-8")
    with (output / "stdout.txt").open("xb") as stdout, (output / "stderr.txt").open("xb") as stderr:
        process = subprocess.Popen(command, env=environment, stdout=stdout, stderr=stderr)
        try:
            code = process.wait(timeout=180)
            timed_out = False
        except subprocess.TimeoutExpired:
            process.kill()
            code = process.wait(timeout=10)
            timed_out = True
    receipt = {
        "native_exit": code,
        "watchdog_seconds": 180,
        "timed_out": timed_out,
        "interpreter": sys.executable,
        "python": sys.version,
        "interpreter_sha256": hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
    }
    (output / "supervisor.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")
    print(json.dumps(receipt))
    return 124 if timed_out else code


if __name__ == "__main__":
    raise SystemExit(main())
