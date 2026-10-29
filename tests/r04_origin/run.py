"""Source-only no-site/fresh-prefix180s runner; independent preflight required."""

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import time
from pathlib import Path

SITE = Path(
    r"C:\Worktrees\PortfolioBuilder\iac-plan-risk-reviewer\R03-RV2-eval-db\.venv\Lib\site-packages"
)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pins(root):
    paths = [
        *root.glob("*.py"),
        *root.glob("*.md"),
        *root.glob("*.ini"),
        *root.glob("data/*.json"),
        *root.glob("bindings/*.json"),
    ]
    return {str(path.resolve()): digest(path) for path in sorted(paths)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--worker", action="store_true")
    args = parser.parse_args()
    output, source = Path(args.out).resolve(), Path(args.source).resolve()
    suite = Path(__file__).resolve().parent
    prefix = Path(sys.pycache_prefix).resolve() if sys.pycache_prefix else None
    if not sys.flags.no_site or not sys.dont_write_bytecode or prefix is None or sys.flags.optimize:
        raise RuntimeError("process-start -I -S -B -X pycache_prefix required")
    expected_prefix = output / (
        "never-bytecode-worker" if args.worker else "never-bytecode-supervisor"
    )
    if prefix != expected_prefix or prefix.exists():
        raise RuntimeError("exact fresh absent process-start cache prefix required")
    if not args.worker:
        output.mkdir(parents=False, exist_ok=False)
        command = [
            sys.executable,
            "-I",
            "-S",
            "-B",
            "-X",
            "pycache_prefix=" + str(output / "never-bytecode-worker"),
            str(Path(__file__).resolve()),
            "--worker",
            "--source",
            str(source),
            "--out",
            str(output),
        ]
        environment = {
            "SystemRoot": r"C:\WINDOWS",
            "WINDIR": r"C:\WINDOWS",
            "SYSTEMDRIVE": "C:",
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONUTF8": "1",
            "TEMP": str(output),
            "TMP": str(output),
        }
        (output / "command.json").write_text(json.dumps(command), encoding="utf-8")
        started = time.monotonic()
        with (
            (output / "stdout.txt").open("xb") as stdout,
            (output / "stderr.txt").open("xb") as stderr,
        ):
            process = subprocess.Popen(command, env=environment, stdout=stdout, stderr=stderr)
            timed_out = False
            try:
                code = process.wait(timeout=180)
            except subprocess.TimeoutExpired:
                process.kill()
                code = process.wait(timeout=10)
                timed_out = True
        receipt = {
            "native_exit": code,
            "watchdog_fired": timed_out,
            "watchdog_seconds": 180,
            "elapsed_seconds": time.monotonic() - started,
            "interpreter": sys.executable,
            "interpreter_sha256": digest(Path(sys.executable)),
        }
        (output / "supervisor.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")
        print(json.dumps(receipt))
        return 124 if timed_out else code

    # No .pth/site execution; only the explicitly declared installed package directory.
    sys.path[:0] = [str(source), str(suite.parent), str(SITE)]
    if "_virtualenv" in sys.modules:
        raise RuntimeError("unreviewed virtualenv startup hook loaded")
    import pytest

    if os.name == "nt":
        import colorama  # noqa: F401 -- pytest reporting, before candidate effects
    platform.uname()
    before = {"source": pins(source / "runtime_v1"), "tests": pins(suite)}
    denials = []

    def audit(event, values):
        denied = event.startswith(("socket.", "ctypes.", "winreg.")) or event in (
            "subprocess.Popen",
            "os.system",
            "os.symlink",
            "os.link",
            "os.remove",
            "os.rmdir",
            "os.rename",
            "shutil.rmtree",
            "os.fork",
            "os.spawn",
            "os.exec",
        )
        if event == "open" and isinstance(values[0], (str, bytes, os.PathLike)):
            path = Path(os.fsdecode(values[0]))
            denied |= path.suffix.lower() == ".pyc" or path.suffix.lower() == ".pth"
            denied |= any(
                part.lower().startswith((".env", ".credentials"))
                or part.lower() in ("auth.json", "id_rsa", "id_ed25519")
                for part in path.parts
            )
            flags = values[2]
            if isinstance(flags, int) and flags & (
                os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
            ):
                denied |= not path.resolve().is_relative_to(output)
        if event == "os.mkdir":
            denied |= not Path(values[0]).resolve().is_relative_to(output)
        if denied:
            denials.append(event)
            raise RuntimeError("origin-test effect denied: " + event)

    sys.addaudithook(audit)
    started = time.monotonic()
    code = pytest.main(
        [
            "-c",
            str(suite / "pytest.ini"),
            "--rootdir",
            str(suite),
            "--noconftest",
            "--import-mode=importlib",
            "--assert=plain",
            "-p",
            "no:cacheprovider",
            "-p",
            "no:logging",
            "-s",
            "-q",
            "--junitxml",
            str(output / "junit.xml"),
            str(suite / "test_origin.py"),
            str(suite / "test_metadata.py"),
        ]
    )
    after = {"source": pins(source / "runtime_v1"), "tests": pins(suite)}
    origins = {
        name: str(Path(module.__file__).resolve())
        for name, module in tuple(sys.modules.items())
        if name.split(".")[0] == "runtime_v1" and getattr(module, "__file__", None)
    }
    integrity = (
        before == after
        and not denials
        and all(Path(path).is_relative_to(source) for path in origins.values())
    )
    result = {
        "exit_code": int(code) if integrity else 3,
        "before": before,
        "after": after,
        "effect_denials": denials,
        "integrity_passed": integrity,
        "origins": origins,
        "elapsed_seconds": time.monotonic() - started,
        "actual_contexts": 0,
        "actual_OS_backend_calls": 0,
        "operational_qualification": False,
        "product_acceptance": False,
    }
    (output / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
