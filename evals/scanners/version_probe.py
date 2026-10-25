"""Fixed metadata probes only; never used as the primary capture engine.

Run in the confined, offline Docker preparation image. Raw version output is
retained in Docker logs as base64, since its temporary files disappear at exit.
"""
from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import sys
from pathlib import Path

LIMIT = 65536


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def probe(name, argv):
    directory = Path("/tmp") / name
    directory.mkdir()
    environment = {
        "HOME": str(directory), "TMPDIR": str(directory),
        "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONSAFEPATH": "1", "CHECKOV_ALLOW_USAGE_METRICS": "false",
        "LOG_LEVEL": "ERROR",
    }
    result = {"name": name, "argv": argv, "executable_sha256": digest(Path(argv[0]))}
    with (directory / "stdout").open("xb") as stdout, (directory / "stderr").open("xb") as stderr:
        try:
            completed = subprocess.run(argv, cwd=directory, env=environment,
                                       stdin=subprocess.DEVNULL, stdout=stdout,
                                       stderr=stderr, timeout=30, check=False)
            result.update(status="completed", exit_code=completed.returncode)
        except (OSError, subprocess.TimeoutExpired) as error:
            result.update(status="error", error_type=type(error).__name__)
    for channel in ("stdout", "stderr"):
        path = directory / channel
        with path.open("rb") as stream:
            raw = stream.read(LIMIT + 1)
        result[channel] = {
            "bytes": path.stat().st_size, "sha256": digest(path),
            "base64_prefix": base64.b64encode(raw[:LIMIT]).decode("ascii"),
            "prefix_truncated": len(raw) > LIMIT,
        }
    return result


def main():
    # Distribution metadata inventory, without importing Checkov or running scans.
    inventory_code = (
        "import importlib.metadata as m,json,hashlib; from pathlib import Path; "
        "rows=[{'name':d.metadata['Name'],'version':d.version,"
        "'record_sha256':hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None} "
        "for d in m.distributions() for p in [Path(d._path)/'RECORD']]; "
        "print(json.dumps(sorted(rows,key=lambda r:r['name'].lower()),sort_keys=True))"
    )
    results = [
        probe("checkov-version", ["/opt/m4-checkov/bin/checkov", "--version"]),
        probe("trivy-version", ["/usr/local/bin/trivy", "--version"]),
        probe("checkov-dependencies", ["/opt/m4-checkov/bin/python", "-I", "-c", inventory_code]),
    ]
    report = {
        "kind": "m4-offline-metadata-probes", "primary_scans": 0,
        "source": json.loads(Path("/opt/m4/pins/source.json").read_text()),
        "requirements_sha256": digest(Path("/opt/m4/pins/checkov.requirements.txt")),
        "probes": results,
        "limits": "Version commands only; no scanner compatibility or policy/cache acceptance.",
    }
    print(json.dumps(report, sort_keys=True))
    return int(any(item.get("exit_code") != 0 for item in results))


if __name__ == "__main__":
    sys.exit(main())
