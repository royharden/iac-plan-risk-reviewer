"""Fixed Linux metadata/test run and closed, Git-blob build-context staging.

No checkov/trivy scan, policy import/execution, plan corpus or benchmark run.
All temporary reporters are exported completely through bounded Docker logs.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.metadata
import json
import os
import shutil
import stat
import subprocess
import sys
import time
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path

BASE = "cb298a8a96749ae633f108f61b62515732faf1fe"
TREE_SHA = "6168428f0f5260c79536f13b9697dd5d7fb6866e96a4762e3f8e651b34a342b2"
CHECKOV_LOCK = "3bc130464fd7c4e7c17a2bf8441cbe046cee0db4aa067ea64433da6c368c44d2"
POLICIES = {
    "__init__.py": "e523016a83ad9ddff7ec4d156463598e55a152b384ad74184e8153bdf8e384bc",
    "m4_checks.py": "f3e6a47c5b5c821c4d0a01f5a46e18cf207237bfc1181e39a7b018f67764d8f7",
    "m4_policy.py": "ebb08944a9e72025dbd2a04d85982e9bdb5455d29c4ee489d671eed07ecccc74",
}
TESTS = ("test_trivy_bundle_inventory.py", "test_trivy_bundle_binding.py")
MAX_ARTIFACT = 2 * 1024 * 1024
MAX_REPORT = 8 * 1024 * 1024


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def plain_chain(path):
    for item in reversed((path, *path.parents)):
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError(f"linked/reparse input refused: {item}")


def regular_bytes(path, cap):
    plain_chain(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > cap:
        raise ValueError(f"bounded regular input required: {path}")
    with path.open("rb") as stream:
        raw = stream.read(cap + 1)
    if len(raw) != info.st_size or len(raw) > cap:
        raise ValueError("input size changed")
    return raw


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args])


def stage(root, context, cache, manifest):
    """Host only: materialize the declared allowlist from immutable Git blobs."""
    head = git(root, "rev-parse", "HEAD").decode().strip()
    subprocess.run(["git", "-C", str(root), "diff", "--quiet", "HEAD"], check=True)
    if context.exists():
        raise ValueError("fresh context required")
    plain_chain(context.parent)
    context.mkdir()
    files = git(root, "ls-tree", "-r", "--name-only", BASE).decode().splitlines()
    explicit = {
        "eval/__init__.py",
        "eval/runner/__init__.py",
        "eval/runner/scoring.py",
        "pyproject.toml",
        "uv.lock",
        "evals/__init__.py",
        "evals/scanners/__init__.py",
        "evals/scanners/version_probe.py",
    }
    selected = [
        p
        for p in files
        if p in explicit
        or (p.startswith("src/iac_review/") and p.endswith(".py"))
        or (
            p.startswith("eval/scanners/") and p.endswith(".py") and not p.endswith("dev_inputs.py")
        )
        or p in {f"tests/eval/{name}" for name in TESTS}
        or p.startswith("tests/eval/fixtures/trivy-bundle-v1/")
        or p in {"eval/scanners/dev-readiness.json", "eval/scanners/dev-empty-config.json"}
    ]
    pins = {}

    def put(relative, raw):
        target = context / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(raw)
        pins[relative] = {"bytes": len(raw), "sha256": sha(raw)}

    for relative in sorted(selected):
        mode = git(root, "ls-tree", BASE, "--", relative).split()[0]
        if mode not in (b"100644", b"100755"):
            raise ValueError("nonregular Git build input")
        raw = git(root, "cat-file", "blob", f"{BASE}:{relative}")
        if git(root, "cat-file", "blob", f"{head}:{relative}") != raw:
            raise ValueError(f"provisional base input changed: {relative}")
        put("product/" + relative, raw)
    for relative in ("Dockerfile.scanners-linux", "evals/scanners/linux_readiness.py"):
        raw = git(root, "cat-file", "blob", f"{head}:{relative}")
        if regular_bytes(root / relative, MAX_ARTIFACT) != raw:
            raise ValueError("packaging working bytes differ from Git")
        put(relative if relative.startswith("Dockerfile") else "product/" + relative, raw)
    for name, expected in POLICIES.items():
        raw = git(root, "cat-file", "blob", f"{BASE}:policies/checkov-custom/{name}")
        if sha(raw) != expected:
            raise ValueError("approved LF policy pin mismatch")
        put("policies/checkov-custom/" + name, raw)
    lock = tomllib.loads(git(root, "cat-file", "blob", f"{BASE}:uv.lock").decode())
    packages = {p["name"]: p for p in lock["package"]}
    pending, needed = ["pytest", "pydantic"], set()
    while pending:
        name = pending.pop()
        if name in needed:
            continue
        needed.add(name)
        pending.extend(d["name"] for d in packages[name].get("dependencies", []))
    requirements = []
    for name in sorted(needed):
        package = packages[name]
        hashes = sorted({w["hash"] for w in package["wheels"]})
        if not hashes or any(not h.startswith("sha256:") for h in hashes):
            raise ValueError("hashlocked wheel requirements missing")
        requirements.append(
            f"{name}=={package['version']} " + " ".join("--hash=" + h for h in hashes)
        )
    put("pins/core-requirements.txt", ("\n".join(requirements) + "\n").encode())
    raw = git(root, "cat-file", "blob", f"{BASE}:eval/scanners/checkov-3.3.30.requirements.txt")
    if sha(raw) != CHECKOV_LOCK:
        raise ValueError("Checkov lock changed")
    put("pins/checkov.requirements.txt", raw)
    raw = regular_bytes(manifest, 524288)
    if sha(raw) != TREE_SHA:
        raise ValueError("canonical complete-tree manifest mismatch")
    expected = json.loads(raw)
    put("pins/trivy-bundle-tree.json", raw)
    actual = set()
    for directory, dirs, names in os.walk(cache, followlinks=False):
        for name in dirs + names:
            path = Path(directory) / name
            plain_chain(path)
            actual.add(path.relative_to(cache).as_posix())
    if actual != {row["path"] for row in expected["rows"]}:
        raise ValueError("cache membership differs from approved complete tree")
    for row in expected["rows"]:
        target = context / "cache-seed/policy" / row["path"]
        if row["kind"] == "directory":
            target.mkdir(parents=True, exist_ok=True)
        else:
            data = regular_bytes(cache / row["path"], 65536)
            if len(data) != row["bytes"] or sha(data) != row["sha256"]:
                raise ValueError("cache input bytes differ")
            put("cache-seed/policy/" + row["path"], data)
    source = {
        "source_commit": BASE,
        "packaging_commit": head,
        "primary_scans": 0,
        "cache_sha256": TREE_SHA,
        "files": pins,
        "test_dependencies": {n: packages[n]["version"] for n in sorted(needed)},
    }
    put("pins/source.json", encode(source))
    (context.parent / "context-pins.json").write_bytes(encode(pins))
    print(
        json.dumps(
            {
                "context": str(context),
                "source": BASE,
                "packaging": head,
                "files": len(pins),
                "primary_scans": 0,
            }
        )
    )


def artifact(path):
    raw = regular_bytes(path, MAX_ARTIFACT)
    return {"bytes": len(raw), "sha256": sha(raw), "base64": base64.b64encode(raw).decode()}


def diagnostic_artifact(path):
    """Retain a bounded reporter prefix without hiding missing or unreadable files."""
    # Three encoded prefixes must fit MAX_REPORT alongside source/tree metadata.
    cap = MAX_ARTIFACT // 2
    try:
        plain_chain(path)
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("bounded regular reporter required")
        with path.open("rb") as stream:
            raw = stream.read(cap + 1)
        if len(raw) != min(info.st_size, cap + 1):
            raise ValueError("reporter size changed")
        raw = raw[:cap]
        return (
            {"bytes": len(raw), "sha256": sha(raw), "base64": base64.b64encode(raw).decode()},
            {
                "status": "truncated" if info.st_size > cap else "complete",
                "source_bytes": info.st_size,
                "retained_bytes": len(raw),
                "cap_bytes": cap,
            },
        )
    except FileNotFoundError as error:
        return None, {"status": "missing", "type": type(error).__name__, "message": str(error)}
    except (OSError, ValueError) as error:
        return None, {
            "status": "read-error",
            "type": type(error).__name__,
            "message": str(error),
        }


def image_pins(root, source):
    observed = {}
    for relative, expected in source["files"].items():
        if relative.startswith("product/"):
            path = root / relative.removeprefix("product/")
        elif relative.startswith(("cache-seed/", "policies/", "pins/")):
            path = Path("/opt/m4") / relative
        else:
            continue
        raw = regular_bytes(path, MAX_ARTIFACT)
        found = {"bytes": len(raw), "sha256": sha(raw)}
        if found != expected:
            raise ValueError(f"loaded image pin mismatch: {relative}")
        observed[relative] = found
    return observed


def audit_tree(root):
    """Independent raw-file/directory audit; never call the product verifier."""
    rows, stack, total, files, directories = [], [root], 0, 0, 0
    while stack:
        directory = stack.pop()
        plain_chain(directory)
        with os.scandir(directory) as entries:
            for entry in entries:
                path = Path(entry.path)
                info = entry.stat(follow_symlinks=False)
                relative = path.relative_to(root).as_posix()
                if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                    raise ValueError("audit link/reparse refused")
                if stat.S_ISDIR(info.st_mode):
                    directories += 1
                    rows.append({"path": relative, "kind": "directory"})
                    stack.append(path)
                elif stat.S_ISREG(info.st_mode):
                    data = regular_bytes(path, 65536)
                    files += 1
                    total += len(data)
                    rows.append(
                        {"path": relative, "kind": "file", "bytes": len(data), "sha256": sha(data)}
                    )
                else:
                    raise ValueError("audit special object refused")
                if files > 1024 or directories > 256 or len(rows) > 1280 or total > 2097152:
                    raise ValueError("audit bounds exceeded")
    rows.sort(key=lambda row: row["path"].encode("utf-8"))
    payload = {
        "schema_version": "m4-scanner-bundle-tree-v1",
        "algorithm": "sha256",
        "paths": "normalized-posix-relative-utf8",
        "rows": rows,
    }
    return {
        "tree_sha256": sha(encode(payload)),
        "files": files,
        "directories": directories,
        "aggregate_file_bytes": total,
        "rows": rows,
    }


def test_phase():
    """Fixed child test invocation with explicit product import provenance."""
    import importlib

    import pytest

    root = Path("/opt/m4/product")
    scratch = Path("/tmp/m4-linux-readiness")
    test_copy = scratch / "test-copy"
    source = json.loads(Path("/opt/m4/pins/source.json").read_bytes())
    modules = (
        "eval.scanners.bundle_inventory",
        "eval.scanners.runner",
        "eval.scanners.driver",
        "eval.scanners.trivy_adapter",
        "eval.scanners.run_manifest",
        "eval.scanners.scoring_bridge",
        "eval.runner.scoring",
        "iac_review.contracts.manifest",
    )
    for name in modules:
        importlib.import_module(name)

    def origins():
        result = {}
        for name, module in tuple(sys.modules.items()):
            if not name.startswith(("eval.scanners", "eval.runner", "iac_review")):
                continue
            filename = getattr(module, "__file__", None)
            if not filename:
                continue
            path = Path(filename)
            relative = "product/" + path.relative_to(root).as_posix()
            digest = sha(regular_bytes(path, MAX_ARTIFACT))
            if digest != source["files"][relative]["sha256"]:
                raise ValueError("test imported unpinned product bytes")
            result[name] = {"path": str(path), "sha256": digest}
        return result

    before = origins()
    arguments = [
        "-q",
        "-p",
        "no:cacheprovider",
        "-c",
        str(test_copy / "pyproject.toml"),
        "--basetemp",
        str(scratch / "pytest-temp"),
        "--junitxml",
        str(scratch / "pytest.xml"),
        *[str(test_copy / "tests/eval" / name) for name in TESTS],
    ]
    exit_code = pytest.main(arguments)
    after = origins()
    unchanged = all(after.get(name) == value for name, value in before.items())
    (scratch / "imports.json").write_bytes(
        encode(
            {
                "before": before,
                "after": after,
                "before_unchanged": unchanged,
                "pytest": pytest.__version__,
                "pytest_path": pytest.__file__,
                "executable": sys.executable,
                "arguments": arguments,
            }
        )
    )
    return int(exit_code or not unchanged)


def runtime():
    from version_probe import probe

    root = Path("/opt/m4/product")
    scratch = Path("/tmp/m4-linux-readiness")
    scratch.mkdir()
    Path("/tmp/m4-home").mkdir()
    source = json.loads(Path("/opt/m4/pins/source.json").read_bytes())
    report = {
        "kind": "m4-linux-readiness-v1",
        "primary_scans": 0,
        "source": source,
        "platform": sys.platform,
        "artifacts": {},
        "diagnostics": {"schema_version": "m4-linux-readiness-diagnostics-v1", "reporters": {}},
        "pytest": {"completed": False, "exit_code": None, "timed_out": False},
        "passed": False,
    }
    try:
        before = image_pins(root, source)
        profile = json.loads((root / "eval/scanners/dev-readiness.json").read_bytes())
        if {
            Path(row["path"]).name: row["sha256"] for row in profile["custom_policy_files"]
        } != POLICIES:
            raise ValueError("loaded source profile does not bind approved LF policies")
        report["loaded_policy_profile"] = profile["custom_policy_files"]
        report["core"] = {
            "python": sys.version,
            "executable": sys.executable,
            "executable_sha256": sha(Path(sys.executable).read_bytes()),
            "dependencies": {
                d.metadata["Name"].lower().replace("_", "-"): d.version
                for d in importlib.metadata.distributions()
            },
        }
        core_match = all(
            report["core"]["dependencies"].get(name) == version
            for name, version in source["test_dependencies"].items()
        )
        inventory = "import importlib.metadata as m,json;print(json.dumps(sorted([(d.metadata['Name'],d.version) for d in m.distributions()])))"
        report["versions"] = [
            probe("linux-checkov-version", ["/opt/m4-checkov/bin/checkov", "--version"]),
            probe("linux-trivy-version", ["/usr/local/bin/trivy", "--version"]),
            probe(
                "linux-checkov-dependencies", ["/opt/m4-checkov/bin/python", "-I", "-c", inventory]
            ),
        ]
        test_copy = scratch / "test-copy"
        (test_copy / "tests/eval").mkdir(parents=True)
        for name in TESTS:
            shutil.copyfile(root / "tests/eval" / name, test_copy / "tests/eval" / name)
        shutil.copytree(root / "tests/eval/fixtures", test_copy / "tests/eval/fixtures")
        shutil.copyfile(root / "pyproject.toml", test_copy / "pyproject.toml")
        test_before = {
            p.relative_to(test_copy).as_posix(): sha(p.read_bytes())
            for p in test_copy.rglob("*")
            if p.is_file()
        }
        xml, log = scratch / "pytest.xml", scratch / "pytest.log"
        argv = [sys.executable, "-B", str(Path(__file__)), "tests"]
        report["pytest_argv"] = argv
        environment = dict(
            os.environ, PYTHONPATH=f"{root / 'src'}:{root}:{test_copy / 'tests/eval'}"
        )
        with log.open("xb") as stream:
            try:
                completed = subprocess.run(
                    argv,
                    stdin=subprocess.DEVNULL,
                    stdout=stream,
                    stderr=subprocess.STDOUT,
                    env=environment,
                    timeout=300,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                report["pytest"].update(timed_out=True, timeout_seconds=300)
                raise
        report["pytest"].update(completed=True, exit_code=completed.returncode)
        suites = ET.parse(xml).getroot().findall("testsuite")
        counts = {
            k: sum(int(s.attrib[k]) for s in suites)
            for k in ("tests", "failures", "errors", "skipped")
        }
        skipped = [
            {"name": c.attrib.get("name"), "reason": c.find("skipped").attrib}
            for s in suites
            for c in s.findall("testcase")
            if c.find("skipped") is not None
        ]
        nofollow = [
            c
            for s in suites
            for c in s.findall("testcase")
            if c.attrib.get("name", "").startswith("test_file_open_uses_nofollow_where_available")
        ]
        report["pytest"] = {
            **report["pytest"],
            "exit_code": completed.returncode,
            **counts,
            "skips": skipped,
            "nofollow_cases": [c.attrib for c in nofollow],
            "nofollow_executed": bool(nofollow)
            and all(c.find("skipped") is None for c in nofollow),
        }
        report["test_imports"] = json.loads((scratch / "imports.json").read_bytes())
        report["test_copy_unchanged"] = all(
            sha((test_copy / rel).read_bytes()) == digest for rel, digest in test_before.items()
        )
        from eval.scanners.bundle_inventory import load_bundle_inventory, verify_tree

        workspace = scratch / "tree-workspace"
        workspace.mkdir()
        shutil.copytree(Path("/opt/m4/cache-seed/policy"), workspace / "policy")
        binding = load_bundle_inventory(
            {
                "profile": "m4-trivy-complete-cache-v1",
                "root": str(workspace / "policy"),
                "manifest_path": "/opt/m4/pins/trivy-bundle-tree.json",
                "tree_sha256": TREE_SHA,
            },
            workspace,
        )
        audit_before = audit_tree(workspace / "policy")
        start = time.monotonic()
        deadline = start + 30
        summaries = [
            verify_tree(binding, deadline=deadline),
            verify_tree(binding, deadline=deadline),
        ]
        shared = time.monotonic() - start
        audit_after = audit_tree(workspace / "policy")
        report["tree"] = {
            "passes": summaries,
            "shared_seconds": shared,
            "deadline_seconds": 30,
            "audit_before": audit_before,
            "audit_after": audit_after,
            "unchanged": audit_before == audit_after,
        }
        expected = {
            "tree_sha256": TREE_SHA,
            "files": 642,
            "directories": 99,
            "aggregate_file_bytes": 1056327,
        }
        report["tree"]["expected_match"] = all(
            all(s[k] == v for k, v in expected.items())
            for s in [*summaries, audit_before, audit_after]
        )
        report["image_pins_before"] = before
        report["image_pins_after"] = image_pins(root, source)
        versions_match = (
            base64.b64decode(report["versions"][0]["stdout"]["base64_prefix"]).strip() == b"3.3.30"
            and base64.b64decode(report["versions"][1]["stdout"]["base64_prefix"]).strip()
            == b"Version: 0.76.1"
        )
        report["passed"] = (
            core_match
            and versions_match
            and completed.returncode == 0
            and all(p.get("exit_code") == 0 for p in report["versions"])
            and counts["tests"] == 168
            and counts["failures"] == counts["errors"] == 0
            and report["pytest"]["nofollow_executed"]
            and report["test_imports"]["before_unchanged"]
            and report["test_copy_unchanged"]
            and report["tree"]["unchanged"]
            and report["tree"]["expected_match"]
            and report["tree"]["shared_seconds"] <= 30
            and report["image_pins_after"] == before
        )
    except (
        OSError,
        ValueError,
        RuntimeError,
        subprocess.SubprocessError,
        ET.ParseError,
        KeyError,
        TypeError,
        ImportError,
    ) as error:
        report["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        # The test stdout stream has closed before collection, including on timeout.
        # Collect independently: one missing/bad reporter must not discard the rest.
        for name in ("pytest.xml", "pytest.log", "imports.json"):
            retained, status = diagnostic_artifact(scratch / name)
            report["diagnostics"]["reporters"][name] = status
            if retained is not None:
                report["artifacts"][name] = retained
        if any(
            status["status"] != "complete" for status in report["diagnostics"]["reporters"].values()
        ):
            report["passed"] = False
    raw = encode(report)
    if len(raw) > MAX_REPORT:
        report["passed"] = False
        raw = encode(
            {
                "kind": "m4-linux-readiness-v1",
                "passed": False,
                "primary_scans": 0,
                "error": "report_over_cap",
            }
        )
    print(raw.decode())
    return int(not report["passed"] or len(raw) > MAX_REPORT)


if __name__ == "__main__":
    if sys.argv[1:] == ["tests"]:
        raise SystemExit(test_phase())
    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser()
        parser.add_argument("mode", choices=["stage"])
        parser.add_argument("--root", type=Path, required=True)
        parser.add_argument("--context", type=Path, required=True)
        parser.add_argument("--cache", type=Path, required=True)
        parser.add_argument("--manifest", type=Path, required=True)
        args = parser.parse_args()
        stage(args.root, args.context, args.cache, args.manifest)
    else:
        raise SystemExit(runtime())
