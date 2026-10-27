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
import re
import shutil
import stat
import subprocess
import sys
import time
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path

BASE = "ddcdffd72cf6377b22d5ace95bafed61504652bb"
# Only this profile may differ from BASE in the selected product closure.
PACKAGING_INPUTS = frozenset({"eval/scanners/dev-readiness.json"})
TREE_SHA = "6168428f0f5260c79536f13b9697dd5d7fb6866e96a4762e3f8e651b34a342b2"
CHECKOV_LOCK = "3bc130464fd7c4e7c17a2bf8441cbe046cee0db4aa067ea64433da6c368c44d2"
POLICIES = {
    "__init__.py": "e523016a83ad9ddff7ec4d156463598e55a152b384ad74184e8153bdf8e384bc",
    "m4_checks.py": "f3e6a47c5b5c821c4d0a01f5a46e18cf207237bfc1181e39a7b018f67764d8f7",
    "m4_policy.py": "3d73f610a236e6a9346fd3eca45a43a7e7acdd70bad6a29842edb1f111a0cc6a",
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


def stage(root, context, cache, manifest, packaging_commit):
    """Host only: materialize the declared allowlist from immutable Git blobs."""
    if not isinstance(packaging_commit, str) or not re.fullmatch(r"[0-9a-f]{40}", packaging_commit):
        raise ValueError("explicit full packaging commit required")
    head = git(root, "rev-parse", "HEAD").decode().strip()
    if head != packaging_commit:
        raise ValueError("checkout does not match explicit packaging commit")
    subprocess.run(["git", "-C", str(root), "diff", "--quiet", "HEAD"], check=True)
    if context.exists() or (context.parent / "context-pins.json").exists():
        raise ValueError("fresh context and sibling pins required")
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
        source_commit = packaging_commit if relative in PACKAGING_INPUTS else BASE
        raw = git(root, "cat-file", "blob", f"{source_commit}:{relative}")
        if git(root, "cat-file", "blob", f"{packaging_commit}:{relative}") != raw:
            raise ValueError(f"provisional base input changed: {relative}")
        put("product/" + relative, raw)
    for relative in ("Dockerfile.scanners-linux", "evals/scanners/linux_readiness.py"):
        raw = git(root, "cat-file", "blob", f"{head}:{relative}")
        working = regular_bytes(root / relative, MAX_ARTIFACT)
        if working not in (raw, raw.replace(b"\n", b"\r\n")):
            raise ValueError(
                "packaging working bytes differ from Git LF or exact CRLF representation"
            )
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
        "packaging_commit": packaging_commit,
        "primary_scans": 0,
        "cache_sha256": TREE_SHA,
        "files": pins,
        "test_dependencies": {n: packages[n]["version"] for n in sorted(needed)},
    }
    put("pins/source.json", encode(source))
    with (context.parent / "context-pins.json").open("xb") as stream:
        stream.write(encode(pins))
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
                info = path.lstat()
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


def image_membership(root):
    """Enumerate bounded ordinary membership before any manifest-listed reads."""
    plain_chain(root)
    files, directories, stack = set(), set(), [root]
    while stack:
        directory = stack.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                path = Path(entry.path)
                rel = path.relative_to(root).as_posix()
                if len(rel.encode()) > 256 or len(path.relative_to(root).parts) > 16:
                    raise ValueError("image membership path cap")
                info = path.lstat()
                if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                    raise ValueError("image linked/reparse entry")
                if stat.S_ISDIR(info.st_mode):
                    directories.add(rel)
                    stack.append(path)
                elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                    files.add(rel)
                else:
                    raise ValueError("image special/multilink entry")
                if len(files) > 1024 or len(directories) > 256:
                    raise ValueError("image membership count cap")
    return files, directories


def requirement_versions(raw):
    required = {}
    for line in raw.decode("utf-8").splitlines():
        match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([^\s\\]+)(?:\s.*)?", line)
        if match:
            name = re.sub(r"[-_.]+", "-", match[1]).lower()
            if name in required:
                raise ValueError("duplicate pinned distribution")
            required[name] = match[2]
    if not required or len(required) > 128:
        raise ValueError("bounded pinned distributions required")
    return required


def package_metadata(root, required):
    """Read distribution headers directly; never import installed package code."""
    from email.parser import BytesHeaderParser

    plain_chain(root)
    observed, entries_seen = {}, 0
    with os.scandir(root) as entries:
        for entry in entries:
            entries_seen += 1
            if entries_seen > 2048:
                raise ValueError("package directory count cap")
            if not entry.name.endswith(".dist-info"):
                continue
            path = root / entry.name / "METADATA"
            data = regular_bytes(path, MAX_ARTIFACT)
            headers = BytesHeaderParser().parsebytes(data)
            if len(headers.get_all("Name", [])) != 1 or len(headers.get_all("Version", [])) != 1:
                raise ValueError("distribution name/version headers required")
            name = re.sub(r"[-_.]+", "-", headers["Name"]).lower()
            version = headers["Version"]
            if not re.fullmatch(r"[a-z0-9-]{1,128}", name) or len(version) > 128:
                raise ValueError("invalid package metadata")
            if name in observed:
                raise ValueError("duplicate installed distribution")
            observed[name] = {"version": version, "metadata_sha256": sha(data)}
            if len(observed) > 129:
                raise ValueError("distribution count cap")
    if set(observed) - set(required) - {"pip"} or set(required) - set(observed):
        raise ValueError("installed distribution membership mismatch")
    if any(observed[name]["version"] != version for name, version in required.items()):
        raise ValueError("installed distribution version mismatch")
    return {"required": required, "observed": observed, "pip_unpinned": "pip" not in required}


def inspect_image_metadata(
    image_root, core_packages, checkov_packages, packaging_commit, source_sha
):
    """Pure read-back seam. Injected roots are test data, not image qualification."""
    if not isinstance(packaging_commit, str) or not re.fullmatch(r"[0-9a-f]{40}", packaging_commit):
        raise ValueError("explicit full packaging commit required")
    if not isinstance(source_sha, str) or not re.fullmatch(r"[0-9a-f]{64}", source_sha):
        raise ValueError("external source receipt digest required")
    raw_source = regular_bytes(image_root / "pins/source.json", 524288)
    if sha(raw_source) != source_sha:
        raise ValueError("external source receipt mismatch")
    source = json.loads(raw_source)
    if source["source_commit"] != BASE or source["packaging_commit"] != packaging_commit:
        raise ValueError("source tuple mismatch")
    if source["primary_scans"] != 0 or source["cache_sha256"] != TREE_SHA:
        raise ValueError("metadata source scope mismatch")
    pins = source["files"]
    if not isinstance(pins, dict) or not 1 <= len(pins) <= 1024:
        raise ValueError("bounded image pins required")
    expected = {"pins/source.json"}
    for relative in pins:
        if relative == "Dockerfile.scanners-linux":
            continue  # Build input, not copied into /opt/m4.
        parts = relative.split("/")
        if (
            not all(re.fullmatch(r"[A-Za-z0-9_.-]+", part) for part in parts)
            or any(part in (".", "..") for part in parts)
            or any(
                part.lower().startswith((".env", ".credentials")) or part.lower() == "auth.json"
                for part in parts
            )
            or not relative.startswith(
                ("product/", "policies/checkov-custom/", "cache-seed/policy/", "pins/")
            )
        ):
            raise ValueError("unsafe image pin path")
        expected.add(relative)
    actual, directories = image_membership(image_root)
    expected_dirs = {
        parent.as_posix() for p in expected for parent in Path(p).parents if parent != Path(".")
    }
    tree_raw = regular_bytes(image_root / "pins/trivy-bundle-tree.json", 524288)
    if sha(tree_raw) != TREE_SHA:
        raise ValueError("cache tree manifest mismatch")
    tree = json.loads(tree_raw)
    expected_dirs.update(
        "cache-seed/policy/" + row["path"] for row in tree["rows"] if row["kind"] == "directory"
    )
    if actual != expected or directories != expected_dirs:
        raise ValueError("image membership mismatch")
    total = len(raw_source)
    for relative in sorted(expected - {"pins/source.json"}):
        data = regular_bytes(image_root / relative, MAX_ARTIFACT)
        if {"bytes": len(data), "sha256": sha(data)} != pins[relative]:
            raise ValueError("loaded image byte pin mismatch: " + relative)
        total += len(data)
        if total > 16 * 1024 * 1024:
            raise ValueError("image aggregate byte cap")
    policies = {
        "policies/checkov-custom/" + name: pins.get("policies/checkov-custom/" + name)
        for name in POLICIES
    }
    sizes = {"__init__.py": 82, "m4_checks.py": 2576, "m4_policy.py": 11018}
    if any(
        policies["policies/checkov-custom/" + name] != {"bytes": sizes[name], "sha256": digest}
        for name, digest in POLICIES.items()
    ):
        raise ValueError("approved loaded policy mismatch")
    profile = json.loads(
        regular_bytes(image_root / "product/eval/scanners/dev-readiness.json", MAX_ARTIFACT)
    )
    rows = profile["custom_policy_files"]
    if (
        len(rows) != 3
        or {row["path"]: {"bytes": row["bytes"], "sha256": row["sha256"]} for row in rows}
        != policies
    ):
        raise ValueError("loaded policy profile mismatch")
    config = profile["config"]
    if (
        config["path"] != "eval/scanners/dev-empty-config.json"
        or config["sha256"] != pins["product/" + config["path"]]["sha256"]
    ):
        raise ValueError("loaded config profile mismatch")
    cache_files = [row for row in tree["rows"] if row["kind"] == "file"]
    for row in cache_files:
        if pins.get("cache-seed/policy/" + row["path"]) != {
            "bytes": row["bytes"],
            "sha256": row["sha256"],
        }:
            raise ValueError("loaded cache manifest mismatch")
    core_required = requirement_versions(
        regular_bytes(image_root / "pins/core-requirements.txt", MAX_ARTIFACT)
    )
    if core_required != source["test_dependencies"]:
        raise ValueError("core dependency source mismatch")
    checkov_raw = regular_bytes(image_root / "pins/checkov.requirements.txt", MAX_ARTIFACT)
    if sha(checkov_raw) != CHECKOV_LOCK:
        raise ValueError("Checkov requirements lock mismatch")
    return {
        "kind": "m4-readonly-image-metadata-v1",
        "passed": True,
        "source_commit": BASE,
        "packaging_commit": packaging_commit,
        "source_receipt_sha256": source_sha,
        "files_verified": len(expected),
        "bytes_verified": total,
        "policy_files": policies,
        "config_sha256": config["sha256"],
        "cache": {
            "tree_sha256": TREE_SHA,
            "files": len(cache_files),
            "directories": sum(row["kind"] == "directory" for row in tree["rows"]),
            "aggregate_file_bytes": sum(row["bytes"] for row in cache_files),
        },
        "packages": {
            "core": package_metadata(core_packages, core_required),
            "checkov": package_metadata(checkov_packages, requirement_versions(checkov_raw)),
        },
        "primary_scans": 0,
        "legacy168_tests": "NOT_RUN_HELD",
        "nofollow": "NOT_RUN",
        "native_callbacks": "NOT_RUN",
        "primary_inputs": "NOT_RUN",
        "product_acceptance": False,
    }


def image_metadata_main(packaging_commit, source_sha):
    try:
        report = inspect_image_metadata(
            Path("/opt/m4"),
            Path("/opt/m4-core/lib/python3.12/site-packages"),
            Path("/opt/m4-checkov/lib/python3.12/site-packages"),
            packaging_commit,
            source_sha,
        )
        raw = encode(report)
        if len(raw) > MAX_REPORT:
            raise ValueError("metadata report cap")
    except (OSError, ValueError, KeyError, TypeError, RuntimeError) as error:
        raw = encode(
            {
                "kind": "m4-readonly-image-metadata-v1",
                "passed": False,
                "error": {"type": type(error).__name__, "message": str(error)[:1024]},
                "legacy168_tests": "NOT_RUN_HELD",
                "primary_scans": 0,
                "product_acceptance": False,
            }
        )
        print(raw.decode())
        return 1
    print(raw.decode())
    return 0


if __name__ == "__main__":
    if not sys.argv[1:] or sys.argv[1:] in (["tests"], ["legacy-tests"]):
        print(
            encode(
                {
                    "kind": "m4-legacy-readiness-held",
                    "passed": False,
                    "legacy168_tests": "NOT_RUN_HELD",
                    "product_acceptance": False,
                }
            ).decode()
        )
        raise SystemExit(2)
    parser = argparse.ArgumentParser()
    modes = parser.add_subparsers(dest="mode", required=True)
    staging = modes.add_parser("stage")
    staging.add_argument("--root", type=Path, required=True)
    staging.add_argument("--packaging-commit", required=True)
    staging.add_argument("--context", type=Path, required=True)
    staging.add_argument("--cache", type=Path, required=True)
    staging.add_argument("--manifest", type=Path, required=True)
    metadata = modes.add_parser("image-metadata")
    metadata.add_argument("--packaging-commit", required=True)
    metadata.add_argument("--source-sha", required=True)
    args = parser.parse_args()
    if args.mode == "stage":
        stage(args.root, args.context, args.cache, args.manifest, args.packaging_commit)
    else:
        raise SystemExit(image_metadata_main(args.packaging_commit, args.source_sha))
