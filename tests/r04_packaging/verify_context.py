"""Independent metadata validator for an explicitly supplied staged context.

No staging, scanner, Docker, credential or corpus access. Does not import candidate
code. Read only manifest-listed ordinary files; output is local metadata evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat

BASE = "ddcdffd72cf6377b22d5ace95bafed61504652bb"
POLICIES = {
    "__init__.py": (82, "e523016a83ad9ddff7ec4d156463598e55a152b384ad74184e8153bdf8e384bc"),
    "m4_checks.py": (2576, "f3e6a47c5b5c821c4d0a01f5a46e18cf207237bfc1181e39a7b018f67764d8f7"),
    "m4_policy.py": (11018, "3d73f610a236e6a9346fd3eca45a43a7e7acdd70bad6a29842edb1f111a0cc6a"),
}


def raw(path, cap=2 * 1024 * 1024):
    for ancestor in (path, *path.parents):
        info = ancestor.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("linked input")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > cap:
        raise ValueError("not bounded regular input")
    with path.open("rb") as stream: data = stream.read(cap + 1)
    if len(data) != info.st_size: raise ValueError("size changed")
    return data


def entry_metadata(entry):
    """No following links; separately injectable metadata for inert controls."""
    # Windows DirEntry.stat may omit st_nlink; Path.lstat obtains the actual
    # non-following filesystem metadata needed to reject hard links.
    return Path(entry.path).lstat()


def exact_membership(context, declared):
    """Inspect names and lstat metadata only, before opening declared payloads.

    Only ancestors of declared files may be directories. Never descend into an
    undeclared directory, a reparse point, or any other linked/special entry.
    """
    expected_files = set(declared)
    expected_dirs = {parent.as_posix() for relative in declared
                     for parent in Path(relative).parents if parent != Path(".")}
    files, directories = set(), set()
    pending = [context]
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                relative = (directory / entry.name).relative_to(context).as_posix()
                info = entry_metadata(entry)
                if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                    raise ValueError("linked context entry")
                if stat.S_ISDIR(info.st_mode):
                    if relative not in expected_dirs:
                        raise ValueError("extra context directory")
                    directories.add(relative)
                    pending.append(directory / entry.name)
                elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                    if relative not in expected_files:
                        raise ValueError("extra context file")
                    files.add(relative)
                else:
                    raise ValueError("special or multiply-linked context entry")
    if files != expected_files or directories != expected_dirs:
        raise ValueError("missing declared context member")


def inspect(context, packaging_commit, pins_sha, source_sha):
    if len(packaging_commit) != 40 or any(c not in "0123456789abcdef" for c in packaging_commit):
        raise ValueError("exact packaging commit required")
    pin_raw = raw(context.parent / "context-pins.json", 524288)
    source_raw = raw(context / "pins/source.json", 524288)
    if hashlib.sha256(pin_raw).hexdigest() != pins_sha:
        raise ValueError("external context manifest pin mismatch")
    if hashlib.sha256(source_raw).hexdigest() != source_sha:
        raise ValueError("external source receipt pin mismatch")
    pins = json.loads(pin_raw)
    source = json.loads(source_raw)
    if source["source_commit"] != BASE or source["packaging_commit"] != packaging_commit:
        raise ValueError("source tuple mismatch")
    if source["primary_scans"] != 0: raise ValueError("metadata cannot claim primary scans")
    # Validate every declaration before inventory or declared-payload reads.
    for relative in pins:
        p = Path(relative)
        if (p.is_absolute() or ".." in p.parts or "\\" in relative or ":" in relative
                or p.as_posix() != relative or relative == "."):
            raise ValueError("unsafe manifest path")
        if any(part.lower().startswith(".env") or part.lower() in
               {"auth", "auth.json", "credentials", "credentials.json", "secret", "secrets", "key", "keys"}
               or Path(part).suffix.lower() in {".key", ".pem", ".p12", ".pfx"}
               for part in p.parts):
            raise ValueError("credential path refused without reading")
        permitted = (relative.startswith(("product/src/iac_review/", "product/eval/",
                     "product/evals/", "product/tests/eval/", "policies/checkov-custom/",
                     "pins/", "cache-seed/policy/")) or
                     relative in ("Dockerfile.scanners-linux", "product/pyproject.toml", "product/uv.lock"))
        if not permitted: raise ValueError("outside declared build allowlist")
    exact_membership(context, pins)
    for relative, expected in pins.items():
        p = Path(relative)
        data = raw(context / p)
        actual = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        if actual != expected: raise ValueError("staged byte pin mismatch")
    for relative, expected in source["files"].items():
        if pins.get(relative) != expected: raise ValueError("source/context manifests disagree")
    for name, (size, sha) in POLICIES.items():
        if pins.get("policies/checkov-custom/" + name) != {"bytes": size, "sha256": sha}:
            raise ValueError("approved policy differs")
    profile = json.loads(raw(context / "product/eval/scanners/dev-readiness.json"))
    def policies(value):
        if isinstance(value, dict):
            if value.get("path") == "policies/checkov-custom/m4_policy.py": yield value
            for child in value.values(): yield from policies(child)
        elif isinstance(value, list):
            for child in value: yield from policies(child)
    # Active custom_policy_files is distinct from preserved historical CRLF pins.
    rows = list(policies(profile["custom_policy_files"]))
    if not rows: raise ValueError("readiness policy declaration missing")
    for row in rows:
        if row.get("sha256") != POLICIES["m4_policy.py"][1] or row.get("bytes") != 11018:
            raise ValueError("stale readiness policy")
    return {"kind": "rv4-independent-context-check", "source_commit": BASE,
            "packaging_commit": packaging_commit, "files_verified": len(pins),
            "readiness_policy_rows": len(rows), "passed": True, "primary_scans": 0,
            "loaded_image": "NOT RUN", "product_acceptance": False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--context", required=True, type=Path)
    parser.add_argument("--packaging-commit", required=True)
    parser.add_argument("--pins-sha", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    result = inspect(args.context.absolute(), args.packaging_commit, args.pins_sha, args.source_sha)
    with args.out.open("x", encoding="utf-8") as stream: json.dump(result, stream, indent=2)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__": raise SystemExit(main())
