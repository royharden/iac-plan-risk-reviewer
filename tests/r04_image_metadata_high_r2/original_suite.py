"""API-informed synthetic tests. Candidate execution requires independent INT preflight.

No pytest/tempfile lifecycle, real links, candidate subprocess, or cleanup.
All missing variants omit bytes while building a fresh independent directory.
"""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import stat
import sys
import types
import zipfile

HERE = Path(__file__).absolute().parent
SOURCE_HASH = "c63e1fec58ad3ec0cfaadd22ad4191499f1b1e726154100822695b55aa3d75e3"
SOURCE_COMMIT = "d8fe3399387a6073ca4612e9a659e7560694d6de"


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def plain(path):
    for item in (path, *path.parents):
        info = item.lstat()
        assert not stat.S_ISLNK(info.st_mode)
        assert not getattr(info, "st_file_attributes", 0) & 0x400


def load_data():
    oracle = json.loads((HERE / "oracle.json").read_bytes())
    raw = (HERE / "image-data.zip").read_bytes()
    assert digest(raw) == oracle["archive_sha256"]
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        data = {name: archive.read(name) for name in archive.namelist()}
    assert len(data) == oracle["files"]
    assert sum(map(len, data.values())) == oracle["bytes"]
    assert digest(data["pins/source.json"]) == oracle["source_sha256"]
    receipt = json.loads(data["pins/source.json"])
    assert receipt["packaging_commit"] == SOURCE_COMMIT
    for name, value in data.items():
        assert not Path(name).is_absolute() and all(p not in (".", "..") for p in name.split("/"))
        if name != "pins/source.json":
            assert receipt["files"][name] == {"bytes": len(value), "sha256": digest(value)}
    return oracle, data


def build(root, oracle, original, variant):
    """A separate fresh tree per vector: never remove or replace existing files."""
    assert not root.exists()
    plain(root.parent)
    root.mkdir()
    data = dict(original)
    receipt = json.loads(data["pins/source.json"])
    config = "product/eval/scanners/dev-empty-config.json"
    policy = "policies/checkov-custom/m4_policy.py"
    cache = next(name for name in sorted(data) if name.startswith("cache-seed/policy/"))
    if variant in ("missing-file", "directory-for-file"):
        data.pop(config)
    elif variant == "extra-file":
        data["product/extra.py"] = b"# inert extra\n"
    elif variant in ("wrong-hash", "policy-bytes", "config-bytes", "cache-bytes"):
        target = {"policy-bytes": policy, "cache-bytes": cache}.get(variant, config)
        data[target] = bytes([data[target][0] ^ 1]) + data[target][1:]
    elif variant == "wrong-length":
        data[config] += b" "
    elif variant == "missing-cache-file":
        data.pop(cache)
    elif variant == "wrong-base":
        receipt["source_commit"] = "1" * 40
    elif variant == "receipt-packaging":
        receipt["packaging_commit"] = "1" * 40
    elif variant == "nonzero-scans":
        receipt["primary_scans"] = 1
    elif variant == "cache-tree-id":
        receipt["cache_sha256"] = "1" * 64
    elif variant == "dependency-map":
        receipt["test_dependencies"] = {"wrong": "1.0"}
    elif variant in ("profile-policy", "profile-config"):
        name = "product/eval/scanners/dev-readiness.json"
        profile = json.loads(data[name])
        if variant == "profile-policy":
            profile["custom_policy_files"] = profile["custom_policy_files"][:2]
        else:
            profile["config"]["sha256"] = "1" * 64
        data[name] = json.dumps(profile).encode()
        receipt["files"][name] = {"bytes": len(data[name]), "sha256": digest(data[name])}
    elif variant == "declared-length":
        receipt["files"][config]["bytes"] += 1
    elif variant == "declared-hash":
        receipt["files"][config]["sha256"] = "1" * 64
    elif variant == "policy-pin":
        receipt["files"][policy]["sha256"] = "1" * 64
    elif variant == "unsafe-receipt-path":
        receipt["files"]["product/../escaped"] = {"bytes": 0, "sha256": digest(b"")}
    elif variant == "tree-manifest":
        data["pins/trivy-bundle-tree.json"] += b" "
    # Mutated receipts get a new external digest only when the control is intended
    # to reach tuple/profile validation rather than the external digest check.
    data["pins/source.json"] = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
    if variant not in ("valid", "pip-absent"):
        source_sha = digest(data["pins/source.json"])
    else:
        data["pins/source.json"] = original["pins/source.json"]
        source_sha = oracle["source_sha256"]
    image = root / "image"
    image.mkdir()
    for name in oracle["directories"]:
        (image / name).mkdir(parents=True, exist_ok=True)
    for name, raw in sorted(data.items()):
        target = image / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(raw)
    if variant == "directory-for-file":
        (image / config).mkdir()
    if variant == "extra-directory":
        (image / "empty-extra").mkdir()
    package_roots = []
    for group in ("core", "checkov"):
        packages = root / group
        packages.mkdir()
        package_roots.append(packages)
        required = oracle["packages"][group]
        first = sorted(required)[0]
        rows = [(name, version, name) for name, version in required.items()]
        if variant != "pip-absent":
            rows.append(("pip", "999.123", "pip"))
        if group == "core":
            if variant == "package-missing":
                rows = [row for row in rows if row[0] != first]
            if variant == "package-extra":
                rows.append(("unexpected-runtime", "1.0", "extra"))
            if variant == "package-duplicate":
                rows.append((first, required[first], "duplicate"))
        for name, version, directory in rows:
            folder = packages / (directory + "-fixture.dist-info")
            folder.mkdir()
            if group == "core" and name == first and variant == "metadata-missing":
                continue
            if group == "core" and name == first and variant == "package-version":
                version = "0.invalid"
            headers = f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n\n"
            if group == "core" and name == first and variant == "duplicate-header":
                headers = headers.rstrip() + "\nName: second\n\n"
            with (folder / "METADATA").open("xb") as stream:
                stream.write(headers.encode())
    return image, *package_roots, source_sha


VARIANTS = (
    "valid", "pip-absent", "external-hash", "external-commit", "bad-commit-format",
    "missing-file", "extra-file", "extra-directory", "directory-for-file", "wrong-hash",
    "wrong-length", "declared-length", "declared-hash", "policy-bytes", "config-bytes",
    "cache-bytes", "missing-cache-file", "wrong-base", "receipt-packaging", "nonzero-scans",
    "cache-tree-id", "dependency-map", "profile-policy", "profile-config", "policy-pin",
    "unsafe-receipt-path", "tree-manifest", "package-missing", "package-extra",
    "package-duplicate", "package-version", "metadata-missing", "duplicate-header",
)


def success(report, oracle, pip_present):
    expected = {
        "kind": "m4-readonly-image-metadata-v1", "passed": True,
        "source_commit": oracle["source_commit"], "packaging_commit": SOURCE_COMMIT,
        "source_receipt_sha256": oracle["source_sha256"], "files_verified": oracle["files"],
        "bytes_verified": oracle["bytes"], "policy_files": oracle["policy_files"],
        "config_sha256": oracle["config_sha256"], "cache": oracle["cache"],
        "primary_scans": 0, "legacy168_tests": "NOT_RUN_HELD", "nofollow": "NOT_RUN",
        "native_callbacks": "NOT_RUN", "primary_inputs": "NOT_RUN", "product_acceptance": False,
    }
    assert set(report) == set(expected) | {"packages"}
    for key, value in expected.items():
        assert report[key] == value, (key, report[key], value)
    assert report["passed"] is True and report["product_acceptance"] is False
    for group in ("core", "checkov"):
        actual = report["packages"][group]
        required = oracle["packages"][group]
        assert actual["required"] == required
        assert set(actual["observed"]) == set(required) | ({"pip"} if pip_present else set())
        assert actual["pip_unpinned"] is True
        for name, metadata in actual["observed"].items():
            version = required.get(name, "999.123")
            raw = f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n\n".encode()
            assert metadata == {"version": version, "metadata_sha256": digest(raw)}


def selfcheck(output):
    oracle, data = load_data()
    assert not output.exists()
    plain(output.parent)
    output.mkdir()
    for variant in VARIANTS:
        build(output / variant, oracle, data, variant)
    print(json.dumps({"fixture_builds": len(VARIANTS), "candidate_imports": 0,
                      "loaded_image_claim": False, "cleanup": "NONE_RETAINED"}))


def run(source, output):
    oracle, data = load_data()
    raw = source.read_bytes()
    assert digest(raw) == SOURCE_HASH
    assert not output.exists()
    plain(output.parent)
    output.mkdir()
    # Compile supplied source text: bypass cached candidate pyc and do not alter sys.path.
    module = types.ModuleType("frozen_readonly_metadata_candidate")
    module.__file__ = str(source)
    exec(compile(raw, str(source), "exec"), module.__dict__)
    results = []
    for variant in VARIANTS:
        image, core, checkov, source_sha = build(output / variant, oracle, data, variant)
        packaging = SOURCE_COMMIT
        if variant == "external-hash":
            source_sha = "1" * 64
        elif variant == "external-commit":
            packaging = "1" * 40
        elif variant == "bad-commit-format":
            packaging = "d8fe339"
        try:
            report = module.inspect_image_metadata(image, core, checkov, packaging, source_sha)
        except (ValueError, OSError, KeyError, TypeError, RuntimeError) as error:
            assert variant not in ("valid", "pip-absent"), (variant, str(error))
            results.append({"case": variant, "passed": True, "rejected": type(error).__name__})
        else:
            assert variant in ("valid", "pip-absent"), (variant, "unexpected success")
            success(report, oracle, variant != "pip-absent")
            results.append({"case": variant, "passed": True})
    # Explicit invalid tuple fails before fixed image roots are read. No private patch.
    captured = io.StringIO()
    with contextlib.redirect_stdout(captured):
        code = module.image_metadata_main("invalid", "1" * 64)
    failure = json.loads(captured.getvalue())
    assert code == 1 and failure["passed"] is False
    assert len(captured.getvalue().encode()) < 2048
    assert set(failure) == {"kind", "passed", "error", "legacy168_tests", "primary_scans", "product_acceptance"}
    assert failure["legacy168_tests"] == "NOT_RUN_HELD"
    assert failure["primary_scans"] == 0 and failure["product_acceptance"] is False
    assert failure["error"]["type"] == "ValueError"
    assert failure["error"]["message"] == "explicit full packaging commit required"
    assert digest(source.read_bytes()) == SOURCE_HASH
    with (output / "results.json").open("x", encoding="utf-8") as stream:
        json.dump({"results": results, "wrapper_invalid_tuple": "PASS", "source_sha256": SOURCE_HASH,
                   "legacy168_tests": "NOT_RUN_HELD", "product_acceptance": False}, stream, indent=2)
    print(json.dumps({"passed": len(results), "wrapper_invalid_tuple": "PASS",
                      "synthetic_only": True, "product_acceptance": False}))


if __name__ == "__main__":
    if sys.argv[1] == "selfcheck":
        selfcheck(Path(sys.argv[2]))
    elif sys.argv[1] == "run":
        run(Path(sys.argv[2]), Path(sys.argv[3]))
    else:
        raise SystemExit("explicit selfcheck or run required")
