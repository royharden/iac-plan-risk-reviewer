"""Reviewed source-only loader; invoked under -I -S -B and fresh pycache prefix.

No candidate imports occur before all manifest pins are checked. No third-party
packages, import hooks, pytest, assertion rewriting, capture or cleanup.
"""
import hashlib
import json
import sys
import time
import traceback
import types
from pathlib import Path


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    manifest_path, output_path = map(Path, sys.argv[1:])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    if not sys.flags.no_site or not sys.flags.isolated or not sys.dont_write_bytecode:
        raise RuntimeError("isolated no-site no-bytecode startup required")
    if Path(sys.pycache_prefix) != output_path / "absent-pycache":
        raise RuntimeError("fresh prefix required")
    if Path(sys.pycache_prefix).exists():
        raise RuntimeError("cache prefix must remain absent")
    def pins():
        actual = {row["path"]: digest(row["path"]) for row in manifest["pins"]}
        if any(actual[row["path"]] != row["sha256"] for row in manifest["pins"]):
            raise RuntimeError("closure drift")
        return actual
    pre = pins()
    def load(name, path, package=False):
        module = types.ModuleType(name)
        module.__file__ = str(path)
        module.__package__ = name if package else name.rpartition(".")[0]
        if package:
            module.__path__ = []
        sys.modules[name] = module
        exec(compile(Path(path).read_bytes(), str(path), "exec"), module.__dict__)
        return module
    source = manifest["source"]
    modules = {}
    for name in ("evals", "evals.scanners", "evals.scanners.storage_wire",
                 "evals.scanners.storage_receiver", "evals.scanners.storage_export"):
        modules[name] = load(name, source[name], name in ("evals", "evals.scanners"))
        if "." in name:
            parent, _, child = name.rpartition(".")
            setattr(sys.modules[parent], child, modules[name])
    oracle = load("exporter_oracle", manifest["oracle"])
    suite = load("exporter_suite", manifest["suite"])
    literals = json.loads(Path(manifest["literals"]).read_text(encoding="utf-8-sig"))
    suite.setup(modules["evals.scanners.storage_export"], modules["evals.scanners.storage_wire"],
                modules["evals.scanners.storage_receiver"], oracle, literals, output_path)
    results = []
    for name, function in sorted(vars(suite).items()):
        if name.startswith("test_") and callable(function):
            started = time.monotonic()
            try:
                function()
            except Exception:
                results.append({"name": name, "status": "FAIL", "traceback": traceback.format_exc(),
                                "seconds": time.monotonic() - started})
            else:
                results.append({"name": name, "status": "PASS", "seconds": time.monotonic() - started})
    post = pins()
    report = {"results": results, "pre": pre, "post": post,
              "native_eligible": False, "durable_verified": False,
              "loaded_files": sorted({str(getattr(m, "__file__", "")) for m in sys.modules.values()}),
              "startup": {"executable": sys.executable, "prefix": sys.prefix,
                          "base_prefix": sys.base_prefix, "path": sys.path,
                          "pycache_prefix": sys.pycache_prefix},
              "scope": "synthetic encoding and separate retained local copy only"}
    with (output_path / "results.json").open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
    print(json.dumps({"tests": len(results), "failed": sum(r["status"] == "FAIL" for r in results)}))
    return int(any(row["status"] != "PASS" for row in results))


if __name__ == "__main__":
    raise SystemExit(main())
