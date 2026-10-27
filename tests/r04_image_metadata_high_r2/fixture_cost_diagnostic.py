"""Finite source-free fixture cost diagnosis. Execute only after narrow preflight.

Reads literal old test data; calls only original load_data/build, never run/tests.
Every progress record is appended and flushed before its phase. No deletion.
"""
import hashlib
import json
from pathlib import Path
import stat
import sys
import time
import types

HERE = Path(__file__).absolute().parent
OLD_SUITE_SHA = "43cc3d62db2039597aa9aed93a00f93c20033223d575f75d28fcfa9476ff8617"


def event(output, phase, **details):
    record = {"phase": phase, "monotonic": time.monotonic(), **details}
    with (output / "progress.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, sort_keys=True) + "\n")
        stream.flush()
    print(json.dumps(record, sort_keys=True), flush=True)


def main(output):
    assert not output.exists()
    for path in (output.parent, *output.parent.parents):
        info = path.lstat()
        assert not stat.S_ISLNK(info.st_mode)
        assert not getattr(info, "st_file_attributes", 0) & 0x400
    output.mkdir()
    event(output, "start", candidate_imports=0, cases=2, maximum_fixture_files=1604)
    raw = (HERE / "original_suite.py").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == OLD_SUITE_SHA
    fixture = types.ModuleType("frozen_source_free_fixture_builders")
    fixture.__file__ = str(HERE / "original_suite.py")
    exec(compile(raw, fixture.__file__, "exec"), fixture.__dict__)
    oracle, data = fixture.load_data()
    results = []
    for index, variant in enumerate(("valid", "wrong-hash")):
        event(output, "build-start", case=variant, index=index)
        started = time.monotonic()
        image, core, checkov, _ = fixture.build(output / variant, oracle, data, variant)
        build_seconds = time.monotonic() - started
        event(output, "build-complete", case=variant, seconds=build_seconds)
        started = time.monotonic()
        files = byte_count = metadata_calls = 0
        for root in (image, core, checkov):
            for path in root.rglob("*"):
                info = path.lstat()
                metadata_calls += 1
                assert not stat.S_ISLNK(info.st_mode)
                assert not getattr(info, "st_file_attributes", 0) & 0x400
                if stat.S_ISREG(info.st_mode):
                    assert info.st_nlink == 1
                    byte_count += len(path.read_bytes())
                    files += 1
        row = {"case": variant, "build_seconds": build_seconds,
               "sweep_seconds": time.monotonic() - started, "files": files,
               "bytes": byte_count, "lstat_calls": metadata_calls}
        results.append(row)
        event(output, "sweep-complete", **row)
    with (output / "results.json").open("x", encoding="utf-8") as stream:
        json.dump({"candidate_imports": 0, "results": results,
                   "scope": "source-free ordinary fixture creation and independent read/lstat sweep",
                   "cleanup": "NONE_RETAINED"}, stream, indent=2)
    event(output, "complete", cases=len(results), candidate_imports=0)


if __name__ == "__main__":
    main(Path(sys.argv[1]))
