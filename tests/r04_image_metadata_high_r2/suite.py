"""High successor. Candidate execution is for independently admitted RV4 only.

Original33 constructors/oracle/assertions are literal frozen inputs. They are
represented through complete public inert observations on the NEW source tuple.
This never reruns/repairs the retained d8fe watchdog evidence.
"""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import sys
import time
import types

HERE = Path(__file__).absolute().parent
SOURCE_COMMIT = "2c3acb27dbe52695a4fdd90c7a82b5a9e6f92f92"
SOURCE_HASH = "cf23462efd48981340a61f0e82d5aa50750dd956c7fe25ca7994bbad0a70ed46"
ORIGINAL_HASH = "43cc3d62db2039597aa9aed93a00f93c20033223d575f75d28fcfa9476ff8617"
FIXED_ROOTS = (Path("/opt/m4"), Path("/opt/m4-core/lib/python3.12/site-packages"),
               Path("/opt/m4-checkov/lib/python3.12/site-packages"))
REFUSALS = (ValueError, OSError, KeyError, TypeError, RuntimeError)
HELD = {"legacy168_tests": "NOT_RUN_HELD", "nofollow": "NOT_RUN",
        "native_callbacks": "NOT_RUN", "primary_inputs": "NOT_RUN",
        "primary_scans": 0, "product_acceptance": False}
MAX_REPORT = 8 * 1024 * 1024
EXPECTED_CASES = 123


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def load_module(path, name, expected):
    raw = path.read_bytes()
    assert digest(raw) == expected
    module = types.ModuleType(name)
    module.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


class Ledger:
    def __init__(self, output, guard):
        self.output, self.results, self.guard = output, [], guard

    def event(self, phase, **details):
        record = {"phase": phase, "monotonic": time.monotonic(), **details}
        with (self.output / "progress.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record, sort_keys=True) + "\n")
            stream.flush()
        print(json.dumps(record, sort_keys=True), flush=True)

    def case(self, name, callback):
        self.event("case-start", case=name)
        started = time.monotonic()
        self.active_tree = None
        try:
            details = callback() or {}
            assert not self.guard.denials, self.guard.denials
        except BaseException as error:
            row = {"case": name, "passed": False, "error_type": type(error).__name__,
                   "message": str(error)[:2048]}
            if self.active_tree is not None:
                row.update(evidence(self.active_tree))
            row["denied_effects"] = self.guard.denials
        else:
            row = {"case": name, "passed": True, **details}
        row["seconds"] = time.monotonic() - started
        self.results.append(row)
        self.event("case-complete", **row)
        with (self.output / "cases.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(row, sort_keys=True) + "\n")
            stream.flush()


def evidence(tree):
    counts = {}
    for row in tree.calls:
        counts[row[0]] = counts.get(row[0], 0) + 1
    return {"observations": counts, "reads": [row for row in tree.calls if row[0] == "read"],
            "last_observations": tree.calls[-16:]}


def refuse(callback):
    try:
        callback()
    except REFUSALS as error:
        return {"rejected": type(error).__name__, "reason": str(error)[:256]}
    raise AssertionError("malformed observation unexpectedly accepted")


def held_report(raw, code, *, success=None, synthetic=True):
    assert type(raw) is bytes and len(raw) <= MAX_REPORT
    report = json.loads(raw)
    assert report["synthetic"] is synthetic
    assert report["observation_kind"] == ("synthetic" if synthetic else "os-readback")
    for key, value in HELD.items():
        assert report[key] == value, (key, report[key], value)
    assert report["product_acceptance"] is False
    if success is not None:
        assert report["passed"] is success and code == (0 if success else 1)
    if "error" in report:
        assert type(report["error"]["message"]) is str
        assert len(report["error"]["message"]) <= 1024
    return report


def fixed_tree(tree, roots, adapter):
    result = adapter.Tree(Path("/opt/r04-fixture"))
    result.directories = set()
    for path in tree.directories:
        for old, new in zip(roots, FIXED_ROOTS):
            if path == old or old in path.parents:
                mapped = new / path.relative_to(old)
                result.directories.add(mapped)
                result.directories.update(mapped.parents)
                break
    for path, raw in tree.files.items():
        matches = [(old, new) for old, new in zip(roots, FIXED_ROOTS)
                   if old in path.parents]
        assert len(matches) == 1
        old, new = matches[0]
        result.files[new / path.relative_to(old)] = raw
    return result


def execute(module, original, adapter, ledger):
    oracle, data = original.load_data()
    assert len(original.VARIANTS) == 33 and len(set(original.VARIANTS)) == 33

    def fixture(variant="valid"):
        result = adapter.build(original, oracle, data, variant,
                               Path("C:/synthetic-r04-image-high") / variant)
        ledger.active_tree = result[0]
        return result

    def inspect(tree, roots, source_sha, packaging=original.SOURCE_COMMIT):
        return module.inspect_image_metadata(*roots, packaging, source_sha,
                                             observations=tree.observations(module.ImageNode))

    def original_case(variant):
        tree, roots, source_sha = fixture(variant)
        packaging = original.SOURCE_COMMIT
        if variant == "external-hash":
            source_sha = "1" * 64
        elif variant == "external-commit":
            packaging = "1" * 40
        elif variant == "bad-commit-format":
            packaging = "d8fe339"
        try:
            report = inspect(tree, roots, source_sha, packaging)
        except REFUSALS as error:
            assert variant not in ("valid", "pip-absent"), (variant, str(error))
            result = {"rejected": type(error).__name__}
        else:
            assert variant in ("valid", "pip-absent"), (variant, "unexpected success")
            # The new public API adds this label. The original success function,
            # including its exact key set and all external values, is unchanged.
            assert report["synthetic"] is True
            old_report = dict(report)
            del old_report["synthetic"]
            original.success(old_report, oracle, variant != "pip-absent")
            result = {"synthetic": True}
        return {**result, **evidence(tree)}

    for variant in original.VARIANTS:
        ledger.case("original33/" + variant, lambda variant=variant: original_case(variant))

    def incomplete(attributes):
        calls = []
        class Partial:
            pass
        provider = Partial()
        for name in attributes:
            def trap(*args, name=name):
                calls.append(name)
                raise AssertionError("partial provider was accessed")
            setattr(provider, name, trap)
        result = refuse(lambda: module.image_membership(Path("C:/inert"), observations=provider))
        assert calls == []
        return result

    for names in ((), ("lstat",), ("lstat", "entries"), ("entries", "read"), ("lstat", "read")):
        ledger.case("interface/" + ("-".join(names) or "empty"),
                    lambda names=names: incomplete(names))

    node_vectors = (("special", 0, 1, False), ("symlink", 0, 1, False),
                    ("file", 0, 2, False), ("file", 0, 0, False),
                    ("file", 0, 1, True), ("directory", 0, 1, True),
                    ("invalid", 0, 1, False), ("file", True, 1, False),
                    ("file", -1, 1, False), ("file", 0, True, False),
                    ("file", 0, -1, False), ("file", 0, 1, 1))

    def node_case(vector, role):
        tree, roots, source_sha = fixture()
        target = {"image-file": roots[0] / "product/eval/scanners/dev-empty-config.json",
                  "package-metadata": next(path for path in tree.files
                                            if roots[1] in path.parents),
                  "package-root": roots[1],
                  "package-directory": next(path.parent for path in tree.files
                                             if roots[1] in path.parents),
                  "image-root": roots[0], "ancestor": roots[0].anchor}[role]
        target = Path(target)
        selected = list(vector)
        # Isolate kind/link/reparse checks from size validation: an ignored unsafe
        # flag must reach success and fail this control, not fail on fake size0.
        if type(selected[1]) is int and selected[1] == 0 and target in tree.files:
            selected[1] = len(tree.files[target])
        tree.node_overrides[target] = module.ImageNode(*selected)
        result = refuse(lambda: inspect(tree, roots, source_sha))
        return {**result, "role": role, **evidence(tree)}

    for index, vector in enumerate(node_vectors):
        for role in ("image-file", "package-metadata"):
            ledger.case(f"node/{index}/{role}",
                        lambda vector=vector, role=role: node_case(vector, role))
    for role in ("image-root", "ancestor", "package-root", "package-directory"):
        for vector in (("special", 0, 1, False), ("symlink", 0, 1, False),
                       ("directory", 0, 1, True)):
            ledger.case(f"node/{role}/{vector[0]}/{vector[3]}",
                        lambda vector=vector, role=role: node_case(vector, role))

    def invalid_node_value(value):
        tree, roots, source_sha = fixture()
        tree.node_overrides[roots[0]] = value
        return {**refuse(lambda: inspect(tree, roots, source_sha)), **evidence(tree)}

    for label, value in (("none", None), ("notimplemented", NotImplemented),
                         ("plain-tuple", ("directory", 0, 1, False))):
        ledger.case("node-result/" + label, lambda value=value: invalid_node_value(value))

    def entries_case(value):
        tree, roots, source_sha = fixture()
        tree.entry_overrides[roots[0]] = value
        return {**refuse(lambda: inspect(tree, roots, source_sha)), **evidence(tree)}

    for label, value in (("none", None), ("partial", NotImplemented), ("list", []),
                         ("empty-name", ("",)), ("dot", (".",)), ("dotdot", ("..",)),
                         ("slash", ("a/b",)), ("backslash", ("a\\b",)),
                         ("absolute", ("/x",)), ("drive", ("C:x",)), ("nul", ("a\x00b",)),
                         ("duplicate", ("same", "same")), ("long", ("a" * 257,)),
                         ("count-cap", tuple(str(i) for i in range(2049)))):
        ledger.case("entries/" + label, lambda value=value: entries_case(value))

    def read_case(label):
        tree, roots, source_sha = fixture()
        path = roots[0] / "pins/source.json"
        raw = tree.files[path]
        tree.read_overrides[path] = {"none": None, "partial": NotImplemented,
                                     "bytearray": bytearray(raw), "size": raw + b" ",
                                     "over-limit": b" " * 524290}[label]
        return {**refuse(lambda: inspect(tree, roots, source_sha)), **evidence(tree)}

    for label in ("none", "partial", "bytearray", "size", "over-limit"):
        ledger.case("read/" + label, lambda label=label: read_case(label))

    def membership_case(variant):
        tree, roots, source_sha = fixture(variant)
        result = refuse(lambda: inspect(tree, roots, source_sha))
        allowed = {str(roots[0] / "pins/source.json"),
                   str(roots[0] / "pins/trivy-bundle-tree.json")}
        reads = [row[1] for row in tree.calls if row[0] == "read"]
        assert reads and set(reads) <= allowed, reads
        return {**result, "anchor_exception_only": True, **evidence(tree)}

    for variant in ("missing-file", "extra-file", "extra-directory", "directory-for-file"):
        ledger.case("membership-before-payload/" + variant,
                    lambda variant=variant: membership_case(variant))

    def anchor_case(name):
        tree, roots, source_sha = fixture()
        path = roots[0] / ("pins/" + name)
        tree.denied_reads.add(path)
        raw, code = module.image_metadata_report(original.SOURCE_COMMIT, source_sha,
                                                 observations=tree.observations(module.ImageNode),
                                                 roots=roots)
        report = held_report(raw, code, success=False)
        assert report["error"]["type"] == "OSError"
        assert any(row[:2] == ("read", str(path)) for row in tree.calls)
        return evidence(tree)

    for name in ("source.json", "trivy-bundle-tree.json"):
        ledger.case("anchor-read-exception/" + name, lambda name=name: anchor_case(name))

    def report_positive(fixed=False):
        tree, roots, source_sha = fixture()
        if fixed:
            tree = fixed_tree(tree, roots, adapter)
            ledger.active_tree = tree
            roots = FIXED_ROOTS
            raw, code = module.image_metadata_cli(
                ["image-metadata", "--packaging-commit", original.SOURCE_COMMIT,
                 "--source-sha", source_sha], observations=tree.observations(module.ImageNode))
        else:
            raw, code = module.image_metadata_report(original.SOURCE_COMMIT, source_sha,
                                                     observations=tree.observations(module.ImageNode),
                                                     roots=roots)
        report = held_report(raw, code, success=True)
        assert set(report) == set(HELD) | {"synthetic", "observation_kind", "kind", "passed",
            "source_commit", "packaging_commit", "source_receipt_sha256", "files_verified",
            "bytes_verified", "policy_files", "config_sha256", "cache", "packages"}
        projected = dict(report)
        del projected["synthetic"]
        del projected["observation_kind"]
        original.success(projected, oracle, True)
        assert all(any(row[:2] == ("lstat", str(path)) for row in tree.calls)
                   for path in (roots[0], *roots[0].parents))
        anchor_paths = {str(roots[0] / "pins/source.json"),
                        str(roots[0] / "pins/trivy-bundle-tree.json")}
        first_payload = next(index for index, row in enumerate(tree.calls)
                             if row[0] == "read" and row[1] not in anchor_paths)
        image_directories = {path for path in tree.directories
                             if path == roots[0] or roots[0] in path.parents}
        for directory in image_directories:
            assert any(index < first_payload and row[:2] == ("entries", str(directory))
                       for index, row in enumerate(tree.calls))
        return {"fixed_root_cli": fixed, **evidence(tree)}

    ledger.case("report/explicit-roots-positive", report_positive)
    ledger.case("cli/fixed-roots-positive", lambda: report_positive(True))

    def invalid_roots(roots):
        class Trap:
            def lstat(self, *args):
                raise AssertionError("invalid roots accessed observations")
            entries = read = lstat
        raw, code = module.image_metadata_report(original.SOURCE_COMMIT, oracle["source_sha256"],
                                                 observations=Trap(), roots=roots)
        report = held_report(raw, code, success=False)
        assert report["error"]["type"] == "ValueError"

    for index, roots in enumerate((list(FIXED_ROOTS), FIXED_ROOTS[:2],
                                    (FIXED_ROOTS[0], FIXED_ROOTS[1], "not-Path"))):
        ledger.case(f"report/invalid-roots/{index}", lambda roots=roots: invalid_roots(roots))

    def huge_observation_error():
        tree, roots, source_sha = fixture()
        base = tree.observations(module.ImageNode)
        class HugeFailure:
            lstat, entries = base.lstat, base.entries
            def read(self, path, limit):
                raise OSError("X" * 12000)
        raw, code = module.image_metadata_report(original.SOURCE_COMMIT, source_sha,
                                                 observations=HugeFailure(), roots=roots)
        report = held_report(raw, code, success=False)
        assert report["error"] == {"type": "OSError", "message": "X" * 1024}
        assert len(raw) < 8192

    ledger.case("report/huge-observation-error-truncation", huge_observation_error)

    def cli_refusal(argv, held=False):
        provider_calls = []
        class Trap:
            def lstat(self, *args):
                provider_calls.append("lstat")
                raise AssertionError("held CLI accessed observations")
            entries = read = lstat
        raw, code = module.image_metadata_cli(argv, observations=Trap())
        report = held_report(raw, code)
        assert code == 2 and report["passed"] is False and not provider_calls
        if held:
            assert report["kind"] == "m4-legacy-readiness-held"
        return {"provider_calls": provider_calls}

    for argv in ([], ["tests"], ["legacy-tests"]):
        ledger.case("cli/held/" + repr(argv), lambda argv=argv: cli_refusal(argv, True))
    for argv in (["image-metadata"], ["unknown"],
                 ["image-metadata", "--roots", "C:/inert", "--source-sha", "1" * 64],
                 ["image-metadata", "--packaging-commit", "1" * 40,
                  "--packaging-commit", "1" * 40],
                 ["image-metadata", "--packaging-commit", "1" * 40,
                  "--source-sha", "1" * 64, "--extra", "x"]):
        ledger.case("cli/malformed/" + repr(argv), lambda argv=argv: cli_refusal(argv))

    def renderer_case(label):
        reports = {
            "positive-force-held": {"passed": True, "synthetic": False,
                                    "product_acceptance": True, "primary_scans": 9,
                                    "legacy168_tests": "PASS", "native_callbacks": "PASS"},
            "negative": {"passed": False}, "invalid": None,
            "passed-not-bool": {"passed": 1},
            "huge-serialization-error": {"passed": True, "payload": type("X" * 12000, (), {})()},
            "oversize": {"passed": True, "payload": "x" * (MAX_REPORT + 1)},
        }
        raw, code = module.render_synthetic_image_report(reports[label])
        report = held_report(raw, code, success=label == "positive-force-held")
        if label in ("invalid", "passed-not-bool", "huge-serialization-error", "oversize"):
            assert "error" in report and len(raw) < 8192
        if label == "huge-serialization-error":
            assert report["error"]["type"] == "TypeError"
            assert len(report["error"]["message"]) == 1024
        return {"output_bytes": len(raw), "error": report.get("error")}

    for label in ("positive-force-held", "negative", "invalid", "passed-not-bool", "huge-serialization-error", "oversize"):
        ledger.case("renderer/" + label, lambda label=label: renderer_case(label))

    def old_invalid_wrapper():
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            code = module.image_metadata_main("invalid", "1" * 64)
        complete = json.loads(captured.getvalue())
        held_report(captured.getvalue().strip().encode(), code, success=False, synthetic=False)
        # Original six-field failure schema is preserved as a projection; all new
        # fields above are independently asserted, never dropped without checking.
        original_keys = {"kind", "passed", "error", "legacy168_tests", "primary_scans", "product_acceptance"}
        assert set(complete) == original_keys | {"synthetic", "observation_kind", "nofollow", "native_callbacks", "primary_inputs"}
        failure = {key: complete[key] for key in original_keys}
        assert code == 1 and failure["passed"] is False
        assert len(captured.getvalue().encode()) < 2048
        assert set(failure) == {"kind", "passed", "error", "legacy168_tests", "primary_scans", "product_acceptance"}
        assert failure["legacy168_tests"] == "NOT_RUN_HELD"
        assert failure["primary_scans"] == 0 and failure["product_acceptance"] is False
        assert failure["error"]["type"] == "ValueError"
        assert failure["error"]["message"] == "explicit full packaging commit required"
        return {"old_wrapper_assertions": "unchanged", "added_fields_checked": True}

    ledger.case("original-wrapper/invalid-tuple", old_invalid_wrapper)


def main(source, output):
    # Independent launcher owns startup pins, fresh footprint and full preflight.
    assert not output.exists()
    output.mkdir()
    closure_raw = (HERE / "closure.json").read_bytes()
    closure = json.loads(closure_raw)
    guard_module = load_module(HERE / "effect_guard.py", "frozen_effect_guard", closure["effect_guard.py"])
    guard = guard_module.Guard(output, source, {HERE / name for name in closure} | {HERE / "closure.json"})
    sys.addaudithook(guard.hook)
    ledger = Ledger(output, guard)
    ledger.event("startup", source_commit=SOURCE_COMMIT, source_sha256=SOURCE_HASH,
                 original33=True, expected_cases=EXPECTED_CASES,
                 candidate_imports_authorized_only_after_independent_preflight=True)
    for name, expected in closure.items():
        assert digest((HERE / name).read_bytes()) == expected
    assert (HERE / "closure.json").read_bytes() == closure_raw
    original = load_module(HERE / "original_suite.py", "frozen_original_test_constructors", ORIGINAL_HASH)
    adapter = load_module(HERE / "inert_fixture.py", "frozen_inert_fixture_adapter", closure["inert_fixture.py"])
    module = load_module(source, "frozen_image_observation_source", SOURCE_HASH)
    execute(module, original, adapter, ledger)
    assert digest(source.read_bytes()) == SOURCE_HASH
    assert (HERE / "closure.json").read_bytes() == closure_raw
    for name, expected in closure.items():
        assert digest((HERE / name).read_bytes()) == expected
    result = {"source_commit": SOURCE_COMMIT, "source_sha256": SOURCE_HASH,
              "completed": len(ledger.results), "passed": sum(row["passed"] for row in ledger.results),
              "failed": sum(not row["passed"] for row in ledger.results),
              "expected_cases": EXPECTED_CASES,
              "original33_completed": sum(row["case"].startswith("original33/") for row in ledger.results),
              "denied_effects": guard.denials,
              "synthetic_only": True, "product_acceptance": False,
              "cleanup": "NONE_RETAINED", "results": ledger.results}
    with (output / "results.json").open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2)
    ledger.event("complete", **{key: value for key, value in result.items() if key != "results"})
    return int(bool(result["failed"] or result["completed"] != EXPECTED_CASES
                    or result["original33_completed"] != 33 or guard.denials))


if __name__ == "__main__":
    raise SystemExit(main(Path(sys.argv[1]), Path(sys.argv[2])))
