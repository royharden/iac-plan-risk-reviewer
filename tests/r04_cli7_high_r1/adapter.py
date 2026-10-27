"""Mechanical dispatch of the externally owned seven-case oracle, no pytest.

Only decorators/fixture dispatch and invoke transport change. plan/body AST nodes
are compiled unchanged after exact raw test and AST identity checks.
"""
import ast
import hashlib
import json
import time
from pathlib import Path
from types import SimpleNamespace


def digest(node):
    return hashlib.sha256(ast.dump(node, include_attributes=False).encode()).hexdigest()


def emit_file(path, value):
    import os
    raw = json.dumps(value, ensure_ascii=True, sort_keys=True).encode("ascii")
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def extract(guard):
    config = guard.config
    raw = Path(config["oracle"]).read_bytes()
    expectations = json.loads(Path(config["expectations"]).read_bytes())
    if config["ast_recipe_status"] != "OWNER_RECIPE_AND_VERSION_QUALIFIED":
        raise RuntimeError("original AST recipe recovered; interpreter/schema qualification pending")
    if hashlib.sha256(raw).hexdigest() != expectations["test_sha256"]:
        raise RuntimeError("original test bytes drift")
    tree = ast.parse(raw, filename=config["oracle"])
    functions = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
    plan = functions["plan"]
    body = functions["test_exit_privacy_verify_export"]
    # Exact recovered owner recipe: full plan FunctionDef, unmodified runtime fields.
    if digest(plan) != expectations["plan_function_AST_sha256"]:
        raise RuntimeError("original plan AST drift")
    if len(body.decorator_list) != 1:
        raise RuntimeError("unexpected framework decoration")
    decorator = body.decorator_list[0]
    if not (isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute) and
            isinstance(decorator.func.value, ast.Attribute) and
            isinstance(decorator.func.value.value, ast.Name) and
            decorator.func.value.value.id == "pytest" and decorator.func.value.attr == "mark" and
            decorator.func.attr == "parametrize" and len(decorator.args) == 2 and
            ast.literal_eval(decorator.args[0]) == "case,expected" and not decorator.keywords):
        raise RuntimeError("parameter decorator shape changed")
    rows = ast.literal_eval(decorator.args[1])
    expected_rows = [(r["case"], r["expected_exit"]) for r in expectations["cases"]]
    if rows != expected_rows or len(rows) != 7 or rows != [(r["case"], r["expected_exit"]) for r in config["cases"]]:
        raise RuntimeError("original seven parameter rows drift")
    if digest(ast.Module(body=body.body, type_ignores=[])) != expectations["test_body_AST_sha256"]:
        raise RuntimeError("original assertion body AST drift")
    body.decorator_list = []
    # No imports or other test module top-level code are executed.
    selected = ast.Module(body=[plan, body], type_ignores=[])
    namespace = {"json": json, "hashlib": hashlib}
    exec(compile(selected, config["oracle"], "exec"), namespace)
    return rows, namespace


def run(guard):
    root = Path(guard.config["output"])
    control = root / "control"
    rows, namespace = extract(guard)
    sequence = 0
    outcomes = []

    def invoke(*args):
        nonlocal sequence
        sequence += 1
        if sequence > 25:
            raise RuntimeError("unexpected extra CLI call")
        planned = guard.config["calls"][sequence - 1]
        arguments = list(map(str, args))
        if arguments != planned["args"]:
            raise RuntimeError("oracle call differs from frozen command table")
        before = guard.inventory(root / "cases")
        guard.rehash()
        guard.emit({"event": "cli-before", "call_id": sequence, "inventory": before})
        emit_file(control / f"request-{sequence:02d}.json", {"id": sequence, "args": arguments})
        emit_file(control / f"request-{sequence:02d}.ready", {"id": sequence})
        response = control / f"response-{sequence:02d}.json"
        ready = control / f"response-{sequence:02d}.ready"
        # The outside supervisor owns both timers. This bounded wait cannot kill anything.
        deadline = time.monotonic() + 35
        while not ready.exists():
            if time.monotonic() > deadline:
                raise RuntimeError("supervisor response missing; no local process fallback")
            time.sleep(0.01)
        value = json.loads(response.read_bytes())
        if value["id"] != sequence or value["timed_out"] or not value["receipt_complete"]:
            raise RuntimeError("CLI incomplete/timeout, not an oracle result")
        stdout = Path(value["stdout"]).read_bytes().decode("utf-8")
        stderr = Path(value["stderr"]).read_bytes().decode("utf-8")
        # subprocess.run(text=True, encoding=utf-8) uses universal newline translation.
        stdout = stdout.replace("\r\n", "\n").replace("\r", "\n")
        stderr = stderr.replace("\r\n", "\n").replace("\r", "\n")
        guard.rehash()
        guard.emit({"event": "cli-after", "call_id": sequence,
                    "inventory": guard.inventory(root / "cases"), "native_exit": value["exit"]})
        return SimpleNamespace(returncode=value["exit"], stdout=stdout, stderr=stderr)

    namespace["invoke"] = invoke
    for case, expected in rows:
        case_path = root / "cases" / case
        case_path.mkdir(exist_ok=False)
        before_count = sequence
        started = time.monotonic()
        try:
            namespace["test_exit_privacy_verify_export"](case_path, case, expected)
        except BaseException as error:
            # Record exact failed case and preserve exception semantics; no skips or continuing as PASS.
            trace = []
            cursor = error.__traceback__
            while cursor is not None:
                trace.append({"filename": cursor.tb_frame.f_code.co_filename, "line": cursor.tb_lineno})
                cursor = cursor.tb_next
            guard.emit({"event": "case-failed", "case": case, "error_type": type(error).__name__,
                        "trace_locations": trace,
                        "calls": sequence - before_count, "elapsed": time.monotonic() - started})
            emit_file(root / "evidence" / "case-results.json", {"logical_cases": outcomes + [
                {"case": case, "status": "FAILED", "error_type": type(error).__name__}] + [
                {"case": later, "status": "NOT_RUN"} for later, _ in rows[len(outcomes) + 1:]],
                "cli_calls": sequence, "acceptance": False, "status": "FAILED_NOT_SEVEN_PASS"})
            raise
        count = sequence - before_count
        if count != (1 if case == "malformed" else 4):
            raise RuntimeError("case invocation count mismatch")
        outcomes.append({"case": case, "expected_exit": expected, "status": "PASS", "calls": count})
        guard.emit({"event": "case-completed", **outcomes[-1]})
    if sequence != 25 or len(outcomes) != 7:
        raise RuntimeError("incomplete seven-case dispatch")
    emit_file(root / "evidence" / "case-results.json", {"logical_cases": outcomes, "cli_calls": sequence,
              "pytest_collected": "NOT_APPLICABLE", "hostname": "NOT_COLLECTED",
              "acceptance": False, "method": "mechanical-original-body-adapter"})
    return 0
