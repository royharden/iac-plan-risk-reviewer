"""PROPOSED static parser, NOT invoked. Separate exact startup admission required.

It parses source as data and never imports product, dependencies, or test bodies.
It cannot prove compatibility with the original unpinned parser process/schema.
"""
import sys

ROOT = r"C:\Worktrees\PortfolioBuilder\iac-plan-risk-reviewer\R04-D13-CLI7-runner-High-r1\tests\r04_cli7_high_r1"
BASE = r"C:\Users\Roy Harden\AppData\Roaming\uv\python\cpython-3.12.13-windows-x86_64-none"
with open(ROOT + r"\bootstrap-read-paths.txt", encoding="utf-8") as source:
    allowed = {line.strip().replace("/", "\\").lower() for line in source if line.strip()}
allowed.add((ROOT + r"\proposal-config.json").lower())
phase = {"data": set()}


def audit(event, args):
    denied = event.startswith(("socket.", "ctypes.", "winreg.", "subprocess."))
    denied |= event in ("os.remove", "os.rmdir", "os.rename", "os.mkdir", "os.symlink", "os.link",
                        "os.system", "os.exec", "os.spawn", "os.fork", "shutil.rmtree")
    if event == "open":
        path = args[0]
        denied |= not isinstance(path, str)
        if isinstance(path, str):
            key = path.replace("/", "\\").lower()
            denied |= key not in allowed | phase["data"] or key.endswith((".pyc", ".pth"))
        denied |= bool(args[2] & (1 | 2 | 8 | 256 | 512 | 1024))
    if denied:
        raise RuntimeError("static parser startup effect denied")


sys.addaudithook(audit)
sys.path[:] = [BASE + r"\Lib", BASE + r"\DLLs"]
import ast
import json

with open(ROOT + r"\proposal-config.json", encoding="utf-8") as source:
    config = json.load(source)
paths = [row["path"] for row in config["pins"] if row["path"].lower().startswith(ROOT.lower() + "\\")
         and row["path"].endswith(".py")]
phase["data"] = {path.lower() for path in paths}
for path in paths:
    with open(path, "rb") as source:
        ast.parse(source.read(), filename=path)
print(json.dumps({"parsed_source_files": len(paths), "executed_source_bodies": 0,
                  "oracle_equivalence": "NOT_PROVEN_PENDING_AST_INTERPRETER_SCHEMA_QUALIFICATION"}))
