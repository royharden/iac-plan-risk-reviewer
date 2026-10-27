"""Source-only entrypoint; launched only by the reviewed owned-job supervisor.

No invocation of this file is admitted by its construction grant. sys is builtin.
The supervisor verifies the entire frozen manifest before this process resumes.
"""
import sys

BASE = r"C:\Users\Roy Harden\AppData\Roaming\uv\python\cpython-3.12.13-windows-x86_64-none"
HELPERS = r"C:\Worktrees\PortfolioBuilder\iac-plan-risk-reviewer\R04-D13-CLI7-runner-High-r1\tests\r04_cli7_high_r1"
OUTPUT = r"C:\Worktrees\PortfolioBuilder\iac-plan-risk-reviewer\RV4-CLI7-0149-output-r1"
# Exactly: receipt, launch-config, worker|cli, integer call ID (0 for worker).
if len(sys.argv) != 5 or sys.argv[3] not in ("worker", "cli"):
    raise RuntimeError("invalid fixed bootstrap arguments")
receipt_path, config_path, role, call_text = sys.argv[1:]
call_id = int(call_text)
if (role == "worker" and call_id != 0) or (role == "cli" and not 1 <= call_id <= 25):
    raise RuntimeError("invalid fixed call ID")
label = "worker" if role == "worker" else f"cli-{call_id:02d}"
if receipt_path != OUTPUT + "\\evidence\\" + label + ".jsonl" or config_path != OUTPUT + "\\launch-config.json":
    raise RuntimeError("unexpected fixed bootstrap destination")
# A finite DATA allowlist, checked by the outside supervisor before resume.
# No module is imported to parse it, and no code in it is executed.
with open(HELPERS + r"\bootstrap-read-paths.txt", "r", encoding="utf-8") as pin_data:
    early_reads = {line.strip().replace("/", "\\").lower() for line in pin_data if line.strip()}
early_reads.add(config_path.lower())
receipt = open(receipt_path, "xb", buffering=0)
phase = {"guard": None}


def early(event, args):
    if phase["guard"] is not None:
        return phase["guard"].audit(event, args)
    # No third-party or product import is possible in this bootstrap phase.
    denied = event.startswith(("socket.", "ctypes.", "winreg.", "subprocess."))
    denied |= event in (
        "os.remove", "os.rmdir", "os.rename", "os.mkdir", "os.symlink", "os.link",
        "os.system", "os.exec", "os.spawn", "os.fork", "shutil.rmtree",
    )
    if event == "open":
        path, mode, flags = args
        if not isinstance(path, str):
            denied = True
        else:
            plain = path.replace("/", "\\").lower()
            allowed = plain in early_reads
            denied |= not allowed or bool(flags & (1 | 2 | 8 | 256 | 512 | 1024))
            denied |= ".pyc" in plain or "\\site-packages\\" in plain
    if denied:
        # No diagnostic import or exception formatting can read another file.
        receipt.write(("BOOTSTRAP_DENIED " + event + "\n").encode("ascii"))
        receipt.flush()
        raise RuntimeError("bootstrap effect denied")


sys.addaudithook(early)
# Every non-builtin import occurs after the hook above. No warming of native APIs.
sys.path[:] = [HELPERS, BASE + r"\Lib", BASE + r"\DLLs"]
import childguard

guard = childguard.Guard(receipt, config_path, role, int(call_text))
phase["guard"] = guard
guard.validate()
try:
    if role == "worker":
        import adapter
        code = adapter.run(guard)
    else:
        import runpy
        sys.path.insert(0, guard.config["source_root"])
        # Only explicitly pinned package files, never site/.pth or old pyc.
        sys.path.append(guard.config["dependency_root"])
        sys.argv = ["iac_review", *guard.command["args"]]
        try:
            runpy.run_module("iac_review", run_name="__main__", alter_sys=True)
            code = 0
        except SystemExit as outcome:
            code = outcome.code if type(outcome.code) is int else 1
    guard.finish(code)
except BaseException as error:
    guard.fail(type(error).__name__)
    raise
raise SystemExit(code)
