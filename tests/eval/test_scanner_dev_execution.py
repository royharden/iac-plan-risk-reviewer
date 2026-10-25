"""Raw-retention regressions with mocked Popen; no scanner or child process runs.

Grant/live fields below are artificial unit inputs, never real execution evidence.
The real grant, argv, environment and file-pin gates are exercised before the
mocked process boundary. No hidden corpus or provider/model is involved.
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import uuid
from dataclasses import asdict, replace
from pathlib import Path

import pytest
from test_scanner_execution_source import fixture, load

from eval.scanners.runner import (
    BoundedSubprocessRunner,
    Limits,
    ScannerPin,
    capture,
    digest,
    fixed_environment,
    invocation_digest,
    stage_guarded_input,
)


class PublicProcess:
    def __init__(
        self,
        stdout=b"\xffpublic-output\x00",
        stderr=b"\xfepublic-error\x00",
        *,
        code=0,
        running=False,
    ):
        self.stdout = io.BytesIO(stdout)
        self.stderr = io.BytesIO(stderr)
        self.returncode = None if running else code
        self.pid = 424242  # Artificial metadata only; never used to signal an OS PID.
        self.killed = False

    def poll(self):
        return self.returncode

    def kill(self):
        self.killed = True
        self.returncode = -9

    def wait(self, timeout=None):
        assert timeout is not None
        return self.returncode


def setup(tmp_path, monkeypatch, *, process=None, start_error=False):
    invocation, approval, manifest, grant, files = fixture(tmp_path)
    invocation = replace(
        invocation, limits=Limits(timeout_seconds=0.1, stdout_bytes=16, stderr_bytes=16)
    )
    approval = replace(approval, invocation_sha256=invocation_digest(invocation))
    grant = dict(grant, invocations=[asdict(approval)])
    runner = BoundedSubprocessRunner(True, load(tmp_path, manifest, grant))
    calls = []
    process = process or PublicProcess()

    def popen(argv, **kwargs):
        calls.append((argv, kwargs))
        assert kwargs["shell"] is False
        assert kwargs["cwd"] == tmp_path
        assert kwargs["env"] == dict(invocation.environment)
        if start_error:
            raise OSError("public synthetic start failure")
        return process

    monkeypatch.setattr("subprocess.Popen", popen)
    return runner, invocation, approval, files, calls, process


def terminal(tmp_path, stem):
    return json.loads((tmp_path / f".scanner-terminal-{stem}.json").read_bytes())


@pytest.mark.parametrize("code", [0, 1, 7])
def test_raw_non_utf8_bytes_exit_and_hash_links_survive(tmp_path, monkeypatch, code):
    """what_bug_this_catches: decoding/discarding failed scanner output makes original evidence irreproducible."""
    runner, invocation, approval, _, calls, _ = setup(
        tmp_path, monkeypatch, process=PublicProcess(code=code)
    )
    result = runner(invocation)
    receipt = terminal(tmp_path, approval.invocation_sha256)
    assert result.exit_code == receipt["raw_exit_code"] == code
    assert result.stdout == b"\xffpublic-output\x00" and result.stderr == b"\xfepublic-error\x00"
    for field, raw in (("stdout", result.stdout), ("stderr", result.stderr)):
        assert (tmp_path / receipt[f"{field}_file"]).read_bytes() == raw
        assert receipt[f"{field}_sha256"] == digest(raw)
    assert receipt["retained_output_complete"] is True
    assert receipt["output_truncated"] is False and result.error_code is None
    assert result.terminal_receipt_sha256 == digest(
        (tmp_path / f".scanner-terminal-{approval.invocation_sha256}.json").read_bytes()
    )
    assert len(calls) == 1
    with pytest.raises(PermissionError, match="already has a start receipt"):
        runner(invocation)
    assert len(calls) == 1


def test_timeout_keeps_captured_bytes_and_a_terminal_receipt(tmp_path, monkeypatch):
    """what_bug_this_catches: timeout removes original partial output or silently retries."""
    runner, invocation, approval, _, calls, process = setup(
        tmp_path, monkeypatch, process=PublicProcess(running=True)
    )
    result = runner(invocation)
    receipt = terminal(tmp_path, approval.invocation_sha256)
    assert result.timed_out and process.killed and len(calls) == 1
    assert receipt["timed_out"] is True
    assert (tmp_path / receipt["stdout_file"]).read_bytes() == result.stdout
    assert (tmp_path / receipt["stderr_file"]).read_bytes() == result.stderr


def test_overflow_retains_only_capped_prefix_and_marks_it_incomplete(tmp_path, monkeypatch):
    """what_bug_this_catches: unbounded stdout retention or capped output mislabeled as a full capture."""
    runner, invocation, approval, _, _, _ = setup(
        tmp_path, monkeypatch, process=PublicProcess(b"x" * 100, b"y" * 100)
    )
    result = runner(invocation)
    receipt = terminal(tmp_path, approval.invocation_sha256)
    assert result.output_truncated and receipt["output_truncated"] is True
    assert result.stdout == b"x" * 16 and result.stderr == b"y" * 16
    assert (tmp_path / receipt["stdout_file"]).read_bytes() == result.stdout
    assert (tmp_path / receipt["stderr_file"]).read_bytes() == result.stderr
    # Retention of the captured prefix is separate from scanner-output completeness.
    assert receipt["retained_output_complete"] is True


def test_start_error_preserves_empty_outputs_and_never_attests_process_start(tmp_path, monkeypatch):
    runner, invocation, approval, _, calls, _ = setup(tmp_path, monkeypatch, start_error=True)
    result = runner(invocation)
    receipt = terminal(tmp_path, approval.invocation_sha256)
    assert result.error_code == "process_start_failed" and result.execution_kind == "none"
    assert receipt["process_started"] is False and receipt["raw_exit_code"] is None
    assert (tmp_path / receipt["stdout_file"]).read_bytes() == b""
    assert (tmp_path / receipt["stderr_file"]).read_bytes() == b""
    assert len(calls) == 1


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_existing_raw_output_is_never_overwritten(tmp_path, monkeypatch, stream):
    """what_bug_this_catches: a reused output path destroys prior retained evidence."""
    runner, invocation, approval, _, calls, _ = setup(tmp_path, monkeypatch)
    prior = tmp_path / f".scanner-{stream}-{approval.invocation_sha256}.bin"
    prior.write_bytes(b"preexisting-public-evidence")
    result = runner(invocation)
    receipt = terminal(tmp_path, approval.invocation_sha256)
    assert prior.read_bytes() == b"preexisting-public-evidence"
    assert result.error_code == "raw_output_write_failed" and len(calls) == 1
    assert receipt["retained_output_complete"] is False


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_output_write_failure_cannot_become_a_successful_capture(tmp_path, monkeypatch, stream):
    """what_bug_this_catches: correct scanner exit/output bypasses a failed durable-evidence write."""
    runner, invocation, _, files, calls, _ = setup(tmp_path, monkeypatch)
    original = BoundedSubprocessRunner._write_bytes

    def write(path, raw):
        if path.name.startswith(f".scanner-{stream}-"):
            raise OSError("synthetic output persistence failure")
        return original(path, raw)

    monkeypatch.setattr(BoundedSubprocessRunner, "_write_bytes", staticmethod(write))
    plan, executable, deps, version, config, policy = files
    pin = ScannerPin(
        executable,
        "fixture-only",
        digest(executable.read_bytes()),
        digest(deps.read_bytes()),
        digest(version.read_bytes()),
        deps,
        version,
    )
    result = capture(
        arm="C",
        pin=pin,
        plan_path=plan,
        config_path=config,
        workspace=tmp_path,
        runner=runner,
        argv_builder=lambda: invocation.argv,
        parser=lambda _: (),
        check_ids=("CKV_FIXTURE",),
        policy_sha256=digest(policy.read_bytes()),
        policy_manifest_path=policy,
        limits=invocation.limits,
    )
    assert len(calls) == 1
    assert result.status == "error" and result.reasons == ("raw_output_write_failed",)
    assert not result.observations


def test_terminal_write_failure_is_explicit_after_raw_files_survive(tmp_path, monkeypatch):
    runner, invocation, approval, _, _, _ = setup(tmp_path, monkeypatch)
    original = BoundedSubprocessRunner._write_bytes

    def write(path, raw):
        if path.name.startswith(".scanner-terminal-"):
            raise OSError("synthetic terminal persistence failure")
        return original(path, raw)

    monkeypatch.setattr(BoundedSubprocessRunner, "_write_bytes", staticmethod(write))
    result = runner(invocation)
    assert result.error_code == "terminal_receipt_write_failed"
    assert result.terminal_receipt_sha256 is None
    assert (
        tmp_path / f".scanner-stdout-{approval.invocation_sha256}.bin"
    ).read_bytes() == result.stdout
    assert (
        tmp_path / f".scanner-stderr-{approval.invocation_sha256}.bin"
    ).read_bytes() == result.stderr


def test_no_grant_refuses_before_any_start_or_raw_file(tmp_path, monkeypatch):
    """what_bug_this_catches: a retention refactor accidentally starts an unauthorized executable."""
    invocation, _, _, _, _ = fixture(tmp_path)

    def forbidden(*args, **kwargs):
        raise AssertionError("Popen must not run without the exact grant")

    monkeypatch.setattr("subprocess.Popen", forbidden)
    with pytest.raises(PermissionError, match="pinned operator grant"):
        BoundedSubprocessRunner(True)(invocation)
    assert not list(Path(tmp_path).glob(".scanner-*"))


def retained_workspace(name):
    """Keep link fixtures outside pytest's automatically removed temporary tree."""
    root = (
        Path(__file__).resolve().parents[2]
        / ".agent-work"
        / "RV2-0040-junction-regression"
        / f"{name}-{uuid.uuid4().hex}"
    )
    root.mkdir(parents=True, exist_ok=False)
    return root


def linked_workspace(kind, position):
    root = retained_workspace(f"{kind}-{position}")
    target = root / "target"
    target.mkdir()
    workspace = target if position == "direct" else target / "ordinary-child"
    if position != "direct":
        workspace.mkdir()
    link = root / "linked"
    if kind == "junction":
        if os.name != "nt":
            pytest.skip("Windows junction regression requires Windows")
        # The only real process allowed in these tests creates this owned junction.
        # No scanner Popen mock has been installed yet, and no cleanup is registered.
        powershell = (
            Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
        )

        def quote(value):
            return "'" + str(value).replace("'", "''") + "'"

        completed = subprocess.run(
            [
                str(powershell),
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                (
                    "$ErrorActionPreference='Stop'; $null=New-Item -ItemType Junction "
                    f"-Path {quote(link)} -Target {quote(target)}"
                ),
            ],
            shell=False,
            capture_output=True,
            check=False,
            timeout=20,
            env=dict(fixed_environment(root)),
        )
        assert completed.returncode == 0, completed.stderr.decode(errors="replace")
        assert link.is_junction()
    else:
        os.symlink(target, link, target_is_directory=True)
        assert link.is_symlink()
    return workspace, link if position == "direct" else link / "ordinary-child"


def file_snapshot(directory):
    return {
        str(path.relative_to(directory)): digest(path.read_bytes())
        for path in directory.rglob("*")
        if path.is_file()
    }


@pytest.mark.parametrize("kind", ["symlink", "junction"])
@pytest.mark.parametrize("position", ["direct", "ancestor"])
def test_workspace_links_refuse_before_approval_writes_or_process(monkeypatch, kind, position):
    """what_bug_this_catches: junction or linked ancestor redirects exact-grant capture writes out of its physical workspace."""
    physical, linked = linked_workspace(kind, position)
    invocation, approval, manifest, grant, _ = fixture(physical)
    invocation = replace(
        invocation,
        cwd=linked,
        environment=fixed_environment(linked),
        limits=Limits(timeout_seconds=0.1, stdout_bytes=16, stderr_bytes=16),
    )
    approval = replace(approval, invocation_sha256=invocation_digest(invocation))
    grant = dict(grant, invocations=[asdict(approval)])
    runner = BoundedSubprocessRunner(True, load(physical, manifest, grant))
    before = file_snapshot(physical)
    calls = []

    def synthetic_process(*args, **kwargs):
        calls.append((args, kwargs))
        return PublicProcess()

    monkeypatch.setattr("subprocess.Popen", synthetic_process)
    refused = []
    for operation in (runner.approval, runner):
        try:
            operation(invocation)
        except (ValueError, PermissionError):
            refused.append(True)
        else:
            refused.append(False)
    # Check effects even when the approval check unexpectedly accepted the link.
    assert not calls, f"linked workspace reached mocked Popen: {linked}"
    assert file_snapshot(physical) == before, f"linked workspace wrote evidence: {linked}"
    assert not list(physical.glob(".scanner-*"))
    assert refused == [True, True], f"linked workspace approval admitted: {linked}"


@pytest.mark.parametrize("kind", ["symlink", "junction"])
@pytest.mark.parametrize("position", ["direct", "ancestor"])
def test_guarded_staging_links_refuse_without_writes(kind, position):
    """what_bug_this_catches: workspace validation fix leaves guarded input staging inconsistent for link ancestors."""
    physical, linked = linked_workspace(kind, position)
    (physical / "guarded-input").mkdir()
    before = file_snapshot(physical)
    raw = b"public synthetic guarded plan"
    with pytest.raises((ValueError, PermissionError)):
        stage_guarded_input(linked, raw, digest(raw), 1024)
    assert file_snapshot(physical) == before
    assert not list((physical / "guarded-input").iterdir())


def test_ordinary_workspace_approval_has_no_effect_then_keeps_capture(monkeypatch):
    """what_bug_this_catches: link confinement rejects ordinary isolated directories or makes approval write artifacts."""
    physical = retained_workspace("ordinary")
    runner, invocation, approval, _, calls, _ = setup(physical, monkeypatch)
    before = file_snapshot(physical)
    assert runner.approval(invocation) == approval
    assert not calls and file_snapshot(physical) == before
    raw = b"public synthetic guarded plan"
    (physical / "guarded-input").mkdir()
    staged = stage_guarded_input(physical, raw, digest(raw), 1024)
    assert staged.read_bytes() == raw
    result = runner(invocation)
    assert len(calls) == 1 and result.error_code is None
    receipt = terminal(physical, approval.invocation_sha256)
    assert (physical / receipt["stdout_file"]).read_bytes() == result.stdout
    assert (physical / receipt["stderr_file"]).read_bytes() == result.stderr
