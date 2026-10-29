"""Behavioral launcher regressions. No Docker, ports, Git or scanner execution.

The source inputs alone are modeled as regular files: OneDrive ancestors may
be reparse points on this machine. Evidence directories use the real filesystem.
"""

import base64
import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
PWSH = shutil.which("pwsh")
OBSERVATION = "M4/r03-rv2-test: stopped (docker ok, listeners ok; 1 container(s) matched)"

HARNESS = r"""
$ErrorActionPreference = 'Stop'
$global:calls = [System.Collections.Generic.List[string]]::new()
$global:image = 'sha256:' + ('a' * 64)
$global:cid = 'b' * 64
$global:mode = '__MODE__'
$global:labels = @{'agentports.project'='m4'; 'agentports.instance'='r03-rv2-test'; 'agentports.owner'='0024'}
function git {
    $global:calls.Add('git rev-parse'); $global:LASTEXITCODE=0
    if ($global:mode -eq 'git-exit') { $global:LASTEXITCODE=1 }
    '1e59284f4180adfe75848943d3fb21f9d308afc8'
}
function Get-Item {
    param([string]$LiteralPath)
    if ($LiteralPath -match '(Dockerfile.scanners|version_probe.py|checkov-3.3.30.requirements.txt)$') {
        return [pscustomobject]@{PSIsContainer=$false; Attributes=0; Directory=$null}
    }
    Microsoft.PowerShell.Management\Get-Item -LiteralPath $LiteralPath -Force
}
function Get-FileHash {
    param([string]$LiteralPath, [string]$Algorithm)
    if ($LiteralPath -match 'checkov-3.3.30.requirements.txt$') {
        return @{Hash='3bc130464fd7c4e7c17a2bf8441cbe046cee0db4aa067ea64433da6c368c44d2'}
    }
    Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $LiteralPath -Algorithm SHA256
}
function Copy-Item {
    param([string]$LiteralPath, [string]$Destination)
    [IO.File]::WriteAllText($Destination, 'modeled approved input')
}
function Test-Path {
    param([string]$LiteralPath)
    if ($global:mode -eq 'leaf-collision') { return $false }
    Microsoft.PowerShell.Management\Test-Path -LiteralPath $LiteralPath
}
function python {
    $global:calls.Add('ports ' + ($args -join ' '))
    $global:LASTEXITCODE=0
    if ($global:mode -eq 'observe-exit' -and $args -contains 'observe') { $global:LASTEXITCODE=1 }
    if ($global:mode -eq 'claim-exit' -and $args -contains 'claim') { $global:LASTEXITCODE=1 }
    if ($global:mode -eq 'check-exit' -and $args -contains 'check') { $global:LASTEXITCODE=1 }
    if ($args -contains 'observe') {
        $text = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__OBSERVATION__'))
        if ($text.Length -gt 0) { $text }
    }
}
function docker {
    $a = @($args); $op = $a[0]; $sub = $a[1]
    $global:calls.Add('docker ' + ($a -join ' ')); $global:LASTEXITCODE=0
    if ($op -eq 'image' -and $sub -eq 'ls') {
        if ($global:mode -eq 'repeat-image') { $global:image }
        if ($global:mode -eq 'image-ls-exit') { $global:LASTEXITCODE=1 }
        return
    }
    if ($op -eq 'container' -and $sub -eq 'ls') {
        if ($global:mode -eq 'repeat-container') { $global:cid }
        if ($global:mode -eq 'container-ls-exit') { $global:LASTEXITCODE=1 }
        return
    }
    if ($op -eq 'build') {
        $idx = [array]::IndexOf($a,'--iidfile')
        if ($idx -ge 0 -and $global:mode -ne 'missing-iid') { [IO.File]::WriteAllText($a[$idx+1],$global:image) }
        if ($global:mode -eq 'build-exit') { $global:LASTEXITCODE=1 }; return
    }
    if ($op -eq 'image' -and $sub -eq 'inspect') {
        if ($global:mode -eq 'image-inspect-exit') { $global:LASTEXITCODE=1; 'inspect failed'; return }
        if ($global:mode -eq 'missing-image') { return }
        if ($global:mode -eq 'malformed-image') { 'not json'; return }
        $id=$global:image; if ($global:mode -eq 'wrong-image') { $id='sha256:' + ('c'*64) }
        if ($global:mode -eq 'wrong-image-label') { $global:labels['agentports.owner']='other' }
        ConvertTo-Json -Depth 8 -InputObject @(@{Id=$id; Config=@{Labels=$global:labels}}); return
    }
    if ($op -eq 'run') {
        $idx = [array]::IndexOf($a,'--cidfile')
        if ($idx -ge 0 -and $global:mode -ne 'missing-cid') { [IO.File]::WriteAllText($a[$idx+1],$global:cid) }
        if ($global:mode -eq 'run-exit') { $global:LASTEXITCODE=1 }; return
    }
    if ($op -eq 'logs') {
        if ($global:mode -eq 'logs-exit') { $global:LASTEXITCODE=1; 'logs failed'; return }
        if ($global:mode -eq 'missing-logs') { return }
        if ($global:mode -eq 'malformed-logs') { '{'; return }
        $r=@{kind='m4-offline-metadata-probes';primary_scans=0;
          source=@{d11_candidate='1e59284f4180adfe75848943d3fb21f9d308afc8';requirements_sha256='3bc130464fd7c4e7c17a2bf8441cbe046cee0db4aa067ea64433da6c368c44d2';primary_scans=0};
          requirements_sha256='3bc130464fd7c4e7c17a2bf8441cbe046cee0db4aa067ea64433da6c368c44d2';
          probes=@(@{name='checkov-version';status='completed';exit_code=0},@{name='trivy-version';status='completed';exit_code=0},@{name='checkov-dependencies';status='completed';exit_code=0})}
        foreach ($p in $r.probes) {
            $p.stdout=@{bytes=0;sha256='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';base64_prefix='';prefix_truncated=$false}
            $p.stderr=$p.stdout.Clone()
        }
        if ($global:mode -eq 'missing-stream') { $r.probes[0].Remove('stdout') }
        if ($global:mode -eq 'malformed-stream') { $r.probes[0].stdout.base64_prefix='???' }
        if ($global:mode -eq 'wrong-stream-hash') { $r.probes[0].stdout.sha256='c'*64 }
        if ($global:mode -eq 'wrong-source') { $r.source.d11_candidate='c'*40 }
        if ($global:mode -eq 'missing-probe') { $r.probes=$r.probes[0..1] }
        if ($global:mode -eq 'missing-probe-exit') { $r.probes[0].Remove('exit_code') }
        $r | ConvertTo-Json -Depth 8; return
    }
    if ($op -eq 'inspect') {
        if ($global:mode -eq 'container-inspect-exit') { $global:LASTEXITCODE=1; 'inspect failed'; return }
        if ($global:mode -eq 'malformed-container') { 'not json'; return }
        $id=$global:cid; $image=$global:image
        if ($global:mode -eq 'wrong-container') { $id='d'*64 }
        if ($global:mode -eq 'wrong-container-image') { $image='sha256:' + ('c'*64) }
        if ($global:mode -eq 'wrong-container-label') { $global:labels['agentports.owner']='other' }
        $name='/m4-r03-rv2-test-e2e'; if ($global:mode -eq 'wrong-container-name') { $name='/other' }
        ConvertTo-Json -Depth 8 -InputObject @(@{Id=$id;Image=$image;Name=$name;Config=@{Labels=$global:labels};State=@{ExitCode=0;Running=$false;OOMKilled=$false}});return
    }
    throw "Unexpected Docker operation: $a"
}
$ok=$false; $failure=$null
try { & '__SCRIPT__' -EvidenceDirectory '__EVIDENCE__' -D11Root 'C:/modeled-source' -Instance 'r03-rv2-test' -PortsScript 'mock-ports.py'; $ok=$true }
catch { $failure=$_.ToString() }
@{completed=$ok;error=$failure;calls=@($global:calls)} | ConvertTo-Json -Depth 5 | Set-Content '__OUTCOME__'
"""


def run_launcher(tmp_path, mode="success", evidence=None, observation=OBSERVATION):
    evidence = evidence or tmp_path / "evidence"
    script = tmp_path / "harness.ps1"
    outcome = tmp_path / "outcome.json"
    code = HARNESS
    for token, value in {
        "MODE": mode,
        "SCRIPT": ROOT / "scripts/docker_scanners.ps1",
        "EVIDENCE": evidence,
        "OUTCOME": outcome,
        "OBSERVATION": base64.b64encode(observation.encode("utf-8")).decode("ascii"),
    }.items():
        code = code.replace(f"__{token}__", str(value).replace("'", "''"))
    script.write_text(code, encoding="utf-8")
    result = subprocess.run(
        [PWSH, "-NoProfile", "-NonInteractive", "-File", str(script)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return json.loads(outcome.read_text(encoding="utf-8-sig")), evidence


def test_success_binds_immutable_image(tmp_path):
    observed, evidence = run_launcher(tmp_path)
    assert observed["completed"], observed
    result = json.loads((evidence / "result.json").read_text(encoding="utf-8-sig"))
    assert result["probe_exit"] == 0
    run = next(c for c in observed["calls"] if c.startswith("docker run "))
    assert run.endswith("sha256:" + "a" * 64)


def test_ports_observation_ordinary_selected_summary_succeeds(tmp_path):
    observed, evidence = run_launcher(tmp_path)
    assert observed["completed"], observed
    assert (evidence / "ports-observe.log").read_text(encoding="utf-8-sig") == OBSERVATION + "\n"
    exits = json.loads((evidence / "command-exits.json").read_text(encoding="utf-8-sig"))
    assert any(
        item["argv"] == ["mock-ports.py", "observe", "m4/r03-rv2-test"] and item["exit_code"] == 0
        for item in exits
    )
    assert (evidence / "result.json").exists()


@pytest.mark.parametrize(
    "observation",
    [
        "",
        " \t ",
        "observation completed",
        "M4/wrong-instance: stopped (docker ok, listeners ok; 1 container(s) matched)",
        "OTHER/r03-rv2-test: stopped (docker ok, listeners ok; 1 container(s) matched)",
        "M4/r03-rv2-test: up (docker ok, listeners ok; 1 container(s) matched)",
        "M4/r03-rv2-test: held (docker ok, listeners ok; 1 container(s) matched)",
        "M4/r03-rv2-test: stopped (docker unknown, listeners ok; 1 container(s) matched)",
        "M4/r03-rv2-test: stopped (docker ok, listeners unknown; 1 container(s) matched)",
        "M4/r03-rv2-test: stopped (docker ok, listeners ok; 0 container(s) matched)",
        "M4/r03-rv2-test: stopped (docker ok, listeners ok; 2 container(s) matched)",
        "M4/r03-rv2-test: stopped (docker ok, listeners ok; unknown container(s) matched)",
        OBSERVATION + "\nCONFLICT: another container matched",
        OBSERVATION + "\n" + OBSERVATION,
    ],
    ids=[
        "empty",
        "whitespace",
        "malformed",
        "wrong-instance",
        "wrong-project",
        "running",
        "held",
        "docker-unknown",
        "listeners-unknown",
        "no-container",
        "multiple-containers",
        "malformed-count",
        "conflict-output",
        "duplicate-summary",
    ],
)
def test_ports_observation_invalid_exit_zero_cannot_succeed(tmp_path, observation):
    # Regression: exit 0 alone previously let absent, unrelated or contradictory
    # observation text accompany a successful selected-instance result.
    observed, evidence = run_launcher(tmp_path, observation=observation)
    assert not observed["completed"], observed
    assert not (evidence / "result.json").exists()
    assert (evidence / "failure.json").exists()
    retained = (evidence / "ports-observe.log").read_text(encoding="utf-8-sig")
    assert retained == (observation + "\n" if observation else "")
    exits = json.loads((evidence / "command-exits.json").read_text(encoding="utf-8-sig"))
    assert exits[-1]["argv"] == ["mock-ports.py", "observe", "m4/r03-rv2-test"]
    assert exits[-1]["exit_code"] == 0


@pytest.mark.parametrize(
    "mode",
    [
        "image-inspect-exit",
        "logs-exit",
        "container-inspect-exit",
        "observe-exit",
        "missing-image",
        "malformed-image",
        "wrong-image",
        "missing-iid",
        "missing-cid",
        "missing-logs",
        "malformed-logs",
        "malformed-container",
        "wrong-container",
        "wrong-container-image",
        "build-exit",
        "run-exit",
        "image-ls-exit",
        "container-ls-exit",
        "git-exit",
        "claim-exit",
        "check-exit",
        "wrong-image-label",
        "wrong-container-label",
        "wrong-container-name",
        "wrong-source",
        "missing-probe",
        "missing-probe-exit",
        "missing-stream",
        "malformed-stream",
        "wrong-stream-hash",
    ],
)
def test_incomplete_or_failed_receipt_cannot_succeed(tmp_path, mode):
    observed, evidence = run_launcher(tmp_path, mode)
    assert not observed["completed"], observed
    assert not (evidence / "result.json").exists()
    assert (evidence / "failure.json").exists()


def test_nonzero_probe_retains_logs_and_inspections(tmp_path):
    observed, evidence = run_launcher(tmp_path, "run-exit")
    assert not observed["completed"]
    for name in ("run.log", "version-probes.log", "container.json", "command-exits.json"):
        assert (evidence / name).exists()
    exits = json.loads((evidence / "command-exits.json").read_text(encoding="utf-8-sig"))
    assert any(e["argv"][0] == "run" and e["exit_code"] == 1 for e in exits)


@pytest.mark.parametrize("mode", ["repeat-image", "repeat-container"])
def test_repeat_instance_refused_before_build(tmp_path, mode):
    observed, _ = run_launcher(tmp_path, mode)
    assert not observed["completed"], observed
    assert not any(c.startswith(("docker build ", "docker run ")) for c in observed["calls"])


def test_existing_evidence_is_preserved_before_external_calls(tmp_path):
    evidence = tmp_path / "existing"
    evidence.mkdir()
    (evidence / "sentinel").write_bytes(b"retained")
    observed, _ = run_launcher(tmp_path, evidence=evidence)
    assert not observed["completed"]
    assert observed["calls"] == []
    assert (evidence / "sentinel").read_bytes() == b"retained"


def test_exclusive_leaf_collision_preserves_existing_tree(tmp_path):
    evidence = tmp_path / "collided"
    evidence.mkdir()
    (evidence / "sentinel").write_bytes(b"retained")
    # Model a stale absence check while retaining actual exclusive directory creation.
    observed, _ = run_launcher(tmp_path, "leaf-collision", evidence=evidence)
    assert not observed["completed"]
    assert observed["calls"] == []
    assert sorted(p.name for p in evidence.iterdir()) == ["sentinel"]
    assert (evidence / "sentinel").read_bytes() == b"retained"


def test_traversing_evidence_path_refused_before_external_calls(tmp_path):
    safe = tmp_path / "safe"
    safe.mkdir()
    observed, _ = run_launcher(tmp_path, evidence=safe / ".." / "elsewhere")
    assert not observed["completed"]
    assert observed["calls"] == []
    assert not (tmp_path / "elsewhere").exists()


def test_real_linked_evidence_ancestor_rejected_before_external_calls(tmp_path):
    # Keep the real junction and target outside pytest's cleanup-owned basetemp.
    retained = tmp_path.parent.parent / f"{tmp_path.parent.name}-{tmp_path.name}-junction"
    retained.mkdir()
    target = retained / "target"
    target.mkdir()
    junction = retained / "junction"
    # An actual owned junction, not a mocked attribute on the evidence path.
    command = f"New-Item -ItemType Junction -Path '{junction}' -Target '{target}' | Out-Null"
    result = subprocess.run(
        [PWSH, "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    observed, _ = run_launcher(tmp_path, evidence=junction / "fresh")
    assert not observed["completed"], observed
    assert observed["calls"] == []
    assert not (target / "fresh").exists()
