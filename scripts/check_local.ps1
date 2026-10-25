<#[
RV1 local CI runner: keyless public unit/integration/CLI tests only.
Example (keep caller cwd OUTER):
  pwsh -File <worktree>\scripts\check_local.ps1 -Python <pinned-venv>\Scripts\python.exe -EvidenceDirectory <new-evidence-dir>
The selected interpreter must contain the reviewed Python 3.12 dependency lock.
No dependency resolution, provider invocation, hidden suite, or Docker operation.
]#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Python,
    [Parameter(Mandatory)][string]$EvidenceDirectory
)
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$pythonPath = (Resolve-Path -LiteralPath $Python).Path
$evidencePath = [System.IO.Path]::GetFullPath($EvidenceDirectory)
if (Test-Path -LiteralPath $evidencePath) { throw 'Evidence directory must be new; existing output is preserved.' }
$version = & $pythonPath -c 'import sys; print(sys.version); raise SystemExit(0 if sys.version_info[:2] == (3, 12) else 3)'
if ($LASTEXITCODE -ne 0) { throw 'Pinned Python 3.12 interpreter required.' }
New-Item -ItemType Directory -Path $evidencePath | Out-Null
$version | Set-Content -LiteralPath (Join-Path $evidencePath 'python-version.txt') -Encoding utf8

# uv-created environments need not include pip; importlib metadata is canonical here.
$dependencyInventory = & $pythonPath -c 'from importlib.metadata import distributions; print("\n".join(sorted(d.metadata["Name"]+"=="+d.version for d in distributions())))'
if ($LASTEXITCODE -ne 0) { throw 'Dependency inventory failed.' }
$dependencyInventory | Set-Content -LiteralPath (Join-Path $evidencePath 'dependencies.txt') -Encoding utf8
$head = & git -C $repoRoot rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw 'Candidate commit identity unavailable.' }
$status = & git -C $repoRoot status --short
$head | Set-Content -LiteralPath (Join-Path $evidencePath 'candidate.txt') -Encoding utf8
$status | Set-Content -LiteralPath (Join-Path $evidencePath 'worktree-status.txt') -Encoding utf8
$targets = @(Get-ChildItem -LiteralPath (Join-Path $repoRoot 'tests') -Directory |
    Where-Object { $_.Name -notin @('eval', 'corpus', '__pycache__') } |
    Sort-Object Name | ForEach-Object { $_.FullName })
if ($targets.Count -eq 0) { throw 'No reviewer test targets found.' }
$pytestArgs = @('-u', '-m', 'pytest', '--import-mode=importlib', '--rootdir', $repoRoot,
    '--junitxml', (Join-Path $evidencePath 'junit.xml'), '--basetemp', (Join-Path $evidencePath 'tmp'), '-ra') + $targets
$command = @($pythonPath) + $pytestArgs
ConvertTo-Json -InputObject $command | Set-Content -LiteralPath (Join-Path $evidencePath 'command.json') -Encoding utf8
# Only this invocation's source tree is importable, even when sharing a read-only venv.
$previousPythonPath = $env:PYTHONPATH
$previousEncoding = $env:PYTHONUTF8
try {
    $env:PYTHONPATH = Join-Path $repoRoot 'src'
    $env:PYTHONUTF8 = '1'
    & $pythonPath @pytestArgs 2>&1 | Tee-Object -FilePath (Join-Path $evidencePath 'pytest.txt')
    $testExitCode = $LASTEXITCODE
} finally {
    $env:PYTHONPATH = $previousPythonPath
    $env:PYTHONUTF8 = $previousEncoding
}
[ordered]@{
    candidate = $head; dirty = [bool]$status; exit_code = $testExitCode
    scope = 'public tests excluding tests/eval and tests/corpus; no hidden/live evaluation'
    product_acceptance = $false; completed_at = (Get-Date -Format o)
} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $evidencePath 'result.json') -Encoding utf8
exit $testExitCode
