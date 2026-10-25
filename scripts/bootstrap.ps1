# Run from any directory. All writable Python/cache state stays in this checkout.
[CmdletBinding()]
param([string]$UvPath)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$projectRoot = Split-Path -Parent $PSScriptRoot
if (-not $UvPath) {
    $standardUv = Join-Path ([Environment]::GetFolderPath('UserProfile')) '.local/bin/uv.exe'
    if (Test-Path -LiteralPath $standardUv -PathType Leaf) {
        $UvPath = $standardUv
    } else {
        $uvCommands = @(Get-Command uv.exe -CommandType Application -ErrorAction Stop)
        if ($uvCommands.Count -ne 1) { throw 'Multiple uv executables found; supply -UvPath.' }
        $UvPath = $uvCommands[0].Source
    }
}
$uvVersion = & $UvPath --version
if ($LASTEXITCODE -ne 0 -or $uvVersion -notmatch '^uv 0\.11\.29(?:\s|$)') {
    throw 'Bootstrap requires uv 0.11.29. Supply its executable with -UvPath.'
}
$environmentValues = @{
    UV_CACHE_DIR = Join-Path $projectRoot '.agent-work/uv-cache'
    UV_PYTHON_INSTALL_DIR = Join-Path $projectRoot '.agent-work/python'
    UV_PROJECT_ENVIRONMENT = Join-Path $projectRoot '.venv'
}
$previousValues = @{}
try {
    foreach ($name in $environmentValues.Keys) {
        $previousValues[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
        [Environment]::SetEnvironmentVariable($name, $environmentValues[$name], 'Process')
    }
    & $UvPath sync --directory $projectRoot --locked --python 3.12.13
    if ($LASTEXITCODE -ne 0) { throw "uv sync failed (exit $LASTEXITCODE)" }
    $pythonPath = Join-Path $projectRoot '.venv/Scripts/python.exe'
    & $pythonPath -c 'import sys; assert sys.version_info[:3] == (3, 12, 13), sys.version; import iac_review; print(sys.executable); print(sys.version)'
    if ($LASTEXITCODE -ne 0) { throw "Interpreter/import verification failed (exit $LASTEXITCODE)" }
    Write-Output "Environment ready: $pythonPath"
} finally {
    foreach ($name in $previousValues.Keys) {
        [Environment]::SetEnvironmentVariable($name, $previousValues[$name], 'Process')
    }
}
