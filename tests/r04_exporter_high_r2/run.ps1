param([Parameter(Mandatory=$true)][string]$OutputPath,
      [Parameter(Mandatory=$true)][string]$ManifestSha256)
$ErrorActionPreference = 'Stop'
$suiteRoot = $PSScriptRoot
$manifestPath = Join-Path $suiteRoot 'closure.json'
if ((Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $ManifestSha256) { throw 'manifest pin mismatch' }
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
function Confirm-StartupInventory {
  foreach ($path in $manifest.absent_startup) {
    if (Test-Path -LiteralPath $path) { throw "unexpected startup path: $path" }
  }
  $actual = @(Get-ChildItem -LiteralPath $manifest.python_home -Recurse -File | Where-Object {
    $_.FullName -notmatch '\\(site-packages|__pycache__)\\' -and
    ($_.Extension -in @('.py','.dll','.pyd','.zip','.exe','._pth') -or $_.Name -eq 'pyvenv.cfg')
  } | ForEach-Object FullName | Sort-Object)
  if (Compare-Object $actual @($manifest.startup_inventory)) { throw 'startup inventory drift' }
}
Confirm-StartupInventory
$targetPath = [IO.Path]::GetFullPath($OutputPath)
$permittedRoot = 'C:\Worktrees\PortfolioBuilder\iac-plan-risk-reviewer\R04-RV3-producer-image-tests\exporter-retained\'
if (-not $targetPath.StartsWith($permittedRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'output outside retained root' }
if (Test-Path -LiteralPath $targetPath) { throw 'output must be fresh and absent' }
foreach ($row in $manifest.pins) {
  if ((Get-FileHash -LiteralPath $row.path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $row.sha256) { throw "closure drift before startup: $($row.path)" }
}
$null = New-Item -ItemType Directory -Path $targetPath
$arguments = @('-I', '-S', '-B', '-X', "pycache_prefix=$targetPath\absent-pycache", (Join-Path $suiteRoot 'run.py'), $manifestPath, $targetPath)
# ProcessStartInfo.ArgumentList preserves each path with spaces without shell interpolation.
$start = [Diagnostics.ProcessStartInfo]::new()
$start.FileName = $manifest.interpreter
$start.UseShellExecute = $false
$start.CreateNoWindow = $true
$start.WorkingDirectory = 'C:\Users\Roy Harden\OneDrive\PJ-OD\PortfolioBuilder\iac-plan-risk-reviewer'
foreach ($argument in $arguments) { $start.ArgumentList.Add($argument) }
$process = [Diagnostics.Process]::Start($start)
$finished = $process.WaitForExit(180000)
if (-not $finished) {
  $process.Kill($true)
  $process.WaitForExit()
  'WATCHDOG_TIMEOUT_180_SECONDS; retained prefix' | Set-Content -LiteralPath (Join-Path $targetPath 'watchdog.txt')
}
$after = foreach ($row in $manifest.pins) {
  $actual = (Get-FileHash -LiteralPath $row.path -Algorithm SHA256).Hash.ToLowerInvariant()
  [pscustomobject]@{path=$row.path;sha256=$actual;matches=($actual -eq $row.sha256)}
}
$after | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $targetPath 'post-startup-pins.json')
Confirm-StartupInventory
if ((Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $ManifestSha256) { throw 'post manifest pin mismatch' }
if (-not $finished) { throw 'watchdog timeout; retained outputs' }
if ($after.matches -contains $false) { throw 'post-execution closure drift' }
if ($process.ExitCode -ne 0) { throw "tests exit $($process.ExitCode); retained results" }
