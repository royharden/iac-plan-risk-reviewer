param([Parameter(Mandatory=$true)][string]$Output)
$ErrorActionPreference='Stop'
# PROPOSED only: RV4 actualHigh full independent preflight + explicit admission
# must bind exact bytes, startup footprint and fresh Output before invocation.
$pythonRoot='C:\Users\Roy Harden\AppData\Roaming\uv\python\cpython-3.12.13-windows-x86_64-none'
$python=Join-Path $pythonRoot 'python.exe'
$source='C:\Worktrees\PortfolioBuilder\iac-plan-risk-reviewer\R04-D15-image-observation\evals\scanners\linux_readiness.py'
$sourceHash='cf23462efd48981340a61f0e82d5aa50750dd956c7fe25ca7994bbad0a70ed46'
$sourceCommit='2c3acb27dbe52695a4fdd90c7a82b5a9e6f92f92'
$testRoot=$PSScriptRoot
$absolute=[IO.Path]::GetFullPath($Output)
$allowed=$testRoot.TrimEnd('\')+'\'
if(-not $absolute.StartsWith($allowed,[StringComparison]::OrdinalIgnoreCase)) {throw 'Output must be an owned descendant of exact successor test root'}
if(Test-Path -LiteralPath $absolute) {throw 'Fresh absent retained output required; no retries or overwrite'}
$closure=Get-Content -Raw -LiteralPath (Join-Path $testRoot 'closure.json') | ConvertFrom-Json
$closureHash=(Get-FileHash -LiteralPath (Join-Path $testRoot 'closure.json') -Algorithm SHA256).Hash
$startup=Get-Content -Raw -LiteralPath (Join-Path $testRoot 'startup.json') | ConvertFrom-Json
$absent=@((Join-Path $pythonRoot 'pyvenv.cfg'),(Join-Path (Split-Path -Parent $pythonRoot) 'pyvenv.cfg'),(Join-Path $pythonRoot 'python._pth'),(Join-Path $pythonRoot 'python312._pth'),(Join-Path $pythonRoot 'python312.zip'))
function Ordinary-Ancestors([string]$path) {
    $item=Get-Item -LiteralPath $path
    while($null -ne $item) {
        if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint)-ne0) {throw "Reparse ancestor: $($item.FullName)"}
        $item=$item.Parent
    }
}
function Check-Pins {
    if((Get-FileHash -LiteralPath (Join-Path $testRoot 'closure.json') -Algorithm SHA256).Hash-ne $closureHash) {throw 'Closure manifest changed'}
    foreach($pin in $closure.PSObject.Properties) {
        if($pin.Name.Contains('/') -or $pin.Name.Contains('\') -or $pin.Name -in @('.','..')) {throw 'Single-component test pin paths required'}
        if((Get-FileHash -LiteralPath (Join-Path $testRoot $pin.Name) -Algorithm SHA256).Hash.ToLowerInvariant()-ne $pin.Value) {throw "Changed test input: $($pin.Name)"}
    }
    if((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()-ne $sourceHash) {throw 'Exact new observation source required; d8fe evidence is separate'}
    foreach($row in $startup) {
        if((Get-FileHash -LiteralPath $row.path -Algorithm SHA256).Hash.ToLowerInvariant()-ne $row.sha256) {throw "Changed startup input: $($row.path)"}
    }
    foreach($path in $absent) {if(Test-Path -LiteralPath $path) {throw "Startup override present: $path"}}
}
Ordinary-Ancestors (Split-Path -Parent $absolute)
Ordinary-Ancestors $testRoot
Ordinary-Ancestors (Split-Path -Parent $source)
Ordinary-Ancestors $pythonRoot
Check-Pins
New-Item -ItemType Directory -Path $absolute -ErrorAction Stop | Out-Null
$cache=Join-Path $absolute 'ABSENT-PYC-PREFIX'
$fixtures=Join-Path $absolute 'results'
$start=[Diagnostics.ProcessStartInfo]::new()
$start.FileName=$python
$start.WorkingDirectory=$testRoot
$start.UseShellExecute=$false
$start.CreateNoWindow=$true
$start.RedirectStandardOutput=$true
$start.RedirectStandardError=$true
$start.Environment.Clear()
$start.Environment['SystemRoot']='C:\Windows'
$start.Environment['WINDIR']='C:\Windows'
$start.Environment['PATH']=$pythonRoot+';C:\Windows\System32'
$start.Environment['TEMP']=$absolute
$start.Environment['TMP']=$absolute
$arguments=@('-I','-S','-B','-X',"pycache_prefix=$cache",(Join-Path $testRoot 'suite.py'),$source,$fixtures)
foreach($arg in $arguments) {$start.ArgumentList.Add($arg)}
@{python=$python;arguments=$arguments;cwd=$testRoot;environment=@{SystemRoot='C:\Windows';WINDIR='C:\Windows';PATH=$start.Environment['PATH'];TEMP=$absolute;TMP=$absolute};source_commit=$sourceCommit;source_sha256=$sourceHash;startup_inputs=$startup.Count;startup_overrides_absent=$absent;output_absent_before=$true;cache_absent_before=$true;watchdog_seconds=180;synthetic_only=$true;product_acceptance=$false;cleanup='NONE_RETAINED'}|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $absolute 'launch.json')
$process=[Diagnostics.Process]::new()
$process.StartInfo=$start
$started=[DateTime]::UtcNow
$null=$process.Start()
$stdout=$process.StandardOutput.ReadToEndAsync()
$stderr=$process.StandardError.ReadToEndAsync()
$completed=$process.WaitForExit(180000)
if(-not $completed) {$process.Kill($true);$process.WaitForExit()}
[IO.File]::WriteAllText((Join-Path $absolute 'stdout.txt'),$stdout.GetAwaiter().GetResult())
[IO.File]::WriteAllText((Join-Path $absolute 'stderr.txt'),$stderr.GetAwaiter().GetResult())
@{completed=$completed;exit_code=$process.ExitCode;pid=$process.Id;started_at=$started.ToString('o');ended_at=[DateTime]::UtcNow.ToString('o');watchdog_seconds=180;source_commit=$sourceCommit;source_sha256=$sourceHash;cache_absent_after=(-not(Test-Path -LiteralPath $cache));old168='NOT_RUN_HELD';full103='NOT_RUN';synthetic_only=$true;product_acceptance=$false;cleanup='NONE_RETAINED'}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $absolute 'execution.json')
# Preserve outputs even if a postcondition fails. A missing final result means
# completed/pass/fail counts are unknown; phase/case records still survive.
Check-Pins
$startup|ForEach-Object {[PSCustomObject]@{path=$_.path;sha256=(Get-FileHash -LiteralPath $_.path -Algorithm SHA256).Hash.ToLowerInvariant()}}|ConvertTo-Json -Depth 3|Set-Content -LiteralPath (Join-Path $absolute 'POST-STARTUP.json')
$closure.PSObject.Properties|ForEach-Object {[PSCustomObject]@{path=$_.Name;sha256=(Get-FileHash -LiteralPath (Join-Path $testRoot $_.Name) -Algorithm SHA256).Hash.ToLowerInvariant()}}|ConvertTo-Json -Depth 3|Set-Content -LiteralPath (Join-Path $absolute 'POST-TESTS.json')
if(-not $completed -or $process.ExitCode-ne0 -or(Test-Path -LiteralPath $cache)) {throw 'Synthetic successor suite failed/incomplete; preserve evidence, no retry'}
