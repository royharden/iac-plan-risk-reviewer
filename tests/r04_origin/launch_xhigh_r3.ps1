# Unexecuted author-owned launch control. Independent complete Xhigh preflight required.
$ErrorActionPreference='Stop'
$outerPath='C:\Users\Roy Harden\OneDrive\PJ-OD\PortfolioBuilder\iac-plan-risk-reviewer'
$suitePath='C:\Worktrees\PortfolioBuilder\iac-plan-risk-reviewer\R04-RV3-origin-tests\tests\r04_origin'
$outputPath=Join-Path $suitePath 'retained\RV4-origin-Xhigh-0141-execution-r1'
if((Get-Location).Path -ne $outerPath -or (Test-Path -LiteralPath $outputPath)){throw 'Exact OUTER/absent output required'}
$info=[Diagnostics.ProcessStartInfo]::new()
$info.FileName='C:\Worktrees\PortfolioBuilder\iac-plan-risk-reviewer\R03-RV2-eval-db\.venv\Scripts\python.exe'
$info.WorkingDirectory=$outerPath
$info.UseShellExecute=$false
$info.CreateNoWindow=$true
$info.Environment.Clear()
$environment=@{SYSTEMROOT='C:\WINDOWS';WINDIR='C:\WINDOWS';SYSTEMDRIVE='C:';PYTEST_DISABLE_PLUGIN_AUTOLOAD='1';PYTHONDONTWRITEBYTECODE='1';PYTHONUTF8='1';PY_COLORS='0';NO_COLOR='1';TERM='dumb';TEMP=$outputPath;TMP=$outputPath;COLUMNS='80';LINES='24'}
foreach($key in $environment.Keys){$info.Environment[$key]=$environment[$key]}
$arguments=@('-I','-S','-B','-X',('pycache_prefix='+(Join-Path $outputPath 'never-bytecode-supervisor')),(Join-Path $suitePath 'run_xhigh_r3.py'),'--source',(Join-Path $suitePath 'retained\source-899ec15-r1'),'--out',$outputPath)
foreach($argument in $arguments){$info.ArgumentList.Add($argument)}
$process=[Diagnostics.Process]::new()
$process.StartInfo=$info
try{
    if(-not $process.Start()){throw 'Exact supervisor launch failed'}
    $process.WaitForExit()
    $code=$process.ExitCode
}finally{$process.Dispose()}
exit $code
