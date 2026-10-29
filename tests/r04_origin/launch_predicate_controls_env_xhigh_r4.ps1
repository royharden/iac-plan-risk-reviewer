# UNEXECUTED. Fresh independent full method preflight and admission required.
$ErrorActionPreference='Stop'
$outerPath='C:\Users\Roy Harden\OneDrive\PJ-OD\PortfolioBuilder\iac-plan-risk-reviewer'
$suitePath='C:\Worktrees\PortfolioBuilder\iac-plan-risk-reviewer\R04-RV3-origin-env-Xhigh-r4\tests\r04_origin'
$manifestPath=Join-Path $suitePath 'predicate_method_env_xhigh_r4.json'
$manifestHash='2bc6d54e8e6f3c7baaf165d4b4bd13aa37d288c05c7481e5d78483b2b70e9b31'
$outputPath=Join-Path $suitePath 'retained\0148-env-controls-r4'
$pythonPath='C:\Worktrees\PortfolioBuilder\iac-plan-risk-reviewer\R03-RV2-eval-db\.venv\Scripts\python.exe'
if((Get-Location).Path -cne $outerPath -or (Test-Path -LiteralPath $outputPath)) {throw 'Exact OUTER/absent control output required'}
for($dir=Get-Item -LiteralPath (Split-Path -Parent $outputPath);$null -ne $dir;$dir=$dir.Parent){
    if(-not ($dir -is [IO.DirectoryInfo]) -or ($dir.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Ordinary output ancestors required'}
}
if((Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $manifestHash){throw 'Exact externally reviewed method manifest required'}
$method=Get-Content -LiteralPath $manifestPath -Raw|ConvertFrom-Json
$closure=Get-Content -LiteralPath (Join-Path $suitePath 'closure_env_xhigh_r4.json') -Raw|ConvertFrom-Json
$pinRows=@($method.inputs)+@($closure.dependencies)+@($closure.startup_configs)+@($closure.binary_DATA)
function Get-CheckedPins($rows){
    $pins=[Collections.Generic.List[object]]::new()
    foreach($row in $rows){
        $file=Get-Item -LiteralPath $row.path
        $hash=(Get-FileHash -LiteralPath $row.path -Algorithm SHA256).Hash.ToLowerInvariant()
        if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Length -ne $row.bytes -or $hash -cne $row.sha256){throw "Pinned control input differs: $($row.path)"}
        $pins.Add([ordered]@{path=$row.path;bytes=$file.Length;sha256=$hash})
    }
    return $pins.ToArray()
}
$before=Get-CheckedPins $pinRows
foreach($path in $closure.startup_absences){if(Test-Path -LiteralPath $path){throw 'Startup absence differs'}}
foreach($alias in $closure.runtime_aliases){
    $resolved=(Get-Item -LiteralPath $alias.alias).ResolveLinkTarget($true)
    if($null -eq $resolved -or $resolved.FullName -ine $alias.canonical){throw 'Pinned runtime alias differs'}
}
$arguments=@('-I','-S','-B','-X',('pycache_prefix='+(Join-Path $outputPath 'never-bytecode')),(Join-Path $suitePath 'predicate_controls_env_xhigh_r4.py'))
$environment=@{SYSTEMROOT='C:\WINDOWS';WINDIR='C:\WINDOWS';SYSTEMDRIVE='C:'}
[void](New-Item -ItemType Directory -Path $outputPath -ErrorAction Stop)
$stdout=[IO.File]::Open((Join-Path $outputPath 'stdout.txt'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
$stderr=[IO.File]::Open((Join-Path $outputPath 'stderr.txt'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
$info=[Diagnostics.ProcessStartInfo]::new()
$info.FileName=$pythonPath
$info.WorkingDirectory=$outerPath
$info.UseShellExecute=$false
$info.CreateNoWindow=$true
$info.RedirectStandardOutput=$true
$info.RedirectStandardError=$true
$info.RedirectStandardInput=$true
$info.Environment.Clear()
foreach($key in $environment.Keys){$info.Environment[$key]=$environment[$key]}
foreach($argument in $arguments){$info.ArgumentList.Add($argument)}
$process=[Diagnostics.Process]::new()
$process.StartInfo=$info
$nativeCode=$null
$ownedPid=$null
$watchdog=$false
$failures=[Collections.Generic.List[string]]::new()
$timer=[Diagnostics.Stopwatch]::StartNew()
try{
    if(-not $process.Start()){throw 'Exact source-free control launch failed'}
    $ownedPid=$process.Id
    $process.StandardInput.Close()
    $copyOut=$process.StandardOutput.BaseStream.CopyToAsync($stdout)
    $copyErr=$process.StandardError.BaseStream.CopyToAsync($stderr)
    if(-not $process.WaitForExit(10000)){
        $watchdog=$true
        $process.Kill()
        if(-not $process.WaitForExit(5000)){throw 'Owned control worker did not stop'}
    }
    $nativeCode=$process.ExitCode
    if(-not $copyOut.Wait(5000) -or -not $copyErr.Wait(5000)){throw 'Control stream retention incomplete'}
}catch{$failures.Add($_.Exception.GetType().FullName+': '+$_.Exception.Message)}
finally{
    $timer.Stop()
    $stdout.Dispose()
    $stderr.Dispose()
    $process.Dispose()
}
$after=$null
try{$after=Get-CheckedPins $pinRows}catch{$failures.Add('Post-pin check: '+$_.Exception.Message)}
$prefixAbsent=-not(Test-Path -LiteralPath (Join-Path $outputPath 'never-bytecode'))
$receipt=[ordered]@{kind='source-free-production-predicate-controls';command=@($pythonPath)+$arguments;environment=$environment;cwd=$outerPath;pid=$ownedPid;native_exit=$nativeCode;watchdog_fired=$watchdog;watchdog_seconds=10;elapsed_seconds=$timer.Elapsed.TotalSeconds;failures=$failures.ToArray();before_pins=$before;after_pins=$after;bytecode_prefix_absent=$prefixAbsent;candidate_imports_observed=$null;pytest_imports_observed=$null;count_evidence='Actual successful worker JSON required; launcher does not trace imports or native effects';actual_callstack_exercised=$false;source_acceptance=$false;cleanup='NONE_RETAINED'}
$receiptStream=[IO.File]::Open((Join-Path $outputPath 'execution.json'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
$writer=[IO.StreamWriter]::new($receiptStream,[Text.UTF8Encoding]::new($false))
try{$writer.Write(($receipt|ConvertTo-Json -Depth 15))}finally{$writer.Dispose();$receiptStream.Dispose()}
if($watchdog -or $failures.Count -ne 0 -or -not $prefixAbsent -or $null -eq $nativeCode){exit 3}
exit $nativeCode
