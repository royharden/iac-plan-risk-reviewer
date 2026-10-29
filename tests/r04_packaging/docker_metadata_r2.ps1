param(
    [Parameter(Mandatory=$true)][string]$Context,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{40}$')][string]$PackagingCommit,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{64}$')][string]$PinsSha,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{64}$')][string]$SourceSha,
    [Parameter(Mandatory=$true)][string]$Python,
    [Parameter(Mandatory=$true)][string]$Verifier,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{64}$')][string]$PortsScriptSha,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{64}$')][string]$DockerClientSha,
    [Parameter(Mandatory=$true)][string]$Out,
    [Parameter(Mandatory=$true)][ValidatePattern('^r04-rv4-metadata-r2-[a-z0-9-]+$')][string]$Instance
)
$ErrorActionPreference='Stop'
# NEW EFFECT component. Never invoke without independent RV3 effect approval and
# a NEW exact INT activation record. The denied r1 runner/old conditional grant
# does not authorize this successor. No old pytest or version-probe entrypoint.
$ports='C:\Users\Roy Harden\OneDrive\PJ-OD\skills\skills-bts\agent-ports\scripts\ports.py'
$localEngine='npipe:////./pipe/dockerDesktopLinuxEngine'
$pythonSha='7f06d4ab8afee27a5fe6a273ef621758290ecbc2f7461ebaf554433efd850e5d'
$verifierSha='1f3ddaad0420ede25e32263a610c1addfca1bc2aec80ea9a285a3114109f8430'
$docker=(Get-Command docker -CommandType Application | Select-Object -First 1).Source
function Assert-Pin([string]$Path,[string]$Expected) {
    if((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $Expected) {
        throw 'Pinned tooling/input bytes differ; stop without retry'
    }
}
Assert-Pin $Python $pythonSha
Assert-Pin $Verifier $verifierSha
Assert-Pin $ports $PortsScriptSha
Assert-Pin $docker $DockerClientSha
if($PackagingCommit -ne 'd8fe3399387a6073ca4612e9a659e7560694d6de' -or
   $PinsSha -ne '040581b5d874754e68b8a2d5727463bc1fc8a4bfb5cf3a0bda7b41f7228a488e' -or
   $SourceSha -ne '0edf106a7497fc963bf0e238fcb0127f7739e65d801b6d2c1a3fbfd38e227027') {
    throw 'This edition binds only the declared D15 read-only metadata candidate'
}
$outRoot=[IO.Path]::GetFullPath($Out)
$workspace='C:\Worktrees\PortfolioBuilder\iac-plan-risk-reviewer\'
if(-not [IO.Path]::IsPathFullyQualified($Out) -or
   -not $outRoot.StartsWith($workspace,[StringComparison]::OrdinalIgnoreCase) -or
   (Test-Path -LiteralPath $outRoot)) {throw 'New absolute owned CWorktrees output required'}
$parent=[IO.DirectoryInfo]::new([IO.Path]::GetDirectoryName($outRoot))
while($null -ne $parent) {
    if(-not $parent.Exists -or ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Output parent must be existing ordinary directories'
    }
    $parent=$parent.Parent
}
New-Item -ItemType Directory -Path $outRoot -ErrorAction Stop|Out-Null
# Establish a new EMPTY config before the first process, including verifier and
# every ports.py helper. Never inspect the user's Docker config or credential store.
$config=Join-Path $outRoot 'docker-config-empty'
New-Item -ItemType Directory -Path $config -ErrorAction Stop|Out-Null
$steps=[Collections.Generic.List[object]]::new()
$claimed=$null
$container=$null
$image=$null
$phase='preflight'
$failure=$null
function Write-New([string]$Path,[string]$Text) {
    $stream=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write)
    try {
        $raw=[Text.UTF8Encoding]::new($false).GetBytes($Text)
        $stream.Write($raw,0,$raw.Length)
    } finally {$stream.Dispose()}
}
function Invoke-Owned([string]$Executable,[string[]]$Argv,[string]$Edition,[int]$Seconds) {
    $info=[Diagnostics.ProcessStartInfo]::new()
    $info.FileName=$Executable
    $info.WorkingDirectory=(Get-Location).Path
    $info.UseShellExecute=$false
    $info.CreateNoWindow=$true
    $info.WindowStyle=[Diagnostics.ProcessWindowStyle]::Hidden
    $info.RedirectStandardOutput=$true
    $info.RedirectStandardError=$true
    # A minimal environment prevents proxy/TLS/auth/context/builder overrides.
    # No credential values are read, persisted, printed or forwarded.
    $info.Environment.Clear()
    foreach($key in @('PATH','PATHEXT','SystemRoot','WINDIR','TEMP','TMP','COMSPEC','USERPROFILE','LOCALAPPDATA','CODEX_THREAD_ID')) {
        $value=[Environment]::GetEnvironmentVariable($key)
        if($null -ne $value){$info.Environment[$key]=$value}
    }
    $info.Environment['DOCKER_CONFIG']=$config
    $info.Environment['DOCKER_HOST']=$localEngine
    $info.Environment['PYTHONDONTWRITEBYTECODE']='1'
    $info.Environment['PYTHONNOUSERSITE']='1'
    foreach($item in $Argv){$info.ArgumentList.Add($item)}
    $process=[Diagnostics.Process]::new()
    $process.StartInfo=$info
    if(-not $process.Start()){throw 'Owned process failed to start'}
    $stdout=$process.StandardOutput.ReadToEndAsync()
    $stderr=$process.StandardError.ReadToEndAsync()
    $finished=$process.WaitForExit($Seconds*1000)
    if(-not $finished){$process.Kill();$process.WaitForExit()}
    $text=$stdout.GetAwaiter().GetResult()
    $errorText=$stderr.GetAwaiter().GetResult()
    Write-New (Join-Path $outRoot "$Edition.stdout.txt") $text
    Write-New (Join-Path $outRoot "$Edition.stderr.txt") $errorText
    $steps.Add(@{edition=$Edition;exe=$Executable;argv=$Argv;pid=$process.Id;
        native_exit=$process.ExitCode;timeout=(-not $finished);config=$config;engine=$localEngine})
    if(-not $finished){throw "Owned client timed out ($Edition); daemon state UNKNOWN, preserve without retry"}
    return @{ExitCode=$process.ExitCode;Text=$text}
}
function Require-Zero($Result,[string]$Stage) {
    if($Result.ExitCode -ne 0){throw "Failed $Stage; artifacts preserved, no automatic retry"}
}
function Invoke-Docker([string[]]$Argv,[string]$Edition,[int]$Seconds) {
    return Invoke-Owned $docker (@('--config',$config,'--host',$localEngine)+$Argv) $Edition $Seconds
}
try {
    $verified=Invoke-Owned $Python @('-I','-B',$Verifier,'--context',$Context,'--packaging-commit',$PackagingCommit,
        '--pins-sha',$PinsSha,'--source-sha',$SourceSha,'--out',(Join-Path $outRoot 'context-check.json')) 'context-check' 180
    Require-Zero $verified 'exact context'
    $phase='claim'
    $result=Invoke-Owned $Python @('-I','-B',$ports,'claim','--project','m4','--instance',$Instance,
        '--kind','test','--services','e2e','--owner','0117','--bind','127.0.0.1','--json') 'claim' 180
    Require-Zero $result 'canonical claim'
    $claimed=$result.Text|ConvertFrom-Json
    if($claimed.project -ne 'm4' -or $claimed.instance -ne $Instance -or $claimed.bind -ne '127.0.0.1') {
        throw 'Canonical claim identity/bind mismatch'
    }
    $expectedLabels=@('agentports.project=m4',"agentports.instance=$Instance",'agentports.owner=0117')
    if(@($claimed.labels).Count -ne 3 -or @(Compare-Object $expectedLabels @($claimed.labels)).Count -ne 0) {
        throw 'Unexpected canonical claim labels or owner'
    }
    foreach($property in $claimed.ports.PSObject.Properties) {
        if($property.Value -lt 22100 -or $property.Value -gt 22199){throw 'Claim outside M4 block'}
    }
    if(@($claimed.names.containers).Count -ne 1){throw 'Expected one canonical owned container name'}
    $container=$claimed.names.containers[0]
    if($container -ne "m4-$Instance-e2e"){throw 'Canonical container name mismatch'}
    $image="m4-$Instance`:metadata-r2"
    $labels=@()
    foreach($label in $claimed.labels){$labels+=@('--label',[string]$label)}
    $result=Invoke-Owned $Python @('-I','-B',$ports,'check',"m4/$Instance") 'ports-check' 180
    Require-Zero $result 'ports check (UNKNOWN blocks)'
    $existing=Invoke-Docker @('container','ls','--all','--filter',"name=^/$container$",'--format','{{.ID}}') 'container-name-check' 30
    Require-Zero $existing 'new container name check'
    if($existing.Text.Trim()){throw 'Owned name exists; preserve, do not restart or overwrite'}
    $existing=Invoke-Docker @('image','ls','--filter',"reference=$image",'--quiet') 'image-name-check' 30
    Require-Zero $existing 'new image name check'
    if($existing.Text.Trim()){throw 'Owned image tag exists; preserve, do not retag'}
    $phase='build'
    $result=Invoke-Docker (@('build')+$labels+@('--file',(Join-Path $Context 'Dockerfile.scanners-linux'),'--tag',$image,$Context)) 'build' 900
    Require-Zero $result 'one metadata build'
    $result=Invoke-Docker @('image','inspect',$image) 'image-inspect' 30
    Require-Zero $result 'image identity'
    $imageInfo=@($result.Text|ConvertFrom-Json)[0]
    $expectedEntry=@('/opt/m4-core/bin/python','-I','-B','/opt/m4/product/evals/scanners/linux_readiness.py','image-metadata')
    if($imageInfo.Config.User -cne '65532:65532' -or
       (@($imageInfo.Config.Entrypoint) -join "`n") -cne ($expectedEntry -join "`n")) {
        throw 'Built image user/entrypoint differs from the read-only metadata contract'
    }
    $phase='run'
    $result=Invoke-Docker (@('run')+$labels+@('--name',$container,'--network','none','--read-only','--user','65532:65532',
        '--cap-drop','ALL','--security-opt','no-new-privileges','--memory','768m','--cpus','1','--pids-limit','128',
        '--tmpfs','/tmp:rw,noexec,nosuid,size=128m,mode=1777',$image,
        '--packaging-commit',$PackagingCommit,'--source-sha',$SourceSha)) 'run' 180
    $runExit=$result.ExitCode
    $inspection=Invoke-Docker @('container','inspect',$container) 'container-inspect' 30
    Require-Zero $inspection 'owned container observation'
    $observed=Invoke-Owned $Python @('-I','-B',$ports,'observe',"m4/$Instance") 'ports-observe' 180
    Require-Zero $observed 'ledger observation'
    Require-Zero $result 'one read-only metadata run'
    $report=$result.Text|ConvertFrom-Json
    if($report.kind -cne 'm4-readonly-image-metadata-v1' -or
       $report.passed -isnot [bool] -or $report.passed -ne $true -or
       $report.packaging_commit -cne $PackagingCommit -or $report.source_receipt_sha256 -cne $SourceSha -or
       ($report.primary_scans -isnot [long] -and $report.primary_scans -isnot [int]) -or
       $report.primary_scans -ne 0 -or $report.product_acceptance -isnot [bool] -or
       $report.product_acceptance -ne $false) {
        throw 'Unexpected bounded read-only metadata report'
    }
    $phase='complete'
} catch {
    $failure=$_.Exception.Message
    throw
} finally {
    $receipt=@{kind='rv4-docker-effect-runner-r2';phase=$phase;failure=$failure;steps=$steps;
        packaging_commit=$PackagingCommit;context_pins_sha256=$PinsSha;source_sha256=$SourceSha;
        canonical_claim=$claimed;container=$container;image=$image;runtime_mode='image-metadata only';
        old168_tests='NOT_RUN_HELD';resources_retained=$true;product_acceptance=$false}
    Write-New (Join-Path $outRoot 'execution.json') ($receipt|ConvertTo-Json -Depth 10)
}
