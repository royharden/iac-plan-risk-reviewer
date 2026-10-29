param(
    [Parameter(Mandatory=$true)][string]$Context,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{40}$')][string]$PackagingCommit,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{64}$')][string]$PinsSha,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{64}$')][string]$SourceSha,
    [Parameter(Mandatory=$true)][string]$Python,
    [Parameter(Mandatory=$true)][string]$Out,
    [Parameter(Mandatory=$true)][ValidatePattern('^r04-rv4-packaging-[a-z0-9-]+$')][string]$Instance
)
$ErrorActionPreference='Stop'
# Execute only after INT heavy-slot grant plus independent review of this exact
# runner/context/Dockerfile/runtime closure. This script grants nothing itself.
if (Test-Path -LiteralPath $Out) {throw 'Fresh retained output required'}
$outRoot=[IO.Path]::GetFullPath($Out)
New-Item -ItemType Directory -Path $outRoot -ErrorAction Stop|Out-Null
& $Python -I -B (Join-Path $PSScriptRoot 'verify_context.py') --context $Context --packaging-commit $PackagingCommit --pins-sha $PinsSha --source-sha $SourceSha --out (Join-Path $outRoot 'context-check.json')
if($LASTEXITCODE -ne 0) {throw 'Pinned context validation failed'}
$ports='C:\Users\Roy Harden\OneDrive\PJ-OD\skills\skills-bts\agent-ports\scripts\ports.py'
$owner='0117_Codex_gpt-61-sol_RV4'
& python $ports claim --project M4 --instance $Instance --kind test --services metadata --owner $owner
if($LASTEXITCODE -ne 0) {throw 'M4 claim failed'}
& python $ports check "M4/$Instance"
if($LASTEXITCODE -ne 0) {throw 'M4 resource check failed or unknown'}
$image="m4-$Instance`:metadata"
$container="m4-$Instance-metadata"
$labels=@('--label','agentports.project=M4','--label',"agentports.instance=$Instance",'--label',"agentports.owner=$owner")
# Empty new Docker config prevents reading the user's registry credentials.
$config=Join-Path $outRoot 'docker-config-empty'
New-Item -ItemType Directory -Path $config -ErrorAction Stop|Out-Null
function Invoke-OwnedDocker([string[]]$DockerArgs,[string]$Edition,[int]$TimeoutSeconds) {
    $info=[Diagnostics.ProcessStartInfo]::new()
    $info.FileName=(Get-Command docker -CommandType Application).Source
    $info.UseShellExecute=$false
    $info.CreateNoWindow=$true
    $info.WindowStyle=[Diagnostics.ProcessWindowStyle]::Hidden
    $info.RedirectStandardOutput=$true
    $info.RedirectStandardError=$true
    foreach($item in (@('--config',$config)+$DockerArgs)) {$info.ArgumentList.Add($item)}
    $process=[Diagnostics.Process]::new()
    $process.StartInfo=$info
    if(-not $process.Start()){throw 'Owned Docker client failed to start'}
    $stdout=$process.StandardOutput.ReadToEndAsync()
    $stderr=$process.StandardError.ReadToEndAsync()
    $finished=$process.WaitForExit($TimeoutSeconds*1000)
    if(-not $finished){$process.Kill();$process.WaitForExit()}
    [IO.File]::WriteAllText((Join-Path $outRoot "$Edition.stdout.txt"),$stdout.GetAwaiter().GetResult())
    [IO.File]::WriteAllText((Join-Path $outRoot "$Edition.stderr.txt"),$stderr.GetAwaiter().GetResult())
    if(-not $finished){throw "Owned Docker client timed out; container/image state unknown, preserve and report ($Edition)"}
    return $process.ExitCode
}
$buildExit=Invoke-OwnedDocker (@('build')+$labels+@('--file',(Join-Path $Context 'Dockerfile.scanners-linux'),'--tag',$image,$Context)) 'build' 900
if($buildExit -ne 0) {throw "Build failed ($buildExit); artifacts retained"}
& docker --config $config image inspect $image 1> (Join-Path $outRoot 'image.json')
if($LASTEXITCODE -ne 0) {throw 'Image inspect failed'}
$runExit=Invoke-OwnedDocker (@('run')+$labels+@('--name',$container,'--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','768m','--cpus','1','--pids-limit','128','--tmpfs','/tmp:rw,noexec,nosuid,size=128m,mode=1777',$image)) 'run' 180
& docker --config $config inspect $container 1> (Join-Path $outRoot 'container.json')
& python $ports observe "M4/$Instance"
$record=@{packaging_commit=$PackagingCommit;context_pins_sha256=$PinsSha;source_sha256=$SourceSha;image=$image;container=$container;build_exit=$buildExit;run_exit=$runExit;primary_scans=0;product_acceptance=$false;retained=$true}
[IO.File]::WriteAllText((Join-Path $outRoot 'execution.json'),($record|ConvertTo-Json -Depth 4))
if($runExit -ne 0) {throw "Metadata container failed ($runExit); retained"}
Write-Output "Metadata run native0; retained $container. Interpret bounded report independently."
