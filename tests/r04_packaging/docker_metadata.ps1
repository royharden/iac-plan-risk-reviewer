param(
    [Parameter(Mandatory=$true)][string]$Context,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{40}$')][string]$PackagingCommit,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{64}$')][string]$PinsSha,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{64}$')][string]$SourceSha,
    [Parameter(Mandatory=$true)][string]$Out,
    [Parameter(Mandatory=$true)][ValidatePattern('^r04-rv4-packaging-[a-z0-9-]+$')][string]$Instance
)
$ErrorActionPreference='Stop'
# Execute only after INT heavy-slot grant plus independent review of this exact
# runner/context/Dockerfile/runtime closure. This script grants nothing itself.
if (Test-Path -LiteralPath $Out) {throw 'Fresh retained output required'}
$outRoot=[IO.Path]::GetFullPath($Out)
New-Item -ItemType Directory -Path $outRoot -ErrorAction Stop|Out-Null
$checkout=Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$python=Join-Path $checkout '.venv\Scripts\python.exe'
& $python -I -B (Join-Path $PSScriptRoot 'verify_context.py') --context $Context --packaging-commit $PackagingCommit --pins-sha $PinsSha --source-sha $SourceSha --out (Join-Path $outRoot 'context-check.json')
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
& docker --config $config build @labels --file (Join-Path $Context 'Dockerfile.scanners-linux') --tag $image $Context 1> (Join-Path $outRoot 'build.stdout.txt') 2> (Join-Path $outRoot 'build.stderr.txt')
$buildExit=$LASTEXITCODE
if($buildExit -ne 0) {throw "Build failed ($buildExit); artifacts retained"}
& docker --config $config image inspect $image 1> (Join-Path $outRoot 'image.json')
if($LASTEXITCODE -ne 0) {throw 'Image inspect failed'}
& docker --config $config run @labels --name $container --network none --read-only --cap-drop ALL --security-opt no-new-privileges --memory 768m --cpus 1 --pids-limit 128 --tmpfs '/tmp:rw,noexec,nosuid,size=128m,mode=1777' $image 1> (Join-Path $outRoot 'run.stdout.txt') 2> (Join-Path $outRoot 'run.stderr.txt')
$runExit=$LASTEXITCODE
& docker --config $config inspect $container 1> (Join-Path $outRoot 'container.json')
& python $ports observe "M4/$Instance"
$record=@{packaging_commit=$PackagingCommit;context_pins_sha256=$PinsSha;source_sha256=$SourceSha;image=$image;container=$container;build_exit=$buildExit;run_exit=$runExit;primary_scans=0;product_acceptance=$false;retained=$true}
[IO.File]::WriteAllText((Join-Path $outRoot 'execution.json'),($record|ConvertTo-Json -Depth 4))
if($runExit -ne 0) {throw "Metadata container failed ($runExit); retained"}
Write-Output "Metadata run native0; retained $container. Interpret bounded report independently."
