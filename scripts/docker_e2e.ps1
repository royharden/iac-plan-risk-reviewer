param(
    [Parameter(Mandatory=$true)][ValidatePattern('^python:3\.12\.13-slim@sha256:[a-f0-9]{64}$')]
    [string]$BaseImage,
    [string]$PortsScript = 'C:\Users\Roy Harden\OneDrive\PJ-OD\skills\skills-bts\agent-ports\scripts\ports.py',
    [ValidatePattern('^[0-9A-Z]{4}$')][string]$Owner = '0024',
    [ValidatePattern('^r03-rv2-[a-z0-9-]+$')][string]$Instance = 'r03-rv2-e2e'
)
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
# INT must resolve any active run hold before this script is invoked. Project m4
# registration is deliberately external; never change another project's block.
& python $PortsScript claim --project m4 --instance $Instance --kind test --services e2e --owner $Owner
if ($LASTEXITCODE -ne 0) { throw 'agent-ports claim failed; no Docker build or run attempted' }
& python $PortsScript check "m4/$Instance"
if ($LASTEXITCODE -ne 0) { throw 'agent-ports check failed/unknown; no Docker build or run attempted' }
$containerName = "m4-$Instance-e2e"
$imageName = "m4-$Instance`:r03"
$labels = @('--label', 'agentports.project=m4', '--label', "agentports.instance=$Instance",
            '--label', "agentports.owner=$Owner")
# Build from a new allowlisted context, so Docker never traverses the checkout's
# .git/.venv or any credential/environment file. Preserve this M4-owned artifact.
$taskContext = Join-Path ([System.IO.Path]::GetTempPath()) ("m4-docker-context-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $taskContext | Out-Null
$relativeFiles = @('Dockerfile.r03', 'evals/requirements-runtime.txt', 'evals/__init__.py',
    'evals/run_public.py', 'evals/docker_journey.py', 'fixtures/expected/dev/rv2-policy-v1.json')
$relativeFiles += @(& git -C $taskRoot ls-files 'src/iac_review/*.py' 'src/iac_review/**/*.py')
$relativeFiles += @(Get-ChildItem -LiteralPath "$taskRoot\fixtures\scenarios\dev" -Filter '*.json' -File |
    ForEach-Object { 'fixtures/scenarios/dev/' + $_.Name })
foreach ($relativeFile in ($relativeFiles | Select-Object -Unique)) {
    $sourceFile = Join-Path $taskRoot $relativeFile
    $cursor = Get-Item -LiteralPath $sourceFile
    while ($cursor.FullName -ne $taskRoot) {
        if ($cursor.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { throw 'Linked build input refused' }
        $cursor = Get-Item -LiteralPath (Split-Path -Parent $cursor.FullName)
    }
    $destinationFile = Join-Path $taskContext $relativeFile
    New-Item -ItemType Directory -Path (Split-Path -Parent $destinationFile) -Force | Out-Null
    Copy-Item -LiteralPath $sourceFile -Destination $destinationFile
}
& docker build @labels --build-arg "PYTHON_IMAGE=$BaseImage" --file "$taskContext\Dockerfile.r03" --tag $imageName $taskContext
if ($LASTEXITCODE -ne 0) { throw 'M4 Docker build failed' }
# No host ports, mounts, Docker socket, environment imports or network access.
# Preserve the stopped container: no --rm and no cleanup/delete operation.
& docker run @labels --name $containerName --network none --read-only --cap-drop ALL `
    --security-opt no-new-privileges --memory 512m --cpus 1 `
    --tmpfs '/tmp:rw,noexec,nosuid,size=64m,mode=1777' $imageName
$result = $LASTEXITCODE
& python $PortsScript observe "m4/$Instance"
if ($result -ne 0) { throw "M4 Docker journey failed with exit $result; container preserved" }
Write-Output "M4 Docker journey passed; stopped container preserved: $containerName"
