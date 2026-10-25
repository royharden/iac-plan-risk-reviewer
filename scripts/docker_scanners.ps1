param(
    [Parameter(Mandatory=$true)][string]$EvidenceDirectory,
    [string]$D11Root = 'C:\Worktrees\PortfolioBuilder\iac-plan-risk-reviewer\R03-D11-scanner-dev',
    [ValidatePattern('^r03-rv2-[a-z0-9-]+$')][string]$Instance = 'r03-rv2-scanners-prep',
    [string]$PortsScript = 'C:\Users\Roy Harden\OneDrive\PJ-OD\skills\skills-bts\agent-ports\scripts\ports.py'
)
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
$candidate = '1e59284f4180adfe75848943d3fb21f9d308afc8'
$requirementsHash = '3bc130464fd7c4e7c17a2bf8441cbe046cee0db4aa067ea64433da6c368c44d2'
if ((& git -C $D11Root rev-parse HEAD) -ne $candidate) { throw 'D11 candidate changed' }
if (-not [System.IO.Path]::IsPathFullyQualified($EvidenceDirectory)) { throw 'Absolute evidence directory required' }
if (Test-Path -LiteralPath $EvidenceDirectory) { throw 'Fresh evidence directory required' }
# Every copied input and ancestor is checked before any Docker operation.
$inputs = @(
    @{source=(Join-Path $taskRoot 'Dockerfile.scanners'); target='Dockerfile.scanners'},
    @{source=(Join-Path $taskRoot 'evals/scanners/version_probe.py'); target='probe.py'},
    @{source=(Join-Path $D11Root 'eval/scanners/checkov-3.3.30.requirements.txt'); target='pins/checkov.requirements.txt'}
)
foreach ($entry in $inputs) {
    $cursor = Get-Item -LiteralPath $entry.source
    if ($cursor.PSIsContainer) { throw 'Regular input file required' }
    if ($cursor.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { throw 'Linked build input refused' }
    $cursor = $cursor.Directory
    while ($null -ne $cursor) {
        if ($cursor.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { throw 'Linked build ancestor refused' }
        $cursor = $cursor.Parent
    }
}
if ((Get-FileHash -LiteralPath $inputs[2].source -Algorithm SHA256).Hash.ToLowerInvariant() -ne $requirementsHash) { throw 'D11 lock bytes changed' }
& python $PortsScript claim --project m4 --instance $Instance --kind test --services e2e --owner 0024
if ($LASTEXITCODE -ne 0) { throw 'Port claim failed' }
& python $PortsScript check "m4/$Instance"
if ($LASTEXITCODE -ne 0) { throw 'Port preflight blocked or unknown' }
$taskContext = Join-Path $EvidenceDirectory 'context'
New-Item -ItemType Directory -Path (Join-Path $taskContext 'pins') | Out-Null
foreach ($entry in $inputs) { Copy-Item -LiteralPath $entry.source -Destination (Join-Path $taskContext $entry.target) }
$source = @{d11_candidate=$candidate; requirements_sha256=$requirementsHash; primary_scans=0}
[System.IO.File]::WriteAllText((Join-Path $taskContext 'pins/source.json'), ($source | ConvertTo-Json), [System.Text.UTF8Encoding]::new($false))
$hashes = @(Get-ChildItem -LiteralPath $taskContext -Recurse -File | ForEach-Object {
    @{path=$_.FullName.Substring($taskContext.Length+1); sha256=(Get-FileHash -LiteralPath $_.FullName).Hash.ToLowerInvariant()}
})
$hashes | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'context-hashes.json')
$labels = @('--label','agentports.project=m4','--label',"agentports.instance=$Instance",'--label','agentports.owner=0024')
$imageName = "m4-$Instance`:r03"
$containerName = "m4-$Instance-e2e"
& docker build @labels --progress plain --file (Join-Path $taskContext 'Dockerfile.scanners') --tag $imageName $taskContext 2>&1 | Tee-Object -FilePath (Join-Path $EvidenceDirectory 'build.log')
if ($LASTEXITCODE -ne 0) { throw 'Hashlocked metadata image build failed; no fallback attempted' }
& docker image inspect $imageName | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'image.json')
& docker run @labels --name $containerName --network none --read-only --cap-drop ALL --security-opt no-new-privileges --memory 768m --cpus 1 --tmpfs '/tmp:rw,noexec,nosuid,size=64m,mode=1777' $imageName
$probeExit = $LASTEXITCODE
& docker logs $containerName 2>&1 | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'version-probes.log')
& docker inspect $containerName | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'container.json')
& python $PortsScript observe "m4/$Instance"
@{probe_exit=$probeExit; image=$imageName; container=$containerName; primary_scans=0} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'result.json')
if ($probeExit -ne 0) { throw "Metadata probe failed exit $probeExit; evidence and stopped container preserved" }
