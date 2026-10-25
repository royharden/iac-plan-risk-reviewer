param(
    [Parameter(Mandatory=$true)][string]$EvidenceDirectory,
    [string]$D11Root = 'C:\Worktrees\PortfolioBuilder\iac-plan-risk-reviewer\R03-D11-scanner-dev',
    [ValidatePattern('^r03-rv2-[a-z0-9-]+$')][string]$Instance = 'r03-rv2-scanners-prep',
    [string]$PortsScript = 'C:\Users\Roy Harden\OneDrive\PJ-OD\skills\skills-bts\agent-ports\scripts\ports.py'
)
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$taskRoot = Split-Path -Parent $PSScriptRoot
$candidate = '1e59284f4180adfe75848943d3fb21f9d308afc8'
$requirementsHash = '3bc130464fd7c4e7c17a2bf8441cbe046cee0db4aa067ea64433da6c368c44d2'

function Assert-RegularDirectoryChain([string]$Path) {
    # Walk from the root, never through an unchecked linked ancestor.
    $full = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetPathRoot($full)
    $cursor = $root
    $parts = @($full.Substring($root.Length).Split([char[]]@('\','/'), [StringSplitOptions]::RemoveEmptyEntries))
    foreach ($part in @('') + $parts) {
        if ($part) { $cursor = Join-Path $cursor $part }
        $item = Get-Item -LiteralPath $cursor -Force
        if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Regular existing directory ancestors required; linked ancestor refused'
        }
    }
}

if (-not [IO.Path]::IsPathFullyQualified($EvidenceDirectory)) { throw 'Absolute evidence directory required' }
if (@($EvidenceDirectory.Split([char[]]@('\','/')) | Where-Object { $_ -eq '..' }).Count) { throw 'Evidence path traversal refused' }
$EvidenceDirectory = [IO.Path]::GetFullPath($EvidenceDirectory)
Assert-RegularDirectoryChain (Split-Path -Parent $EvidenceDirectory)
if (Test-Path -LiteralPath $EvidenceDirectory) { throw 'Fresh evidence directory required' }
$inputs = @(
    @{source=(Join-Path $taskRoot 'Dockerfile.scanners'); target='Dockerfile.scanners'},
    @{source=(Join-Path $taskRoot 'evals/scanners/version_probe.py'); target='probe.py'},
    @{source=(Join-Path $D11Root 'eval/scanners/checkov-3.3.30.requirements.txt'); target='pins/checkov.requirements.txt'}
)
foreach ($entry in $inputs) {
    $cursor = Get-Item -LiteralPath $entry.source
    if ($cursor.PSIsContainer -or ($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Regular input file required' }
    $cursor = $cursor.Directory
    while ($null -ne $cursor) {
        if ($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Linked build ancestor refused' }
        $cursor = $cursor.Parent
    }
}
if ((Get-FileHash -LiteralPath $inputs[2].source -Algorithm SHA256).Hash.ToLowerInvariant() -ne $requirementsHash) { throw 'D11 lock bytes changed' }
# No Force: an existing destination fails rather than being reused. Parent must
# already exist. This is exclusive leaf creation, not immunity to ancestor races.
New-Item -ItemType Directory -Path $EvidenceDirectory -ErrorAction Stop | Out-Null
Assert-RegularDirectoryChain $EvidenceDirectory
$commandExits = [Collections.Generic.List[object]]::new()
function Invoke-Recorded([string]$Command, [string[]]$Arguments, [string]$Receipt, [switch]$AllowFailure) {
    [IO.File]::WriteAllText((Join-Path $EvidenceDirectory $Receipt), '')
    $global:LASTEXITCODE = $null
    & $Command @Arguments 2>&1 | Set-Content -LiteralPath (Join-Path $EvidenceDirectory $Receipt)
    $exitCode = $global:LASTEXITCODE
    $commandExits.Add(@{command=$Command; argv=$Arguments; exit_code=$exitCode; receipt=$Receipt})
    ConvertTo-Json -InputObject @($commandExits) -Depth 8 | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'command-exits.json')
    if ($null -eq $exitCode -or ($exitCode -ne 0 -and -not $AllowFailure)) { throw "Required command failed: $Command ($Receipt), exit $exitCode" }
}
function Read-RequiredJson([string]$Receipt) {
    $raw = Get-Content -LiteralPath (Join-Path $EvidenceDirectory $Receipt) -Raw
    if ([string]::IsNullOrWhiteSpace($raw)) { throw "Missing receipt content: $Receipt" }
    return ConvertFrom-Json -InputObject $raw -ErrorAction Stop
}
function Assert-Labels($Labels) {
    if ($Labels.'agentports.project' -ne 'm4' -or $Labels.'agentports.instance' -ne $Instance -or $Labels.'agentports.owner' -ne '0024') { throw 'Resource labels do not match selected instance' }
}
function Assert-StreamReceipt($Stream) {
    if ($null -eq $Stream -or ($Stream.bytes -isnot [long] -and $Stream.bytes -isnot [int]) -or $Stream.bytes -lt 0 -or $Stream.bytes -gt 67108864 -or $Stream.sha256 -cnotmatch '^[a-f0-9]{64}$' -or $Stream.base64_prefix -isnot [string] -or $Stream.prefix_truncated -isnot [bool]) { throw 'Missing or malformed raw stream receipt' }
    $bytes = [Convert]::FromBase64String($Stream.base64_prefix)
    if ($Stream.prefix_truncated) {
        if ($Stream.bytes -le 65536 -or $bytes.Length -ne 65536) { throw 'Invalid truncated stream receipt' }
    } else {
        if ($Stream.bytes -ne $bytes.Length -or $bytes.Length -gt 65536) { throw 'Invalid complete stream receipt length' }
        $hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
        if ($hash -cne $Stream.sha256) { throw 'Raw stream receipt hash mismatch' }
    }
}
$labels = @('--label','agentports.project=m4','--label',"agentports.instance=$Instance",'--label','agentports.owner=0024')
$imageName = "m4-$Instance`:r03"
$containerName = "m4-$Instance-e2e"
try {
    Invoke-Recorded git @('-C',$D11Root,'rev-parse','HEAD') 'source-head.txt'
    if ((Get-Content -LiteralPath (Join-Path $EvidenceDirectory 'source-head.txt') -Raw).Trim() -ne $candidate) { throw 'D11 candidate changed' }
    # Check both selected names before build can retag a retained image.
    Invoke-Recorded docker @('image','ls','--quiet','--no-trunc','--filter',"reference=$imageName") 'existing-image.txt'
    if (-not [string]::IsNullOrWhiteSpace((Get-Content -LiteralPath (Join-Path $EvidenceDirectory 'existing-image.txt') -Raw))) { throw 'Existing instance image refused; preserved' }
    Invoke-Recorded docker @('container','ls','--all','--quiet','--no-trunc','--filter',"name=^/$containerName`$") 'existing-container.txt'
    if (-not [string]::IsNullOrWhiteSpace((Get-Content -LiteralPath (Join-Path $EvidenceDirectory 'existing-container.txt') -Raw))) { throw 'Existing instance container refused; preserved' }
    Invoke-Recorded python @($PortsScript,'claim','--project','m4','--instance',$Instance,'--kind','test','--services','e2e','--owner','0024') 'ports-claim.log'
    Invoke-Recorded python @($PortsScript,'check',"m4/$Instance") 'ports-check.log'
    $taskContext = Join-Path $EvidenceDirectory 'context'
    New-Item -ItemType Directory -Path (Join-Path $taskContext 'pins') | Out-Null
    foreach ($entry in $inputs) { Copy-Item -LiteralPath $entry.source -Destination (Join-Path $taskContext $entry.target) }
    $source = @{d11_candidate=$candidate; requirements_sha256=$requirementsHash; primary_scans=0}
    [IO.File]::WriteAllText((Join-Path $taskContext 'pins/source.json'), ($source | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
    $hashes = @(Get-ChildItem -LiteralPath $taskContext -Recurse -File | ForEach-Object {
        @{path=$_.FullName.Substring($taskContext.Length+1); sha256=(Get-FileHash -LiteralPath $_.FullName).Hash.ToLowerInvariant()}
    })
    $hashes | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'context-hashes.json')
    Invoke-Recorded docker (@('build') + $labels + @('--progress','plain','--file',(Join-Path $taskContext 'Dockerfile.scanners'),'--iidfile',(Join-Path $EvidenceDirectory 'build-image-id.txt'),'--tag',$imageName,$taskContext)) 'build.log'
    $imageId = (Get-Content -LiteralPath (Join-Path $EvidenceDirectory 'build-image-id.txt') -Raw).Trim()
    if ($imageId -cnotmatch '^sha256:[a-f0-9]{64}$') { throw 'Missing or malformed immutable image ID' }
    Invoke-Recorded docker @('image','inspect',$imageName) 'image.json'
    $images = @(Read-RequiredJson 'image.json')
    if ($images.Count -ne 1 -or $images[0].Id -cne $imageId) { throw 'Image receipt identity mismatch' }
    Assert-Labels $images[0].Config.Labels
    Invoke-Recorded docker (@('run') + $labels + @('--name',$containerName,'--cidfile',(Join-Path $EvidenceDirectory 'container-id.txt'),'--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','768m','--cpus','1','--tmpfs','/tmp:rw,noexec,nosuid,size=64m,mode=1777',$imageId)) 'run.log' -AllowFailure
    $probeExit = $commandExits[$commandExits.Count - 1].exit_code
    $containerId = (Get-Content -LiteralPath (Join-Path $EvidenceDirectory 'container-id.txt') -Raw).Trim()
    if ($containerId -cnotmatch '^[a-f0-9]{64}$') { throw 'Missing or malformed immutable container ID' }
    Invoke-Recorded docker @('logs',$containerId) 'version-probes.log'
    Invoke-Recorded docker @('inspect',$containerId) 'container.json'
    Invoke-Recorded python @($PortsScript,'observe',"m4/$Instance") 'ports-observe.log'
    if ($probeExit -ne 0) { throw "Metadata probe failed exit $probeExit; evidence and stopped container preserved" }
    $containers = @(Read-RequiredJson 'container.json')
    if ($containers.Count -ne 1) { throw 'Exactly one container receipt required' }
    $container = $containers[0]
    if ($container.Id -cne $containerId -or $container.Image -cne $imageId -or $container.Name -cne "/$containerName" -or $container.State.ExitCode -ne 0 -or $container.State.Running -ne $false -or $container.State.OOMKilled -ne $false) { throw 'Container receipt identity or exit state mismatch' }
    Assert-Labels $container.Config.Labels
    $report = Read-RequiredJson 'version-probes.log'
    if ($report.kind -cne 'm4-offline-metadata-probes' -or $null -eq $report.primary_scans -or $report.primary_scans -ne 0 -or $report.requirements_sha256 -cne $requirementsHash -or $report.source.d11_candidate -cne $candidate -or $report.source.requirements_sha256 -cne $requirementsHash -or $null -eq $report.source.primary_scans -or $report.source.primary_scans -ne 0) { throw 'Probe receipt source mismatch' }
    $names = @('checkov-version','trivy-version','checkov-dependencies')
    if (@($report.probes).Count -ne 3) { throw 'Three metadata probes required' }
    foreach ($name in $names) {
        $probes = @($report.probes | Where-Object { $_.name -ceq $name })
        if ($probes.Count -ne 1 -or $probes[0].status -cne 'completed' -or $null -eq $probes[0].exit_code -or $probes[0].exit_code -ne 0) { throw 'Missing or failed metadata probe receipt' }
        Assert-StreamReceipt $probes[0].stdout
        Assert-StreamReceipt $probes[0].stderr
    }
    @{probe_exit=$probeExit; image=$imageName; image_id=$imageId; container=$containerName; container_id=$containerId; primary_scans=0} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'result.json')
} catch {
    @{status='failed'; error=$_.ToString(); image=$imageName; container=$containerName; primary_scans=0} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'failure.json')
    throw
}
