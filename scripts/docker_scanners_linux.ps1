param(
    [Parameter(Mandatory=$true)][string]$EvidenceDirectory,
    [string]$CacheRoot = 'C:\Users\Roy Harden\OneDrive\PJ-OD\PortfolioBuilder\iac-plan-risk-reviewer\agentops\runs\PB-M4-R03\evals\RV2-trivy-cache-acquisition-r1\cache\policy',
    [string]$TreeManifest = 'C:\Users\Roy Harden\OneDrive\PJ-OD\PortfolioBuilder\iac-plan-risk-reviewer\agentops\runs\PB-M4-R03\requests\D11-Trivy-bundle-tree-candidate-r1.json',
    [ValidatePattern('^r03-rv2-linux-tree-cb298[a-z0-9-]*$')][string]$Instance = 'r03-rv2-linux-tree-cb298',
    [string]$PortsScript = 'C:\Users\Roy Harden\OneDrive\PJ-OD\skills\skills-bts\agent-ports\scripts\ports.py'
)
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$taskRoot = Split-Path -Parent $PSScriptRoot
# Guard definitions copied exactly from reviewed ebbc/cb298 launcher (EOL ignored).
# Original launcher bytes remain unchanged. No primary scanner command is exposed.
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

function Assert-PortsObservation {
    $raw = Get-Content -LiteralPath (Join-Path $EvidenceDirectory 'ports-observe.log') -Raw
    if ([string]::IsNullOrWhiteSpace($raw)) { throw 'Missing ports observation receipt' }
    # Canonical ports.py cmd_observe prints one summary; ref() uppercases project.
    # This fresh instance must have exactly its one stopped probe container.
    $expected = "M4/$Instance`: stopped (docker ok, listeners ok; 1 container(s) matched)"
    $pattern = '\A' + [regex]::Escape($expected) + '(?:\r?\n)?\z'
    if (-not [regex]::IsMatch($raw, $pattern)) {
        throw 'Ports observation must confirm the selected instance, stopped state, known sources and exactly one matched container'
    }
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

function Assert-ClosedContext([string]$Context) {
    $pins = Read-RequiredJson 'context-pins.json'
    $expectedDirectories = @{}
    foreach ($entry in $pins.PSObject.Properties) {
        $relative = $entry.Name
        while ($relative.Contains('/')) {
            $relative = $relative.Substring(0,$relative.LastIndexOf('/'))
            $expectedDirectories[$relative] = $true
        }
    }
    Assert-RegularDirectoryChain $Context
    $actualFiles = @(Get-ChildItem -LiteralPath $Context -Recurse -File -Force)
    if ($actualFiles.Count -ne @($pins.PSObject.Properties).Count) { throw 'Unlisted/missing context file' }
    foreach ($item in $actualFiles) {
        Assert-RegularDirectoryChain $item.Directory.FullName
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Linked context file' }
        $relative = $item.FullName.Substring($Context.Length+1).Replace('\','/')
        $expected = $pins.PSObject.Properties[$relative]
        if ($null -eq $expected -or $item.Length -ne $expected.Value.bytes -or (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expected.Value.sha256) { throw 'Context file identity changed' }
    }
    $actualDirectories = @(Get-ChildItem -LiteralPath $Context -Recurse -Directory -Force)
    if ($actualDirectories.Count -ne $expectedDirectories.Count) { throw 'Unlisted/missing context directory' }
    foreach ($directory in $actualDirectories) {
        Assert-RegularDirectoryChain $directory.FullName
        $relative = $directory.FullName.Substring($Context.Length+1).Replace('\','/')
        if (-not $expectedDirectories.ContainsKey($relative)) { throw 'Unlisted context directory' }
    }
}

function Invoke-LinuxDocker([string[]]$Arguments, [string]$Receipt, [switch]$AllowFailure) {
    Invoke-Recorded docker (@('--context','desktop-linux') + $Arguments) $Receipt -AllowFailure:$AllowFailure
}

function Save-LinuxDiagnostics($Report) {
    # Preserve every independently valid reporter before considering success.
    $failures = [Collections.Generic.List[string]]::new()
    $diagnostics = $Report.diagnostics
    ConvertTo-Json -InputObject $diagnostics -Depth 12 | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'reporter-status.json')
    if ($diagnostics.schema_version -cne 'm4-linux-readiness-diagnostics-v1') { $failures.Add('Missing/unknown diagnostic schema') }
    foreach ($name in @('pytest.xml','pytest.log','imports.json')) {
        try {
            $status = $diagnostics.reporters.$name
            $artifact = $Report.artifacts.$name
            if ($status.status -cne 'complete') { $failures.Add("Incomplete reporter: $name ($($status.status))") }
            if ($null -eq $artifact) { $failures.Add("Missing reporter bytes: $name"); continue }
            if (($artifact.bytes -isnot [long] -and $artifact.bytes -isnot [int]) -or $artifact.bytes -lt 0 -or $artifact.bytes -gt 2097152 -or $artifact.base64 -isnot [string] -or $artifact.sha256 -cnotmatch '^[a-f0-9]{64}$') { throw 'Malformed/over-cap reporter' }
            if ($artifact.base64.Length -ne (4 * [Math]::Ceiling($artifact.bytes / 3.0))) { throw 'Reporter encoded length mismatch' }
            $raw = [Convert]::FromBase64String($artifact.base64)
            $hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($raw)).ToLowerInvariant()
            if ($raw.Length -ne $artifact.bytes -or $hash -cne $artifact.sha256) { throw 'Reporter byte/hash mismatch' }
            [IO.File]::WriteAllBytes((Join-Path $EvidenceDirectory $name),$raw)
            if (($status.source_bytes -isnot [long] -and $status.source_bytes -isnot [int]) -or $status.cap_bytes -ne 1048576 -or $status.retained_bytes -ne $raw.Length -or $raw.Length -gt $status.cap_bytes -or ($status.status -ceq 'complete' -and $status.source_bytes -ne $raw.Length) -or ($status.status -ceq 'truncated' -and ($status.source_bytes -le $raw.Length -or $raw.Length -ne $status.cap_bytes))) { throw 'Reporter status/length mismatch' }
        } catch {
            $failures.Add("Invalid reporter: $name ($($_.ToString()))")
        }
    }
    ConvertTo-Json -InputObject @($failures) -Depth 4 | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'reporter-failures.json')
    return $failures.Count -eq 0
}

if (-not [IO.Path]::IsPathFullyQualified($EvidenceDirectory)) { throw 'Absolute evidence directory required' }
if (@($EvidenceDirectory.Split([char[]]@('\','/')) | Where-Object { $_ -eq '..' }).Count) { throw 'Evidence traversal refused' }
$EvidenceDirectory = [IO.Path]::GetFullPath($EvidenceDirectory)
Assert-RegularDirectoryChain (Split-Path -Parent $EvidenceDirectory)
if (Test-Path -LiteralPath $EvidenceDirectory) { throw 'Fresh evidence directory required' }
New-Item -ItemType Directory -Path $EvidenceDirectory -ErrorAction Stop | Out-Null
Assert-RegularDirectoryChain $EvidenceDirectory
$commandExits = [Collections.Generic.List[object]]::new()
$labels = @('--label','agentports.project=m4','--label',"agentports.instance=$Instance",'--label','agentports.owner=0024')
$imageName = "m4-$Instance`:r03"
$containerName = "m4-$Instance-e2e"
try {
    Invoke-Recorded git @('-C',$taskRoot,'rev-parse','HEAD') 'packaging-head.txt'
    $packagingHead = (Get-Content -LiteralPath (Join-Path $EvidenceDirectory 'packaging-head.txt') -Raw).Trim()
    Invoke-Recorded git @('-C',$taskRoot,'diff','--quiet','HEAD') 'source-clean.txt'
    Invoke-Recorded git @('-C',$taskRoot,'merge-base','--is-ancestor','cb298a8a96749ae633f108f61b62515732faf1fe','HEAD') 'base-ancestry.txt'
    Invoke-LinuxDocker @('context','show') 'docker-context.txt'
    if ((Get-Content -LiteralPath (Join-Path $EvidenceDirectory 'docker-context.txt') -Raw).Trim() -cne 'desktop-linux') { throw 'Expected local desktop-linux context' }
    Invoke-LinuxDocker @('context','inspect','desktop-linux','--format','{{json .Endpoints.docker.Host}}') 'docker-endpoint.json'
    if ((Read-RequiredJson 'docker-endpoint.json') -cne 'npipe:////./pipe/dockerDesktopLinuxEngine') { throw 'Expected local Linux engine endpoint' }
    Invoke-LinuxDocker @('image','ls','--quiet','--no-trunc','--filter',"reference=$imageName") 'existing-image.txt'
    if (-not [string]::IsNullOrWhiteSpace((Get-Content -LiteralPath (Join-Path $EvidenceDirectory 'existing-image.txt') -Raw))) { throw 'Retained image identity refused' }
    Invoke-LinuxDocker @('container','ls','--all','--quiet','--no-trunc','--filter',"name=^/$containerName`$") 'existing-container.txt'
    if (-not [string]::IsNullOrWhiteSpace((Get-Content -LiteralPath (Join-Path $EvidenceDirectory 'existing-container.txt') -Raw))) { throw 'Retained container identity refused' }
    Invoke-Recorded python @($PortsScript,'claim','--project','m4','--instance',$Instance,'--kind','test','--services','e2e','--owner','0024') 'ports-claim.log'
    Invoke-Recorded python @($PortsScript,'check',"m4/$Instance") 'ports-check.log'
    $context = Join-Path $EvidenceDirectory 'context'
    Invoke-Recorded python @('-B',(Join-Path $taskRoot 'evals/scanners/linux_readiness.py'),'stage','--root',$taskRoot,'--context',$context,'--cache',$CacheRoot,'--manifest',$TreeManifest) 'stage.json'
    $stage = Read-RequiredJson 'stage.json'
    if ($stage.source -cne 'cb298a8a96749ae633f108f61b62515732faf1fe' -or $stage.packaging -cne $packagingHead -or $stage.primary_scans -ne 0) { throw 'Staged source identity mismatch' }
    Assert-ClosedContext $context
    Invoke-LinuxDocker (@('build') + $labels + @('--platform','linux/amd64','--progress','plain','--file',(Join-Path $context 'Dockerfile.scanners-linux'),'--iidfile',(Join-Path $EvidenceDirectory 'build-image-id.txt'),'--tag',$imageName,$context)) 'build.log'
    $imageId = (Get-Content -LiteralPath (Join-Path $EvidenceDirectory 'build-image-id.txt') -Raw).Trim()
    if ($imageId -cnotmatch '^sha256:[a-f0-9]{64}$') { throw 'Immutable image ID missing' }
    Invoke-LinuxDocker @('image','inspect',$imageId) 'image.json'
    $images = @(Read-RequiredJson 'image.json')
    if ($images.Count -ne 1 -or $images[0].Id -cne $imageId -or $images[0].Os -cne 'linux' -or $images[0].Architecture -cne 'amd64') { throw 'Image identity/platform mismatch' }
    Assert-Labels $images[0].Config.Labels
    Invoke-LinuxDocker (@('run') + $labels + @('--name',$containerName,'--cidfile',(Join-Path $EvidenceDirectory 'container-id.txt'),'--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','768m','--cpus','1','--tmpfs','/tmp:rw,noexec,nosuid,size=128m,mode=1777',$imageId)) 'run.log' -AllowFailure
    $runtimeExit = $commandExits[$commandExits.Count - 1].exit_code
    $containerId = (Get-Content -LiteralPath (Join-Path $EvidenceDirectory 'container-id.txt') -Raw).Trim()
    if ($containerId -cnotmatch '^[a-f0-9]{64}$') { throw 'Immutable container ID missing' }
    Invoke-LinuxDocker @('logs',$containerId) 'linux-readiness.json'
    Invoke-LinuxDocker @('inspect',$containerId) 'container.json'
    Invoke-Recorded python @($PortsScript,'observe',"m4/$Instance") 'ports-observe.log'
    Assert-PortsObservation
    $containers = @(Read-RequiredJson 'container.json')
    if ($containers.Count -ne 1) { throw 'One container receipt required' }
    $container = $containers[0]
    Assert-Labels $container.Config.Labels
    if ($container.Id -cne $containerId -or $container.Image -cne $imageId -or $container.Name -cne "/$containerName" -or $container.State.Running -ne $false -or $container.State.OOMKilled -ne $false -or $container.State.ExitCode -ne $runtimeExit -or $container.Config.User -cne '65532:65532' -or $container.HostConfig.NetworkMode -cne 'none' -or -not $container.HostConfig.ReadonlyRootfs -or $container.Mounts.Count -ne 0 -or $container.HostConfig.Memory -ne 805306368 -or $container.HostConfig.NanoCpus -ne 1000000000 -or @($container.HostConfig.PortBindings.PSObject.Properties).Count -ne 0 -or 'ALL' -notin $container.HostConfig.CapDrop -or $container.HostConfig.Privileged -ne $false -or 'no-new-privileges' -notin $container.HostConfig.SecurityOpt) { throw 'Container identity/resource receipt mismatch' }
    $report = Read-RequiredJson 'linux-readiness.json'
    if ($report.kind -cne 'm4-linux-readiness-v1' -or $report.source.source_commit -cne $stage.source -or $report.source.packaging_commit -cne $packagingHead -or $report.primary_scans -ne 0) { throw 'Linux report source identity mismatch' }
    $reportersComplete = Save-LinuxDiagnostics $report
    foreach ($probe in @($report.versions)) { Assert-StreamReceipt $probe.stdout; Assert-StreamReceipt $probe.stderr }
    Invoke-Recorded git @('-C',$taskRoot,'rev-parse','HEAD') 'packaging-after.txt'
    Invoke-Recorded git @('-C',$taskRoot,'diff','--quiet','HEAD') 'source-clean-after.txt'
    if ((Get-Content -LiteralPath (Join-Path $EvidenceDirectory 'packaging-after.txt') -Raw).Trim() -cne $packagingHead) { throw 'Source identity changed during test' }
    $pins = Read-RequiredJson 'context-pins.json'
    foreach ($entry in $pins.PSObject.Properties) {
        $actual = Get-FileHash -LiteralPath (Join-Path $context $entry.Name) -Algorithm SHA256
        if ($actual.Hash.ToLowerInvariant() -cne $entry.Value.sha256) { throw 'Build context bytes changed' }
    }
    Assert-ClosedContext $context
    if ($runtimeExit -ne 0 -or $reportersComplete -ne $true -or $report.passed -ne $true -or $report.pytest.completed -isnot [bool] -or $report.pytest.completed -ne $true -or ($report.pytest.exit_code -isnot [long] -and $report.pytest.exit_code -isnot [int]) -or $report.pytest.exit_code -ne 0 -or $report.pytest.tests -ne 168 -or $report.pytest.failures -ne 0 -or $report.pytest.errors -ne 0 -or $report.pytest.nofollow_executed -ne $true -or $report.tree.expected_match -ne $true -or $report.tree.unchanged -ne $true -or $report.tree.shared_seconds -gt 30) { throw 'Linux metadata/test checks failed; raw report preserved' }
    @{passed=$true; source=$stage.source; packaging=$packagingHead; image=$imageId; container=$containerId; primary_scans=0} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'result.json')
} catch {
    @{passed=$false; error=$_.ToString(); image=$imageName; container=$containerName; primary_scans=0} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'failure.json')
    throw
}
