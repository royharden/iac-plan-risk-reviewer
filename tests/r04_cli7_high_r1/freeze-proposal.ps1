# Text/hash bookkeeping ONLY. No Python, compiler, native helper, or candidate run.
$ErrorActionPreference='Stop'
$owned='C:\Worktrees\PortfolioBuilder\iac-plan-risk-reviewer\R04-D13-CLI7-runner-High-r1\tests\r04_cli7_high_r1'
$outer='C:\Users\Roy Harden\OneDrive\PJ-OD\PortfolioBuilder\iac-plan-risk-reviewer'
if((Get-Location).Path -ne $outer){throw 'OUTER cwd required'}
$run=Join-Path $outer 'agentops/runs/PB-M4-R04'
$runtime=Get-Content -Raw -LiteralPath "$run/work/identity-retained-r2/runtime-inputs.json"|ConvertFrom-Json
$expect=Get-Content -Raw -LiteralPath "$owned/oracle/expectations.json"|ConvertFrom-Json
$selected=Get-Content -Raw -LiteralPath "$owned/source-representation.json"|ConvertFrom-Json
$sourceReady=Get-Content -Raw -LiteralPath "$run/requests/READY-D12-CLI7-source-repair-plan-r1.json"|ConvertFrom-Json
$site='C:\Worktrees\PortfolioBuilder\iac-plan-risk-reviewer\R03-RV2-eval-db\.venv\Lib\site-packages'
$proposedOutput='C:\Worktrees\PortfolioBuilder\iac-plan-risk-reviewer\RV4-CLI7-0149-output-r1'
if(Test-Path -LiteralPath $proposedOutput){throw 'Proposed ordinary output must remain absent'}
function Pin([string]$path){
 $item=Get-Item -LiteralPath $path
 if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse file'}
 [ordered]@{path=$item.FullName;bytes=$item.Length;sha256=(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()}
}
$pins=[Collections.Generic.List[object]]::new()
foreach($row in $runtime.pins){
 $actual=Pin $row.path
 if($actual.sha256 -ne $row.sha256){throw 'Runtime input drift'}
 $pins.Add($actual)
}
$dependencyFiles=@(
 foreach($package in @('pydantic','pydantic_core','annotated_types','typing_inspection')){
  Get-ChildItem -LiteralPath (Join-Path $site $package) -Recurse -File |
   Where-Object {$_.FullName -notmatch '\\__pycache__\\' -and $_.Extension -notin @('.pyc','.pth')}
 }
 Get-Item -LiteralPath "$site/typing_extensions.py"
)
foreach($file in $dependencyFiles){$pins.Add((Pin $file.FullName))}
foreach($row in $sourceReady.source_files){
 $copy=Pin (Join-Path $owned ('source-snapshot/'+$row.relative))
 if($copy.sha256 -ne $row.actual_sha256 -or $copy.bytes -ne $row.actual_bytes){throw 'Raw17 snapshot drift'}
 $original=Pin $row.actual_path
 if($original.sha256 -ne $row.actual_sha256){throw 'Original raw17 drift'}
 $pins.Add($copy)
 $pins.Add($original)
}
if((Pin "$owned/oracle/test_journey.py").sha256 -ne $expect.test_sha256){throw 'Frozen oracle drift'}
$pins.Add((Pin $expect.test_path))
foreach($path in @("$run/work/D12-CLI7-AST-recipe-r1/RECIPE-PROVENANCE.md",
 "$run/work/D12-CLI7-AST-recipe-r1/ORIGINAL-SUCCESSFUL-TOOL-CALL.txt")){$pins.Add((Pin $path))}
$readList=Join-Path $owned 'bootstrap-read-paths.txt'
if(Test-Path -LiteralPath $readList){throw 'Immutable startup DATA allowlist occupied'}
$earlyPaths=@($runtime.pins|ForEach-Object path)+@("$owned/childguard.py","$owned/adapter.py")
[IO.File]::WriteAllText($readList,(($earlyPaths|Sort-Object -Unique)-join "`n"),[Text.UTF8Encoding]::new($false))
$helperFiles=@(Get-ChildItem -LiteralPath $owned -File | Where-Object Name -notin @('proposal-config.json','SOURCE-MANIFEST.json'))
foreach($file in $helperFiles){$pins.Add((Pin $file.FullName))}
foreach($name in @('oracle/test_journey.py','oracle/expectations.json')){$pins.Add((Pin (Join-Path $owned $name)))}
$calls=[Collections.Generic.List[object]]::new()
$cases=@($expect.cases)
foreach($case in $cases){
 $caseRoot=Join-Path "$proposedOutput/cases" $case.case
 $plan=Join-Path $caseRoot 'public-synthetic.json'
 $private=Join-Path $caseRoot 'private-report'
 $export=Join-Path $caseRoot 'safe-export'
 $calls.Add([ordered]@{id=$calls.Count+1;case=$case.case;verb='inspect';args=@('inspect',$plan,'--out',$private)})
 if($case.case -ne 'malformed'){
  $calls.Add([ordered]@{id=$calls.Count+1;case=$case.case;verb='verify-report';args=@('verify-report',$private,'--plan',$plan)})
  $calls.Add([ordered]@{id=$calls.Count+1;case=$case.case;verb='share';args=@('share',$private,'--plan',$plan,'--out',$export)})
  $calls.Add([ordered]@{id=$calls.Count+1;case=$case.case;verb='verify-report';args=@('verify-report',$private,'--plan',$plan)})
 }
}
if($calls.Count -ne 25 -or $cases.Count -ne 7){throw 'Static seven-case/25-call shape drift'}
$cache=[ordered]@{worker=(Join-Path $proposedOutput 'absent-cache-worker')}
1..25|ForEach-Object {$label='cli-{0:00}' -f $_;$cache[$label]=Join-Path $proposedOutput ('absent-cache-'+$label)}
$absent=@($runtime.absent)+@(
 (Join-Path $runtime.python_home 'pyvenv.cfg'),
 (Join-Path (Split-Path $runtime.python_home) 'pyvenv.cfg')
)
foreach($path in $absent){if(Test-Path -LiteralPath $path){throw 'Startup absence failed'}}
$directories=@($pins|ForEach-Object {Split-Path $_.path}|Sort-Object -Unique)
$manifest=[ordered]@{
 schema_version=1;state='STATIC_SOURCE_ONLY_NOT_BUILT_NOT_RUN';
 author='0149_Codex_gpt-61-sol_Sub_CLI7RunnerHigh';workspace_author='0827_Codex_gpt-61-sol_Sub_M4CLI7RunnerHigh';
 actual_child_session='01a17b5a-0450-7133-9a5f-8c3b7ff88dde';actual_effort='high';
 selected_product_commit='ddcdffd72cf6377b22d5ace95bafed61504652bb';
 frozen_test_commit='8f6da247e229d5b517519902e4383d3e967cd19c';
 desired_accepted_baseline='6a0866ade47662660b78a8ac8ead99ca0b1f47b4';desired_baseline_qualifier='Separate integration target; never relabel selected ddcd/raw17 or test8f6 execution';
 whole_journey_admitted=$false;activation_status='EXACT_INDEPENDENT_REVIEW_AND_INT_ACTIVATION_REQUIRED';
 ast_recipe_status='OWNER_RECIPE_CONFIRMED_VERSION_QUALIFICATION_PENDING';
 ast_recipe='body ast.Module(fn.body,type_ignores=[]); plan full FunctionDef; ast.dump(include_attributes=False), defaults, UTF8/no trailing newline; NO field dropping';
 ast_historical_interpreter='bare python producing process image/version/hash unrecorded; same-session earlier Python3.11.3 observation is not exact historical attestation; target3.12 schema not assumed equivalent';
 interpreter=$runtime.interpreter;bootstrap=(Join-Path $owned 'bootstrap.py');
 source_root=(Join-Path $owned 'source-snapshot/src');dependency_root=$site;
 oracle=(Join-Path $owned 'oracle/test_journey.py');expectations=(Join-Path $owned 'oracle/expectations.json');
 output=$proposedOutput;system_root='C:\Windows';
 runtime_path=$runtime.python_home+';'+(Join-Path $runtime.python_home 'DLLs')+';C:\Windows\System32';
 cache_prefixes=$cache;cases=$cases;calls=@($calls);pins=@($pins);absent=$absent;import_dirs=$directories;
 dependencies='pydantic2.14.1/pydantic_core2.50.1/annotated_types0.8.0/typing_inspection0.4.4/typing_extensions actual pinned source; no site startup';
 native_provenance='Exact .pyd/.dll input hashes present; OS transitive loader and future .NET build/runtime closure NOT_QUALIFIED';
 scope='Staging-only admitted; final-marker overwrite, final-payload rollback, temporary-state cleanup, job/native build/run remain NOT_ADMITTED';
 hostname='NOT_COLLECTED';execution_counts=@{candidate_imports=0;CLI=0;test_bodies=0;native_helpers=0;fixtures=0;parser=0}
}
$dest=Join-Path $owned 'proposal-config.json'
if(Test-Path -LiteralPath $dest){throw 'Immutable config occupied; preserve and use a new edition'}
[IO.File]::WriteAllText($dest,($manifest|ConvertTo-Json -Depth 20),[Text.UTF8Encoding]::new($false))
[ordered]@{pins=$pins.Count;dependency_files=$dependencyFiles.Count;source_files=17;logical_cases=7;intended_calls=25;
 output_absent=(-not (Test-Path -LiteralPath $proposedOutput));config=(Pin $dest)}|ConvertTo-Json -Depth 8
