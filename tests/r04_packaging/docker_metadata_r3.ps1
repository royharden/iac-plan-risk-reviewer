#Requires -Version 7.4
param()
$ErrorActionPreference='Stop'
# NEW immutable, static-only High-authored successor to Medium607/r2.
# This file intentionally has NO activation branch, Process.Start/native call,
# directory creation, helper invocation or claim/check/observe/Docker fallback.
# Independent review can inspect this edition; a future runtime edition must be
# separately authored/frozen/reviewed after the exact no-delete disposition.
$inventory='C:\Users\Roy Harden\OneDrive\PJ-OD\PortfolioBuilder\iac-plan-risk-reviewer\agentops\runs\PB-M4-R04\work\0134-Docker-High-repair\host-closure-inventory.json'
$inventorySha='8c3da2873d6828d39eba4784fbe8e0400966a59738c52a6361ede3704f88ea74'
$oldWrapperSha='c7b429d269a923f5c805d8a3107d7621bca08b471ec3b48ee9690ece23791765'
$verifierSha='1f3ddaad0420ede25e32263a610c1addfca1bc2aec80ea9a285a3114109f8430'
$portsSha='57b08a5b8d21e0beb640775d7568a3bd5f70dc58979982a34e49b7de9e09568f'
$basePython='C:\Users\Roy Harden\AppData\Roaming\uv\python\cpython-3.12.13-windows-x86_64-none\python.exe'
# This is review data, not an invocation assembled for immediate execution.
# -I ignores PYTHON* environment settings: the cache prefix MUST be process-start
# -X, not a later assignment or PYTHONPYCACHEPREFIX. -B alone permits cache reads.
# Use the real base path directly; do not traverse the venv's home junction or
# import its site/_virtualenv hooks. -S disables site; -I removes script/cwd and
# user-site additions. The verifier and canonical helper are stdlib-only.
$proposal=[ordered]@{
    kind='rv4-docker-effect-static-proposal-r3';status='BLOCKED_STATIC_ONLY';
    author='0134_Codex_gpt-61-sol_Sub_DockerHighRepair';
    parent_edition='607918601ab576c44943a07e2a5e159f4bc1bf3c';
    parent_actual_effort='Medium; preserved, not relabelled';
    inventory=[ordered]@{path=$inventory;sha256=$inventorySha;runtime_closure_approved=$false};
    preserved_pins=[ordered]@{r2=$oldWrapperSha;verifier=$verifierSha;canonical_ports=$portsSha};
    source=[ordered]@{commit='d8fe3399387a6073ca4612e9a659e7560694d6de';
        pins_sha256='040581b5d874754e68b8a2d5727463bc1fc8a4bfb5cf3a0bda7b41f7228a488e';
        source_sha256='0edf106a7497fc963bf0e238fcb0127f7739e65d801b6d2c1a3fbfd38e227027';
        route='image-metadata only; independent SOURCE/TEST approval remains separate'};
    proposed_host_launch=[ordered]@{
        executable=$basePython;
        prefix=@('-I','-S','-B','-X','pycache_prefix=<fresh-exclusive-Out>/python-startup-cache/<unique-process-edition>');
        required_before_every_start=@('Exact pin recheck for wrapper/verifier/helper/runtime/public code inventory',
            'Exclusive new ordinary empty process-specific cache prefix; preserve after use; no shared-cache reads/deletes',
            'Fresh ordinary empty working directory; no inherited cwd or PATH/PATHEXT',
            'Fresh empty task DOCKER_CONFIG before every process; explicit local Linux-engine named pipe',
            'Cleared environment, then exact reviewed values; no credential/TLS/proxy/context overrides');
        event_owner='AGENT_PORTS_OWNER=0117_Codex_gpt-61-sol_RV4';
        owner_reason='claim --owner alone does not cover detect_owner() in event/history or separate check/observe processes';
        nested_resolution='UNRESOLVED: actual docker/netstat/tasklist/netsh pins captured; bare CreateProcess resolution must be independently bound';
        agentnamer_route='Proposed nonempty explicit AGENT_PORTS_OWNER suppresses optional AgentNamer launch; prove for each exact helper route';
        no_site_route='PROPOSED_NOT_EXECUTED; public code snapshot is evidence basis, not an approved startup closure'
    };
    blocking=[ordered]@{
        'DOCKER-R2-EFFECT-04'='Hard Roy no-delete constraint: normal and stale canonical helper lock deletion; no helper route admitted';
        'DOCKER-R2-EFFECT-05'='No-site/fresh-prefix proposal and actual public pins frozen; exact startup/argument/import-path preflight remains required';
        'DOCKER-R2-EFFECT-06'='Nested executable bytes and candidate locations frozen; exact future search resolution is not enforced by unchanged helper';
    };
    activation=$false;runtime_verified=$false;product_acceptance=$false;
    next='INT/Roy exact helper-effects disposition; independent RV3 static review; separately frozen executable successor plus NEW exact INT activation if authorized'
}
Write-Output ($proposal|ConvertTo-Json -Depth 9)
# No external artifact is loaded, no Out/config/cache directory is made, and no
# input/tool/helper is executed before this unconditional stop. There is no
# override parameter: acknowledgement or a label cannot make this edition run.
throw 'BLOCKED_STATIC_ONLY: canonical ports helper lock deletion is not authorized; r3 has no runtime activation route.'
