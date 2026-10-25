# Public development checks

RV2's 24 synthetic cases transcribe the promoted policy's truth boundaries for R1–R4.
Expectations are written in `fixtures/generator/public_dev.py` without importing
the detector. Their committed input digests live in
`fixtures/expected/dev/rv2-policy-v1.json`. They are development examples, with
illustrative producer metadata, and establish no Terraform/provider compatibility,
sealed-oracle independence, hidden generalization or final product acceptance.

Using the pinned project-local Python 3.12 environment, from any working directory:

```powershell
& '<checkout>\.venv\Scripts\python.exe' '<checkout>\evals\run_public.py' --out '<new-result.json>'
& '<checkout>\.venv\Scripts\python.exe' '<checkout>\evals\run_checks.py'
& '<checkout>\.venv\Scripts\python.exe' '<checkout>\evals\docker_journey.py'
```

`run_public.py` admits only the fixed public dev inventory, checks raw input hashes,
then evaluates normalized rules and evidence-backed reports. It compares the named
rule's applicability/outcome, checks determinate evidence resolution and scans the
shareable projection for its address canary. A failure remains a case-level failure.
It does not run L/P/M/C/C-custom/T, and reports them as NOT MEASURED. The separate
regressions test abstention denominators, certainty errors, F1 and missing costs.

`run_checks.py` collects `tests/eval` and `tests/corpus` only. Existing tests use
public synthetic records, including adversarial custody metadata; they do not open
an actual hidden corpus. The runner puts sibling helper modules on the import path.
Assessment-join unit tests stub separately tested custody/capture gates to isolate
identity joins. These stubs confer no authentic authority or semantic assessment.

`docker_journey.py` executes real CLI subprocesses for risk/clear/inconclusive exit
codes 1/0/2, report verification and shareable export, plus malformed exit 3. Host
execution of this script is evidence about the host only. Container execution is a
separate required check. It retains M4-owned temporary output and deletes nothing.

## Docker execution gate

PB-M4-R03's operator correction assigns M4 loopback block 22100–22199, replacing
the overlapping launch block 21830–21839. INT's run addition 3 permits Docker after
the M4 instance claim/check succeed. Prepared packaging alone establishes no
container execution. Run `scripts/docker_e2e.ps1` with an immutable base reference:

```powershell
& '<checkout>\scripts\docker_e2e.ps1' -BaseImage 'python:3.12.13-slim@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36'
```

The digest was resolved from the public image manifest on 2026-10-25; resolving a
manifest is not a successful build. Runtime requirements are the hash-pinned
runtime subset of D8's lock. The script requires a registered m4 claim and a passing
preflight before build/run, stages an explicit allowlist as its build context, and
starts only its m4-prefixed, labeled container. It publishes no port, uses no mounts,
disables network, drops capabilities, runs unprivileged with a read-only root and a
bounded temporary filesystem, and retains the stopped container. It never reads
credential files, copies a broad checkout, restarts Docker or prunes resources.
