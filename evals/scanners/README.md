# Scanner development preparation

`scripts/docker_scanners.ps1` builds a metadata-only image from a new explicit
four-file context. It installs D11's exact 96-dependency Checkov lock into a
separate Python 3.12 environment and copies Trivy from its pinned official image.
There is no fallback installation. The probe image contains no corpus, gold
labels, product scanner runner, custom policies or primary scan entrypoint.

The fixed `--version` commands and isolated distribution metadata query run with
network disabled, a read-only root, user 65532, dropped capabilities, no host
mounts or ports, 768 MiB memory, one CPU and a 64 MiB temporary filesystem. Each
probe has a 30-second timeout; output files share that filesystem bound. The
first 64 KiB of each stream is included as base64 with full-file size and hash
in the container logs. A truncated prefix is explicit. Preserve the stopped
container, image, context, logs and inspection receipts.

Requires PowerShell 7 with modern .NET. A fresh absolute evidence leaf and an
existing regular parent directory are mandatory. Every existing evidence ancestor
is checked from the filesystem root; links, junctions and reparse points are refused
before any ports or Docker calls. The leaf is created without overwrite before
external operations. This does not provide immunity to concurrent ancestor changes;
use an exclusively controlled regular directory outside OneDrive reparse roots.

Example:

```powershell
./scripts/docker_scanners.ps1 -EvidenceDirectory 'C:/path/to/new-m4-evidence'
```

The script refuses existing image and container names for its selected M4 instance
before build, then claims/checks that instance before build/run. No listener is
opened. The default instance is `r03-rv2-scanners-prep`; choose another unique
instance for another retained probe run. Existing resources are retained. Build
captures an immutable image ID and run uses that ID. Container receipts and logs
use the captured container ID and must match the image, name, labels and exit state.
Every required native command exit is recorded and checked, including Git,
resource preflight, inspection, logs and ports observation. Empty/malformed receipts
and incomplete raw stream metadata fail closed. `result.json` is written only after
all checks pass. Failure retains the context, command receipts and `failure.json`;
a nonzero probe run attempts log/inspection/observation capture before failing.
Observation must contain the canonical `ports.py cmd_observe` summary for the
selected instance: `M4/<instance>: stopped (docker ok, listeners ok; 1 container(s) matched)`.
The helper uppercases the displayed project. Missing, malformed, unrelated or extra
output, unknown sources, another status, and zero or multiple matches fail before
`result.json`. The summary does not enumerate port conflicts; the required claim/check
preflight remains responsible for that check.
No Docker resource is deleted or retagged on collision. These preflight checks are
not an exclusive Docker namespace reservation against another concurrent writer.
The source lock is bound to D11 commit
`1e59284f4180adfe75848943d3fb21f9d308afc8` and SHA256
`3bc130464fd7c4e7c17a2bf8441cbe046cee0db4aa067ea64433da6c368c44d2`.

Version success is not scan compatibility, native dependency, policy callback,
offline cache or product acceptance. Primary comparisons must use the existing
`eval/scanners/runner.py` and driver, exact reviewed source and v2 input pins,
and a separate exact INT execution grant. The public v2 corpus has 24 distinct
case IDs, 23 unique raw plans and zero additional independent scenarios.

Primary raw-output persistence requires a durable reviewed retention path; a
stopped container does not retain files from a temporary filesystem. The probe
uses its durable Docker logs instead. This preparation image does not implement
primary capture or grant handling.

Focused failure regressions invoke a fresh `pwsh -NoProfile -NonInteractive`
process with Git, ports and Docker functions mocked. They perform no Docker or
scanner execution. Source inputs alone are modeled as approved regular inputs;
the evidence collision and junction controls exercise the real filesystem.

```powershell
python -m pytest evals/scanners/tests/test_metadata_launcher.py -q
```

## Linux metadata readiness

The separate `Dockerfile.scanners-linux`, `linux_readiness.py` and
`scripts/docker_scanners_linux.ps1` implement INT grant
`I-RV2-Linux-metadata-readiness-r1.md` for provisional source `cb298a8a`.
This entrypoint has only fixed tool version commands, the two frozen mocked
Trivy-tree test modules, and complete-cache metadata verification. It exposes no
primary scanner command and copies no public plan corpus or policy-label tables.

The context is built from exact Git blobs and a closed public cache inventory.
Core/test requirements are exported from the accepted `uv.lock` with exact
versions and wheel hashes; Checkov uses its separate approved 96-entry lock.
Three approved Git-LF custom policy files are read and hashed, never imported.
The six resource/evidence guard functions are unchanged copies of the reviewed
`ebbc370` launcher. Every Docker command pins the local `desktop-linux` context.

Run only under an exact INT resource grant with a fresh absolute evidence leaf:

```powershell
./scripts/docker_scanners_linux.ps1 -EvidenceDirectory 'C:/Worktrees/PortfolioBuilder/iac-plan-risk-reviewer/R03-RV2-scanner-linux/.agent-work/linux-run-r1'
```

The new M4 instance has no ports or host mounts, no runtime network, read-only
root, user 65532, dropped capabilities, no new privileges, 768 MiB / one CPU and a
128 MiB temporary filesystem. Exact test copies run in writable temporary scratch;
product source and image seeds remain read-only. Reporters are exported fully as
bounded base64 with byte counts and SHA256 through preserved Docker logs, then
decoded and verified on the host. No deletion or cleanup is performed. Temporary
fixture objects disappear with the temporary filesystem; their complete reporters
and immutable input bytes remain retained. A stopped container alone does not
retain temporary-filesystem contents.

The private `m4-linux-readiness-diagnostics-v1` envelope records each reporter as
complete, missing, read-error or truncated. Collection runs after the test stream
closes, including timeout, native child failure and XML/import parse failures.
Each available reporter retains at most 1 MiB (a smaller diagnostic bound than
the existing 2 MiB artifact limit), with retained size/hash and original size when
readable. A truncated file is an explicit prefix, never a complete reporter.
The host saves independently valid reporter bytes and status/failure receipts
even when another reporter is missing or invalid. Failure causes and native exit
or timeout state remain in the raw report. Partial diagnostics cannot pass.

The metadata result requires completed pytest with native exit zero on both
runtime and host, all complete reporters, all 168 cases without failure/error, explicitly
lists Linux/Windows-specific skips, and requires the Linux O_NOFOLLOW case to
execute. Two complete 642-file/99-directory verifier passes share one 30s deadline,
with independent complete before/after audits. This is Linux metadata evidence,
not scanner consumption, policy compatibility, semantic mapping or product
acceptance. Actual primary scans still require a separate exact grant.
