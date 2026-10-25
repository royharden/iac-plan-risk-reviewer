# Local Python environment

The R03 environment targets CPython **3.12.13**, uv **0.11.29**, and Windows
PowerShell 7. Runtime dependencies and development tools are locked with hashes
in `uv.lock`. Direct pins are Pydantic 2.14.1, pytest 9.0.3, Ruff 0.17.2, and the
Hatchling 1.27.0 build backend. Python support is deliberately limited to 3.12.
The lock freezes dependency resolution; it does not establish security or product
acceptance. No keys, credential files, provider calls, Docker, or listening service
are needed for this environment.

The first dependency audit found CVE-2025-71176 in pytest 8.4.2 (UNIX temporary
directory handling). The final pin uses the first patched release, 9.0.3, rather
than retaining the previous `pytest<9` development constraint. This is a runner
update; product rule expectations are unchanged. Vulnerability databases change,
so repeat the advisory check when maintaining this lock.

From any working directory:

```powershell
& 'C:\path\to\checkout\scripts\bootstrap.ps1'
# If uv is installed elsewhere, pass its actual native executable:
& 'C:\path\to\checkout\scripts\bootstrap.ps1' -UvPath 'C:\tools\uv.exe'
```

The bootstrap prefers the standard user `.local/bin/uv.exe` over PATH shims and
checks its version. It never installs uv globally. Install the required uv version
separately if unavailable. Python downloads, uv cache, and the virtual environment
stay under this checkout (`.agent-work/python`, `.agent-work/uv-cache`, `.venv`).
Those process environment overrides are restored even if setup fails. Sync uses
`--locked`: dependency drift is an error, rather than an implicit lock update.

Use absolute paths or uv's `--directory` flag; activation and shell `cd` are not
required. For example, replacing the paths with your assigned checkout:

```powershell
$uvExe = 'C:\Users\Roy Harden\.local\bin\uv.exe'
$checkout = 'C:\Worktrees\PortfolioBuilder\iac-plan-risk-reviewer\R03-DL1'
& $uvExe run --directory $checkout --locked --no-sync python --version
& $uvExe run --directory $checkout --locked --no-sync pytest --collect-only -q
& $uvExe run --directory $checkout --locked --no-sync pytest -q --junitxml=.agent-work/baseline.xml
& $uvExe build --directory $checkout --wheel --no-build-isolation
```

pytest uses importlib collection so same-named test files in different directories
do not collide. Its configured import paths expose the repository's development
`eval` package and existing bare sibling-helper imports in `tests/eval`. These
paths affect tests only; the wheel contains `iac_review` from `src`, not the
development evaluation tree. Run development scripts through uv from this checkout.
The wheel command disables build isolation after locked sync, so Hatchling and
its transitive build dependencies come from the hash-locked environment too.

Each seat writes its own environment; do not sync another seat's `.venv` or assume
an editable install points at your source. A published interpreter may be used
read-only, with your own source paths explicitly selected. Reviewers own the test
suites and independent acceptance. Collection, a successful build, or installed
dependencies alone do not establish runtime correctness. Live model/scanner and
held-out comparisons remain separate gates.
