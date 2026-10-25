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

Example (a fresh absolute evidence directory is mandatory):

```powershell
./scripts/docker_scanners.ps1 -EvidenceDirectory 'C:/path/to/new-m4-evidence'
```

The script claims/checks its M4 instance before Docker operations. No listener
is opened. The default instance is `r03-rv2-scanners-prep`; choose another unique
instance for another retained probe run. The source lock is bound to D11 commit
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
