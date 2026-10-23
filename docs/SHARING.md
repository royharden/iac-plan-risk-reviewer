# Regenerated share-only export

Source construction only. No share export, report, test, app or private data was
generated/executed in this package. All D/L/P/M/C/C-custom/T arms remain NOT MEASURED.

Never share a whole inspection/demo directory. It contains exact private evidence,
source hashes/descriptors and possibly private journal/accounting. After separately
authorized environment/runtime activation, use the dedicated source interface:

```powershell
New-Item -ItemType Directory -Force .\iac-plan-risk-reviewer\shared | Out-Null
uv run --project .\iac-plan-risk-reviewer iac-review share .\iac-plan-risk-reviewer\reports\public-ssh --plan .\iac-plan-risk-reviewer\fixtures\demo\public-ssh.json --out .\iac-plan-risk-reviewer\shared\public-ssh
```

The same library is `iac_review.shareable_export.export_shareable(bundle,
original_plan, out, *, deadline=None)`. `scripts/export_shareable.py` is an explicit
standalone wrapper with bundle/--plan/--out arguments. Both require a fresh separate
output directory and an existing parent. An explicit original plan is mandatory;
no report-provided path is opened. Paths traversing links/junctions, parent aliases,
UNC shares or the private input bundle output namespace are refused.

The exporter first verifies COMPLETE closed inventory, bound private descriptor
and exact supplied source digest. Legacy unbound reports are refused. It compares
the descriptor's fixed installed-core source/parser/rule/config pin inventory with
the actual installed files; stale source/policy versions are refused. An archive
created before a core CLI/code change needs a new inspection under that source.
This checks the declared core subset, not every dependency or authenticity of
loaded code. Hash integrity does not authenticate a producer or benchmark.

It recomputes D/rules/evidence/projections using the original frozen fail-on config,
compares canonical report semantics with typed JSON equality while excluding only
fresh IDs/private descriptor, and checks stored HTML against the real core renderer.
Tampered JSON, arbitrary stored HTML, mismatched threshold/results or source/code
changes are refused. It then generates fresh safe JSON/HTML through the actual
core projection/renderer. Stored HTML/prose is never copied into the output.

The share-only directory contains safe shareable.json, shareable.html, public
manifest.json and its detached hash, plus export-state.json. Public artifact hashes
refer only to those safe files. No original plan/filename/raw-source hash, private
descriptor/map, exact address/pointer, tags or model prose is written there—not
even to pending files. Fresh opaque IDs are disconnected from the original private
bundle; no new source-resolution map is retained. Shared files are not independently
source-resolvable. Keep original private evidence outside this directory.

ABORTED is installed before safe file staging; COMPLETE is published last after
source/bundle/code rechecks and the final cooperative deadline. Failed writes roll
back created safe files where possible. Cleanup refusal/process death can leave
safe remnants, but ABORTED remains authoritative; do not treat them as a finished
export. Filesystem races, blocking I/O, crash durability and Windows path/ACL behavior
remain runtime-unverified. No private material is used as a temporary output.

Successful export retains the review's exit 0/1/2 semantics; failure/usage error is
3. An exit 1 means threshold risk, not broken sharing; exit 2 retains inconclusive
coverage. No global secure badge, live measurement, producer authenticity or
publication authorization follows. Existing inspect/explain/evidence/verify-report
interfaces remain unchanged. Focused source regressions live in tests/shareable/
and have not run.
