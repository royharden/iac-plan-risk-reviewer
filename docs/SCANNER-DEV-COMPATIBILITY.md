# Public development scanner readiness

This profile prepares C (Checkov built-ins), C-custom (action-aware Checkov policies),
and T (Trivy). No scanner has been installed or executed by this preparation.
`eval/scanners/dev-readiness.json` freezes image/config/policy/input metadata;
its `NOT_RUN` state is not a compatibility verdict, execution grant or score.
The existing bounded runner and comparison driver remain the only execution path.

## Tool pins, checked 2026-10-25

| Tool | Exact version | Official Linux amd64 image |
|---|---|---|
| Checkov | 3.3.30 | `bridgecrew/checkov:3.3.30@sha256:a1b2d159f46b452bc87eb6d6d07ac04d82855b7530079197f86f6221e0d77158` |
| Trivy | 0.76.1 | `aquasec/trivy:0.76.1@sha256:2e6c00d711ab4ae41d8a30c2c1fd3bd3b62704c177bb120f95012e939edfb3df` |

Versions and platform/index digests came from public [Checkov tag metadata](https://hub.docker.com/v2/repositories/bridgecrew/checkov/tags/3.3.30/)
and [Trivy tag metadata](https://hub.docker.com/v2/repositories/aquasec/trivy/tags/0.76.1/).
Checkov's [PyPI metadata](https://pypi.org/pypi/checkov/3.3.30/json) and
Trivy's [release](https://github.com/aquasecurity/trivy/releases/tag/v0.76.1) agree on these versions.

The pinned [Checkov Dockerfile](https://github.com/bridgecrewio/checkov/blob/3.3.30/Dockerfile)
uses Python 3.11. It is not the Python 3.12 product environment. RV2's proposed
Python 3.12.13 orchestrator should install Checkov separately at
`/opt/m4-checkov/bin/checkov`, using the generated
`eval/scanners/checkov-3.3.30.requirements.txt` with `--require-hashes` and
`--only-binary=:all:`. Resolution targets Linux x86_64/Python 3.12; installation,
wheel availability and runtime remain unverified. A missing wheel blocks this
proposal; there is no unpinned source-build fallback. Keep core dependencies isolated.
Copy `/usr/local/bin/trivy` from the pinned official Trivy stage; verify its actual
version and binary hash in the resulting image. Image metadata is not a binary hash.

## Frozen inputs and explicit incompatibility

The 24 public inputs at RV2 commit `484eb22` were compared with their Git blobs:
all working files match, and all omit `planned_values` and `configuration`.
The profile records every raw hash. Preserve this original edition.

Checkov's [3.3.30 plan parser](https://github.com/bridgecrewio/checkov/blob/3.3.30/checkov/terraform/plan_parser.py)
schedules resources from `planned_values.root_module.resources` and child modules.
Trivy's [0.76.1 parser](https://github.com/aquasecurity/trivy/blob/v0.76.1/pkg/iac/scanners/terraformplan/tfjson/parser/parser.go)
also builds blocks from `PlannedValues.RootModule`. Resource changes alone do not
schedule these resources. An exit 0 or empty report on the original inputs cannot
establish a benign prediction or a successful primary comparison.

INT authorized construction of RV2's separately named `m4-public-fullplan-dev-v2`
synthetic development edition under `I-RV2-public-dev-v2-amendment-r1.md`:
preserve all resource changes, masks, actions and canaries; include planned resources
only when `after` is non-null. Never substitute prior values or invent a deleted
planned resource. Planned values must also omit unknown subtrees or use permitted
nulls without shifting list positions, following the
[Terraform values/change semantics](https://developer.hashicorp.com/terraform/internals/json-format).
RV2 owns fixture bytes and labels; RV1 must independently check the envelope,
masks, nulls, deletion and hash lineage. All arms receive the same successor raw bytes, and D must
be rerun on their new hashes. This is synthetic shape compatibility, not provenance
from Terraform/AWS producers. No HCL/source enrichment is allowed.

## Fixed execution profile

Use the existing `checkov_adapter.scan` and `trivy_adapter.scan` argv builders.
The only config is `eval/scanners/dev-empty-config.json`, containing `{}`.
Use one private writable workspace per arm. Distinct case invocation hashes separate
exclusive receipt names inside it; the batch manifest has one settings object per arm.

Checkov options are `--file <exact-plan> --framework terraform_plan --output json
--compact --check <fixed-ids> --config-file <empty-config> --skip-download
--skip-results-upload --download-external-modules false`. C-custom alone adds
`--external-checks-dir <pinned-policy-dir>` and the adapter supplies only the same
raw plan path/hash through `IAC_CUSTOM_PLAN_JSON` and `IAC_CUSTOM_PLAN_SHA256`.
Pin all three loadable policy Python files; no product rules or gold are imported.
The [custom-policy API](https://www.checkov.io/3.Custom%20Policies/Python%20Custom%20Policies.html)
and [plan actions API](https://www.checkov.io/7.Scan%20Examples/Terraform%20Plan%20Scanning.html)
support registration and action metadata. Actual callback loading and UNKNOWN
reporting still need isolated verification. Delete-only resources may have no
callback and remain incomplete.

Trivy options are `config --format json --config <empty-config>
--misconfig-scanners terraformplan-json --include-non-failures --skip-check-update
--disable-telemetry --skip-version-check --exit-code 1 --ignorefile ""
--timeout 30s --cache-dir <arm-workspace> -- <exact-plan>`.
The pinned [scan flags](https://github.com/aquasecurity/trivy/blob/v0.76.1/pkg/flag/scan_flags.go)
and [misconfiguration flags](https://github.com/aquasecurity/trivy/blob/v0.76.1/pkg/flag/misconf_flags.go)
are the source references. The adapter requires actual hash-pinned checks-cache
files under that exact workspace. Do not insert an empty placeholder bundle.
Without a prepared offline cache, T remains `not_run`; any cache acquisition needs
its own disclosed immutable provenance before a network-disabled runtime.

[Checkov exits](https://www.checkov.io/2.Basics/Hard%20and%20soft%20fail.html)
are normally 0 for no failed checks and 1 for failures; no soft-fail switches are
used. Trivy normally exits 0 for findings unless configured otherwise; this profile
sets `--exit-code 1`. Neither exit alone is a prediction. The adapters also validate
JSON categories, resource identity, enabled checks and exit/result agreement.

## Mapping and evidence handoff

C's provisional candidates are R1/create with CKV_AWS_24 and CKV_AWS_25, and
R2/create with CKV_AWS_17, restricted to proven known, nonsensitive supported shapes.
R3 removal and R4 destructive intent have no declared built-in transition mapping.
Update/replacement and unknown/masked cells are not silently mapped. C-custom uses
the four CKV_M4 checks and its existing candidate contract. T check mappings remain
undeclared until exact installed policy IDs and semantics are verified. Every
mapping is currently unverified/unmapped, never a scored true negative.

RV2 should emit actual executable, dependency-inventory, version-receipt, config and
policy-manifest hashes from the pinned image. Policy manifests must enumerate
exact enabled check IDs and sorted extra-file hashes required by `capture`.
Construct the existing comparison manifest with explicit absolute in-container
paths, then use `invocation_digest` for each exact bounded argv/environment/file
set. INT approves that manifest and all `ApprovedInvocation` pins in the existing
execution-grant schema. A preparation profile does not authorize execution.

The existing runner now stores capped stdout/stderr bytes in exclusive private
`.scanner-stdout-<invocation_sha>.bin` and `.scanner-stderr-<invocation_sha>.bin`
files. Terminal receipts link their hashes, byte completeness, raw exit, timeout,
overflow and errors. Failed persistence prevents eligible capture. Raw bytes stay
private; exported comparison rows retain hashes/statuses and all denominators.
Missing checks, input incompatibility, timeouts and parser failures remain visible.

RV2 owns container execution and independent regressions; INT owns acceptance and
combined checks. Hidden/holdout, live models, paid calls and final required-arm
measurement remain unmeasured regardless of public development results.

## Complete Trivy cache transport (development v2)

`m4-scanner-run-v2` is explicit and restricted to `development_synthetic`.
The T arm uses `bundle_inventory` with exactly `profile`, `root`, `manifest_path`
and `tree_sha256`; `bundle_files` is forbidden in this mode. The root is exactly
`<T workspace>/policy`, with an external manifest. C/C-custom retain their v1
interfaces. V1 refuses complete-tree fields; its invocation digest, pinned file
limits, policy file inventory and capture/report wires are unchanged.

`eval.scanners.bundle_inventory.BundleInventory` is immutable. Its profile
`m4-trivy-complete-cache-v1` fixes 1,024 regular files, 256 directories and 1,280
entries (root excluded), 65,536 bytes per file, 2,097,152 aggregate file bytes,
256 relative path bytes, depth 12, and 524,288 canonical manifest bytes.
No caller may raise these caps. `load_bundle_inventory` validates the closed
input descriptor and canonical expected manifest; `verify_tree` independently
walks and hashes the entire actual tree. No cache/subset can substitute for a walk.

The manifest has exactly `schema_version: m4-scanner-bundle-tree-v1`,
`algorithm: sha256`, `paths: normalized-posix-relative-utf8`, and `rows`.
Directory rows have `path` and `kind: directory`; file rows also have `bytes`
and `sha256`, with `kind: file`. Rows are sorted by exact UTF-8 path bytes.
Serialization is ASCII JSON with `ensure_ascii=True`, sorted keys, compact comma
and colon separators, finite values and no newline. Duplicate keys or a different
encoding fail. The tree digest is SHA256 of these exact bytes and of the separately
reconstructed actual tree. Root relocation preserves portable tree identity and
changes invocation identity through the absolute binding.

Relative paths use ASCII `[A-Za-z0-9_.-]+` segments. Empty, dot/dotdot, absolute,
UNC/drive, backslash, ADS, control, trailing-dot and Windows-device aliases fail.
All parents and empty directories are explicit. Duplicate and casefold collisions
fail across files and directories; equal basenames at different relative paths
are legal. The traversal streams bounded directory entries, rejects symlinks,
reparse points, junctions, special objects and non-single-link regular files,
and checks opened file and directory identities before/after. No-follow final
opens are used where supported. These checks do not provide atomic handle-relative
race immunity: the operator must exclude concurrent mutation in an isolated sandbox.

T's policy receipt has exactly `schema_version: m4-scanner-policy-manifest-v2`,
`scanner_name: trivy`, `check_ids` (actual enabled IDs), and `bundle_tree_sha256`.
The invocation binds the typed descriptor, all effective caps and pinned external
manifest bytes. Existing closed `ApprovedInvocation`, `LocalExecutionGrant`,
`ScanArtifact`, comparison and report fields stay unchanged. The invocation,
policy, comparison manifest, capture and terminal hashes transitively bind the
tree. New policy bytes require new mapping compatibility/pins and an exact external
grant; a transport hash never proves check semantics or scoring eligibility.

One monotonic deadline covers preparation, approval, verification, process and
closure, at most 30 seconds or a tighter caller limit. The internal clock is
excluded from identity. Successful complete walks occur before approval/start,
immediately before process invocation and after it. Any missing/extra/drifted
entry, read error, link or cap failure prevents eligible prediction. Failed phases
retain null summaries rather than fabricated counts. After start, raw/terminal
persistence is attempted even if the eligibility deadline expires; this recovery
does not extend the eligible attempt. The private terminal alone gains a
`bundle_inventory` object with `expected_tree_sha256`, `before`, `after`, and
`closure_error`. Successful phase summaries contain exactly `tree_sha256`, `files`,
`directories`, `aggregate_file_bytes` and `elapsed_seconds`. A null `after` or
non-null closure error cannot establish success. Legacy terminal payloads omit
this object.

The approved proposed complete cache is 642 files (641 OCI payload files plus
174 bytes of locally generated metadata), 99 directories below `policy`, and
1,056,327 bytes. Canonical tree SHA256 is
`6168428f0f5260c79536f13b9697dd5d7fb6866e96a4762e3f8e651b34a342b2`.
D8 independently audited the actual tree using a different canonical format;
its digest is not a parity claim. This profile does not copy cache payloads into
Git or authorize scanner execution. RV2 must establish Linux performance,
complete seed copy, final-image loaded bytes, policy closure and retained outputs
under a later exact INT resource/execution grant.

INT explicitly selected exact Git LF custom-policy blobs for the future Linux
image in `CONTRACT-TRIVY-TREE-R03-v1.md`. `dev-readiness.json` v2 records their
new exact hashes and preserves the earlier Windows CRLF pins as provenance.
Policy source semantics are unchanged; the final loaded image still needs RV2
verification. Historical candidates and records retain their original bytes.


## R04 exact-source packaging successor

The metadata-only Linux stager fixes source commit
`ddcdffd72cf6377b22d5ace95bafed61504652bb`. The custom policy is the approved
f752 pure repair: Git LF `m4_policy.py`, 11,018 bytes, SHA256
`3d73f610a236e6a9346fd3eca45a43a7e7acdd70bad6a29842edb1f111a0cc6a`.
The other two policy blobs and complete cache tree retain their existing pins.
Prior profiles, contexts, images and their test outcomes remain historical.

`linux_readiness.py stage` now requires `--packaging-commit` with an explicit
full lowercase Git commit, equal to the clean checkout. Source product files
come from the fixed source commit; only `eval/scanners/dev-readiness.json`
comes from that explicit packaging successor. Every other selected product blob
must still equal the fixed source. The Dockerfile and stager come from the
explicit packaging commit. Working bytes must match Git LF or its exact CRLF
representation; staged bytes always remain exact Git LF. Contexts and
sibling `context-pins.json` use fresh exclusive outputs. Git LF extraction
is distinct from any CRLF checkout bytes. Inspect and commit the successor
before staging; a branch name or implicit HEAD is insufficient.

This repin prepares metadata packaging only. New context/image loaded-byte and
runtime test evidence requires a fresh independent review and new team-owned
resources. The readiness profile remains NOT_RUN and product_acceptance=false;
no Checkov callbacks, primary scans, hidden/holdout or live models are admitted.


## R04 read-only image metadata mode

The separate `image-metadata --packaging-commit <full40> --source-sha <sha256>`
entrypoint verifies actual read-back file membership, lengths, hashes, policy,
config, complete cache, and pinned distribution METADATA versions. The external
source-receipt digest and packaging commit come from the reviewed new context.
It imports no product, policy or scanner code and executes no subprocess or
pytest lifecycle. It creates no files, links or scratch directories; evidence is
bounded stdout. Dockerfile.scanners-linux selects this explicit mode.

The previous 168-test path is held: empty argv, `tests` and `legacy-tests` refuse
with exit 2. Its function bodies remain preserved for a separately approved
future route. Metadata output reports `legacy168_tests=NOT_RUN_HELD`,
`nofollow=NOT_RUN`, `native_callbacks=NOT_RUN`, `primary_inputs=NOT_RUN` and
`product_acceptance=false`. A metadata pass never supplies those execution proofs.
Package METADATA pins verify declared versions, not package-code integrity;
extra build-tool pip is reported as unpinned. No old image/context proof carries
forward. New independent SOURCE/TEST/effect review and exact conditional Docker
resource/heavy-slot grant are required before any build or run.
