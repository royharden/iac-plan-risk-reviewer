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
Each arm/case needs its own private writable workspace and exclusive receipt names.

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
