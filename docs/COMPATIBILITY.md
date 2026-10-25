# Compatibility and evidence scope

The recorded keyless development environment is Python 3.12.13, Pydantic 2.14.1
and pytest 9.0.3. Dependencies are pinned in `pyproject.toml` and `uv.lock`.
The combined code passed 946 development tests, a public 24-case matrix and four
host/container CLI journeys. These results establish the bounded synthetic checks
in [testing](TESTING.md), not compatibility with every producer or environment.

| JSON minor format: parser-tested | AWS resource shape: fixture-tested | Producer Terraform / AWS pin | Evidence state |
|---|---|---|---|
| 1.2, public synthetic inputs | Standalone `aws_security_group_rule` for R1, including IPv4/IPv6 and unknown/unsupported components | None; handwritten fixtures, not generated Terraform/provider plans | Development cases passed |
| 1.2, public synthetic inputs | `aws_db_instance` for R2/R3/R4 | None; illustrative Terraform strings are not provenance | Development cases passed |
| 1.2, public synthetic inputs | `aws_ebs_volume` for R3/R4 | None; no producing Terraform/AWS version established | Development cases passed |
| 1.0 / 1.1 are accepted implementation targets; separate per-minor fixture evidence is not established | No additional tested shape claim from acceptance alone | Unresolved | Per-minor validation remains open |

Other major formats reject input; unlisted minor formats are unsupported for this
policy edition. Familiar resource names require canonical
`registry.terraform.io/hashicorp/aws` identity and managed mode. Data resources
are not applicable. Missing completeness/errored flags stay unknown unless a
separately tested producer profile establishes their omission semantics. Unknown
extra fields do not expand detector coverage.

Inline `aws_security_group.ingress` and newer standalone
`aws_vpc_security_group_ingress_rule` are unsupported R1 shapes. Prefix-list and
security-group sources retain unsupported coverage even beside a known risky CIDR.
R1 covers ports 22/3389 only. R4 excludes RDS clusters, DynamoDB, S3, EFS, ElastiCache
and generic instances. Unsupported targeted shapes and unresolved required facts
make review inconclusive rather than negative. A valid finding can coexist with
that coverage loss. No Terraform or AWS provider compatibility version is inferred.

| Interface | Development evidence | Remaining boundary |
|---|---|---|
| Python package / CLI | Pinned environment, installation/build and keyless CLI checks executed | Rebuild/recheck the final distributable after doc changes; broader dependency/license audit and release remain separate |
| Report bundle and typed wire | Bound/legacy inventories, validation, finalization, privacy, escaping and selected failure/deadline regressions passed | Not every crash, filesystem or operating system is established |
| Evidence resolver / viewer | Exact JSON types, pointers/masks, mutation refusal, explicit source pin, standalone and batch tests passed | Hash consistency is not producer authentication; entry/exit transactions may miss restored transient changes |
| Safe sharing | Fresh opaque identities and canonical regeneration verified on synthetic inputs | Whole bundles remain private; legacy/stale source must be reinspected |
| Schemas and integrated metadata | Fixed-registry/schema-export and version/admission regressions executed; 121 declarations | Descriptions do not replace validators or establish payload authority, independent custody or genuine execution |
| Journal/exposure/custody | Public synthetic accounting, replay, exposure, guarded-access and handoff regressions executed | Real authority, provider billing and sealed hidden custody are not established; selected failure tests are not universal crash/concurrency proof |
| L/P/M | Fake/offline finite-selection and protocol tests | Live provider/model/price/cap admission, independent semantic rubrics and genuine measurements remain incomplete |
| C/C-custom/T | Scanner adapters and public development plumbing are separate from the product | Actual binary/custom-policy pins and compatible captures need their own development receipts and required comparative measurements; no live scanner result is claimed here |
| Consumed edition | Public metadata/version/refusal regressions | Genuine seven-arm completion, external approval and real release custody remain incomplete |

Default review has no model, scanner, network, subprocess, cloud or apply path.
The development scanner harness has separately gated subprocess capability;
passing its synthetic tests does not establish an actual tool version or mapping.
A missing tool or mapping is incomplete work, not a true negative or proof of
incompatibility. All seven comparative arms remain NOT MEASURED.

## Distinct version namespaces

- Report private/shareable JSON stays 1.0.0. Artifact manifests are legacy 1.0.0
  (seven files, unbound) or bound 1.1.0 (eight files, including the private
  `run-manifest.json`). Verification counts four/five hashed payloads respectively;
  control files are not payloads. Legacy integrity never becomes provenance binding.
- Provenance profile 1 pins nine files; profile 2 pins eleven, including
  `contracts/report_wire.py` and `contracts/report_inventory.py`. Old bundles are
  not silently upgraded or repinned. Current-source sharing can require reinspection.
- Pre-access `m4-input-exposure-v1` intents and the legacy post-measurement
  `ExposureReceipt` results are different records. `HeldoutAuthorization` v2,
  `CompletionReference`/edition v2 and their separate pins do not grant oracle or
  scoring permission implicitly; obsolete v1 access/completion forms are refused.
- RunManifest schema version 1 distinguishes deterministic/evaluation stages.
  ArmRow versions 1/2 retain explicit legacy/live-eligibility limits. Binary
  introduced-risk predictions are not full-outcome predictions.
- Batch intake selects `m4-assessment-batch-transport-v1`, not the data-only
  `m4-schema-catalogue-v1`. The catalogue has description revision 1 and export
  manifest version 2 with a separate catalogue pin and COMPLETE marker.

The [registry](../eval/runner/schema_registry.py) names actual canonical types and
literal payload versions; it invents no version for unversioned types. Dataclass
TypeAdapter descriptions do not add unknown-field rejection, and closed Pydantic
roots do not prove nested dict/Any privacy. The dictionary `ReviewReport` facade
and typed [report projections](../src/iac_review/contracts/report_wire.py) are
separate; [inventory](../src/iac_review/contracts/report_inventory.py) is the
canonical layout boundary. See [schema documentation](schemas/README.md) for
those descriptive limits; generation has executed, but descriptions confer no
provider activation, actor authentication or release approval.
