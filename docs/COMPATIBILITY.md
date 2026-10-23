# Compatibility targets and evidence

| JSON minor format: parser-tested | AWS resource shape: fixture-tested | Producer Terraform / AWS pin | State |
|---|---|---|---|
| None yet; implementation targets 1.0 / 1.1 / 1.2 | None yet; intended `aws_security_group_rule`, `aws_db_instance`, `aws_ebs_volume` | Unresolved, no real producer run | Runtime unverified |

Other major formats reject input; unlisted minor formats are unsupported for this policy edition. Familiar resource type strings require canonical `registry.terraform.io/hashicorp/aws` provider and managed mode. Data resources are not applicable. Unsupported targeted shapes or unresolved required fields make required review inconclusive rather than negative.

Inline `aws_security_group.ingress` and `aws_vpc_security_group_ingress_rule` are unsupported R1 shapes. R4 excludes RDS clusters, DynamoDB, S3, EFS, ElastiCache and generic instances. Known facts can still yield a bounded finding alongside an unsupported component. Exact tested Terraform/provider/scanner versions must be pinned after activation, with separate fixture results for each format/shape cell. Synthetic handwritten fixtures are not evidence of a producer version.

| Interface | Source state | What remains unverified |
|---|---|---|
| Python package / CLI | Python >=3.12, Pydantic v2 dependency range, `iac-review` entrypoint in `pyproject.toml` | Resolution/lock/audit, package build/install and entrypoint execution |
| Report bundle | Schema 1.0.0 private/shareable JSON/HTML, local artifact manifest and COMPLETE/ABORTED marker | Target-filesystem behavior, deadlines, failure/rollback/crash cases |
| Pinned evidence viewer | `source_view.verify_report` / `view_evidence` plus main CLI `verify-report` / `evidence` source | Actual invocation, mutation/privacy/effect execution; producer authentication deliberately not claimed |
| L/P/M | Fake/protocol executor, provenance, fake-only driver | Approved live adapter/model/price/caps, actual usage, independent scoring/rubric evidence |
| C/C-custom/T | Runner/adapters, explicit driver and scorer bridge source | Exact scanner/binary/dependency/policy pins, sandbox, mapping and real capture compatibility |
| Integrated run metadata | Separate RunManifest/preflight library, binary-target scoring and schema-export bindings now present | Actual schema generation, metadata/payload trust boundaries and end-to-end consumption |
| Ledger operation | Existing start/terminal/reconcile library; operator CLI source in progress | Completed operator command interface, reconciliation/crash/concurrency execution |

No cell in this table advertises a tested version. JSON format and provider shape
support are separate axes; passing synthetic parser examples later cannot by itself
pin a real Terraform/AWS producer profile. Missing flags stay missing unless an
explicit tested producer profile resolves their semantics. Unknown extra fields
do not add detector coverage.

Binary introduced-risk rows are a separate explicit target, not an equivalent
full outcome. D exact requires full-outcome rows. Optional producer exports and
strict all-attempt accounting do not confer live eligibility; fake/legacy rows
still require rejection or explicit incomplete status under v2 pins.
