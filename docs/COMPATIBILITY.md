# Compatibility targets and evidence

| JSON minor format: parser-tested | AWS resource shape: fixture-tested | Producer Terraform / AWS pin | State |
|---|---|---|---|
| None yet; implementation targets 1.0 / 1.1 / 1.2 | None yet; intended `aws_security_group_rule`, `aws_db_instance`, `aws_ebs_volume` | Unresolved, no real producer run | Runtime unverified |

Other major formats reject input; unlisted minor formats are unsupported for this policy edition. Familiar resource type strings require canonical `registry.terraform.io/hashicorp/aws` provider and managed mode. Data resources are not applicable. Unsupported targeted shapes or unresolved required fields make required review inconclusive rather than negative.

Inline `aws_security_group.ingress` and `aws_vpc_security_group_ingress_rule` are unsupported R1 shapes. R4 excludes RDS clusters, DynamoDB, S3, EFS, ElastiCache and generic instances. Known facts can still yield a bounded finding alongside an unsupported component. Exact tested Terraform/provider/scanner versions must be pinned after activation, with separate fixture results for each format/shape cell. Synthetic handwritten fixtures are not evidence of a producer version.
