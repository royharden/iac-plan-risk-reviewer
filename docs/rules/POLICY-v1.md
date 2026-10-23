# Declared AWS change predicates v1

This source policy implements the selected M4 plan's four narrow predicates. It
does not decide whether deployed infrastructure is secure, reachable, compliant,
recoverable, or appropriate for an organization. Source construction has only
received static inspection; runtime and independently authored semantic/oracle
acceptance remain unverified.

All rules require `mode=managed` and canonical provider
`registry.terraform.io/hashicorp/aws`. Data resources are not applicable. A matching
resource type with another provider is unsupported, not clear. Unrelated types
are inventoried as not applicable. Actions retain their order; unsupported action
sequences produce unsupported coverage. A managed read action has no write
transition for R1–R3 and no destructive action for R4. Source metadata, mode,
provider, type and actions are decision evidence.

The four outcomes for a supported predicate are `introduced_risk`,
`unchanged_risk`, `clear`, and `indeterminate`. An unsupported or inapplicable
evaluation has no outcome. A rule's `clear` applies only to that named predicate.
No tag or reviewer-context string suppresses a finding.

| Rule | Supported type/attribute | Severity | Declared positive |
|---|---|---:|---|
| R1 | `aws_security_group_rule` ingress | 4 | A newly exposed `(IPv4 or IPv6, 22 or 3389)` member |
| R2 | `aws_db_instance.publicly_accessible` | 3 | Create true or known false → true |
| R3 | `aws_db_instance.storage_encrypted`, `aws_ebs_volume.encrypted` | 3 | Known true → false on update/replacement |
| R4 | `aws_db_instance`, `aws_ebs_volume` | 4 | Delete or either replacement order with verified prior object existence |

## R1 exposure sets

An exposure member requires known ingress, protocol `tcp` or `6`, a valid integer
port interval within 0–65535 containing 22 and/or 3389, and a corresponding world
CIDR (`0.0.0.0/0` or `::/0`). Protocol `-1` includes both ports without reading port
fields. Known non-TCP protocols are negative for this bounded rule. CIDRs are
parsed with explicit family checking; missing/null/non-list source lists, malformed
CIDRs, and invalid port intervals are indeterminate when needed by the decision.
Boolean values do not count as integers. Both IPv4 and IPv6 list shapes are
required to establish a complete CIDR exposure set.

Set difference uses `(IP family, port)` members. Duplicate/reordered CIDRs do not
change the set. SSH already open plus newly open RDP is an introduction; narrowing
an existing exposure while leaving any member is unchanged risk. Database/search/
cache ports (3306, 5432, 1433, 6379, 27017, 9200) are outside this v1 predicate.

| After | Prior | Result |
|---|---|---|
| Known egress | Any | Not applicable; do not inspect unrelated fields |
| Known non-TCP | Any | Clear for R1 |
| Complete lists with no world CIDR | Any | Clear; unknown ports/protocol are irrelevant |
| Known TCP range excludes both policy ports | Any | Clear; unknown CIDRs are irrelevant |
| Empty known exposure set | Any | Clear |
| Nonempty known set | Create | Introduced risk; create semantics establish empty prior |
| Nonempty known set | Known set with new members | Introduced risk |
| Nonempty known set | Known set with no new members | Unchanged risk |
| Nonempty known set | Necessary prior unknown/sensitive/absent | Indeterminate introduction |
| Necessary after fact unknown/sensitive/absent/null/invalid | Any | Indeterminate |

Only facts used by a short-circuit proof are required decision evidence. Unknown
irrelevant facts may remain supporting limitations, never hidden decision failures.
Prefix-list or security-group sources are separately unsupported coverage. Known
CIDR risk can remain visible alongside that coverage; coverage still makes the
aggregate review inconclusive. Inline `aws_security_group` and
`aws_vpc_security_group_ingress_rule` are unsupported targeted shapes.

## R2 public accessibility

Delete is not applicable. A known false after value is clear without reading prior
public accessibility. True on create introduces declared public accessibility.
Known false → true introduces risk; true → true remains unchanged risk. Unknown,
sensitive, absent, null, or non-Boolean necessary values are indeterminate. A true
flag is declared public accessibility, not evidence of Internet routing.

## R3 encryption removal

Delete is not applicable. Create with a known Boolean after value is clear for
removal only, even when the value is false. Update, replacement and no-op compare
the known before/after Boolean values: true → false introduces removal; all other
fully known transitions are clear for removal. Missing/unknown/sensitive/non-Boolean
necessary prior or after values are indeterminate. Algorithms, key changes, and
whether unencrypted creation is acceptable are outside this predicate.

## R4 destructive intent

Create/update/no-op/read without delete is clear for R4. Delete,
`[delete,create]`, and `[create,delete]` with a verified non-null prior object are
introduced review-required destructive intent; order is preserved. Explicit null
or absent prior state is `contradictory_prior_existence`, not a benign negative.
Unknown/sensitive prior existence or a non-object prior shape is indeterminate.
Sensitive descendants do not negate an independently visible object-existence
fact. The resolver emits only a structural object summary, never prior values.

Optional `replace_paths` is supporting evidence at its own raw metadata pointer.
Its absence, unknown status or malformed content cannot erase known destructive
intent. It is never reinterpreted as an after-value pointer. Disposable tags,
backup assumptions, and reviewer context do not suppress R4. This rule asserts
neither actual data loss nor lack of backups.

Named unsupported R4 types are `aws_instance`, `aws_rds_cluster`,
`aws_dynamodb_table`, `aws_s3_bucket`, `aws_efs_file_system`, and
`aws_elasticache_replication_group`. They are coverage limitations, not negatives.

## Evidence and aggregation

Rules produce references; the report resolves every required decision reference
against the original file digest/resource identity/masks. A failed required
reference withholds the determinate finding and produces an explicit indeterminate
record. Optional references may be omitted with limitations. Sensitive values are
never interpreted as false. Unknown/sensitive markers can document limitations.

The CLI default threshold is severity 3, range 1–4. Introduced and unchanged risk
at threshold count toward risk exit. Report exit precedence is malformed/internal
3, required unsupported/inconclusive coverage 2, otherwise threshold risk 1,
otherwise complete evaluated scope 0. Risk remains visible alongside exit 2.
Independent semantic suites, hidden oracle lineage, privacy/effect checks, and
actual producer/provider compatibility are deferred, not passed by this document.
