# Synthetic demonstration inputs

These files are hand-authored illustrations, not Terraform-generated plans,
producer compatibility evidence, an independent oracle or held-out acceptance
cases. The `terraform_version` value illustrates metadata only. No Terraform
or AWS provider was run to create these files.

- `public-ssh.json`: standalone world-open SSH creation, plus private address and
  marked/unmarked value canaries. Address/pointer identity may appear only in the
  sensitive private report. Attribute canaries must appear in no report/capsule.
- `port-443.json`: a look-alike outside R1's fixed administration port set; this
  does not assert general Internet exposure safety.
- `unknown-port.json`: necessary ports unknown; preserve uncertainty.
- `stateful-replacement.json`: ordered replacement with known existing storage;
  unknown after values and absent optional replace paths do not erase R4 intent.

Construction only: none of these inputs has been executed in Dirty Mode.
