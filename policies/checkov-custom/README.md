# Candidate action-aware Checkov policies

`m4_policy.py` independently implements the four selected predicates over raw
resource changes. It imports neither product detectors nor oracle labels. It is
implementation source, so its authors are ineligible to author/check hidden gold.
`m4_checks.py` is a Checkov external-policy entrypoint with four registered checks.
The later adapter supplies the same raw JSON file/path digest already passed to
Checkov through `IAC_CUSTOM_PLAN_JSON` and `IAC_CUSTOM_PLAN_SHA256`; it supplies no
extra HCL, labels, outcomes or product findings. The callback address and ordered
actions must match that file. Sensitivity/unknown masks dominate field values.

The callback returns FAILED only for introduced risk. PASSED includes unchanged
risk and means a negative for that one comparison target, never infrastructure
safety. Required unknowns, unsupported sources, callback mismatches and missing
raw-plan inputs return UNKNOWN. Binary scanner results cannot recover exact
unchanged/clear or reason/evidence labels; those cells stay unrepresentable.

`mapping.json` is a candidate contract with null pins and unverified compatibility,
not a validated `artifacts.Mapping`. Do not populate it with invented versions.
For later activation pin every Python policy/helper file, its complete installation
dependencies, and the generated policy inventory; verify that Checkov loads these
checks and emits UNKNOWN rather than dropping it as PASS. No dependency is vendored.

The inspected [upstream parser](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/plan_parser.py)
walks planned_values and passes address/actions/change-key metadata, not complete
before/mask facts. Delete-only resources may never reach these callbacks. They
remain missing/incomplete for C-custom; do not manufacture scanner observations
by running `m4_policy` separately. Replacements require actual callback proof.
Address/deposed collisions are rejected rather than silently merged.

Source was syntax-inspected only during Dirty Mode. No Checkov import, policy
registration, fake invocation or scanner execution was performed. Official
[external-policy API](https://www.checkov.io/3.Custom%20Policies/Python%20Custom%20Policies.html)
and [plan metadata docs](https://www.checkov.io/7.Scan%20Examples/Terraform%20Plan%20Scanning.html)
are design references; they are not tested release pins.
