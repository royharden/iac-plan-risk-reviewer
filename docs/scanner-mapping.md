# Scanner comparison source and mapping boundary

Dirty Mode source only. No scanner, fake, subprocess, application import or test was
executed. The adapters/driver/script/test source are constructed; runtime, upstream
compatibility and all C/C-custom/T measurements remain unverified. Dependencies
and exact scanner releases are not installed/pinned by this source change.

Arms remain separate: C built-in Checkov, C-custom independently authored
action-aware Checkov policies, T compatible Trivy. Each arm receives identical
frozen development-synthetic plan bytes. Source enrichment is always off. No
product detector or gold supplies scanner output. Missing tools/checks/mappings,
unsupported actions/types and timeouts remain incomplete, never true negatives.

`eval.scanners.driver.compare` consumes a `m4-scanner-run-v1` manifest and explicit
injected Runner. With no runner it emits incomplete rows. `fake_only=True` accepts
only explicit bounded, hash-pinned fixture stdout files and invokes FakeRunner;
it rejects an injected runtime runner. No executable pins are invented for this
mode. A well-formed fake output can exercise parsers later, but all rows remain
simulated/ineligible with null predictions; no live Capture or ArmRow is emitted.

The manifest has input_scope=`development_synthetic`, build_sha256, cases and arms.
Cases contain opaque case_id, absolute plan_path, exact plan_sha256, and complete
private bindings `resources: [{resource_id, address}]`. No labels, split IDs or
oracle files are consumed. Duplicate/deposed identities are rejected. The driver
rehashes each plan before every arm and after the batch; mutation aborts results.
Hidden inputs require a separately authorized custodian driver, not relabeling a
held-out manifest as development. This declaration does not authenticate custody.

Arm keys are C/C-custom/T. Live settings include pin (see scanner-activation.md),
config_path, workspace, check_ids, policy_manifest_path/policy_sha256 and mappings
(the existing strict artifacts.Mapping wires). C-custom also names custom_policy_dir
and custom_policy_files; T names bundle_files. Each file entry has absolute path,
sha256 and bounded max_bytes. No command/flag comes from resource values. Pin and
mapping provenance must be supplied from actual later activation, never fixtures.
Fake settings instead use `fake_fixtures: {case_id: {stdout_path, stdout_sha256,
exit_code, timed_out}}` plus check_ids; no real binary/version pin is required.

`scripts/eval_scanners.py` defaults to mode pending. Explicit fake-only mode is
offline plumbing, returning exit 2 / SIMULATED_INELIGIBLE. Future live mode requires
authorize-runtime and a current operator sandbox receipt attesting Dirty Mode
closed, runtime authorization, denied network, confined descendants, private run
directory and matching build digest. A receipt records operator responsibility;
it does not create confinement. Do not run any mode during Dirty Mode. Exclusive
output directories live directly under product results/; prior runs are never
overwritten. New scanner-comparison.json and scanner-rows.jsonl contain opaque IDs,
input/mapping/capture hashes and raw-exit/output-hash/time/timeout/error metadata,
not original plan/addresses or raw stdout/stderr. Keep raw outputs only in later
operator-owned private artifacts; these sources do not copy them into reports.

ComparisonRow is a separate immutable target-specific wire: introduced_prediction
is Boolean only when a live capture and exact verified cell mapping are eligible;
otherwise null. It preserves row/status/denominator identity for every required
rule/resource/arm. A binary PASS cannot recover clear versus unchanged_risk or
the exact deterministic reason/evidence. Therefore the driver does not manufacture
successful scorer ArmRows from those observations. INT owns any future scorer
extension accepting binary introduced-risk targets. Do not coerce an absent row
or a negative-with-unknown-full-label into a known-clear product decision.

Candidate custom mappings live in policies/checkov-custom/mapping.json and are
unverified/null-pinned. R1 uses exact world-exposure set differences for ports
22/3389; R2 known create/public false-to-true; R3 known encryption true-to-false
on update/replacement; R4 destructive actions on exactly RDS instance/EBS with
known prior existence. Raw-plan masks/actions are read independently by custom
policies. Checkov's inspected planned_values callback path can omit delete-only
resources; those R4 cells stay incomplete. Unknown callbacks remain incomplete.
Do not run the helper separately and call its output a Checkov measurement.

Follow [activation details](scanner-activation.md) and upstream references there.
After Dirty Mode closes, independently verify exact versions/flags/schema,
compatible inputs and each exact transition mapping on development cases, retain
failure provenance and freeze all policies before hidden access. Rule agreement
does not establish independent gold; imported hash metadata is not independent
authentication. No source/license from tfexplain or other projects is copied.
