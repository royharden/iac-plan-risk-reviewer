# Scanner source activation boundary

Dirty Mode construction only: no scanner, subprocess runner, fake, policy module
or test was executed. Default product imports never import these evaluation
modules. No dependency/version/profile is advertised as tested.

`eval.scanners.checkov_adapter.scan` handles C or, with an explicitly pinned local
external-policy directory, C-custom. `eval.scanners.trivy_adapter.scan` handles T.
Both require an injected Runner, absolute saved-plan/config/executable/scratch
paths, explicit check IDs and a pinned policy manifest. No submitted value becomes
a command/flag. No shell, arbitrary arguments, source enrichment, automatic version
probe, retry, installation or provider interaction is exposed.

`ScannerPin` requires version, executable digest, dependency-manifest digest and
version-evidence digest plus actual manifest/receipt paths. Missing pins return
not_run. Version evidence JSON must identify scanner_name, version,
executable_sha256 and dependency_manifest_sha256. Policy manifest JSON identifies
scanner_name, ordered check_ids and files sorted by name, each with name/sha256.
Every policy/bundle file is rehashed before/after capture. Built-ins use an empty
extra-file inventory with their installation bound by the dependency manifest;
custom policies pin all loadable Python/YAML sources; Trivy requires an explicit
preprovisioned pinned local checks bundle. Nothing downloads a missing bundle.
Pin manifests are private activation inputs, not generated evidence of measurement.

Provide an explicit JSON `{}` config file, with no hidden overrides; the argv
contains exact framework/input/output/check-selection and no-upload/download
options. The runner environment does not inherit provider keys or scanner/Python
overrides. It supplies scratch HOME/TEMP and only OS-loader bootstrap variables.
The future activation owner must prepare/verify a dedicated scratch directory,
dependencies and the cached bundle, then supply OS confinement denying network,
unrelated file access and child processes. CLI offline flags are not a sandbox.

`BoundedSubprocessRunner(activation_authorized=False)` rejects invocation. A later
explicitly authorized runner captures bounded stdout/stderr with concurrent drains,
kills the direct child on overflow/deadline and returns only hashes/normalized
observations to callers. Descendant/pipe confinement and pre/post hash races need
the later runtime sandbox and real tests; they are not established by source.
No raw stdout/stderr is serialized by an adapter. Keep raw output files only in a
later operator-owned private run artifact store. Resource locators in observations
are sensitive scanner metadata, not safe shareable identifiers.

FakeRunner always marks execution_kind=fake. Even well-formed successful fake
JSON yields live_eligible=false and cannot cross ScanArtifact.as_capture().
Missing mappings, skipped/unknown/absent checks, parse errors, hash changes,
ambiguous deposed identities, unknown exit codes, timeouts and truncation stay
explicitly incomplete. No adapter creates ArmRow, outcomes or hidden gold.
`cell_status` requires a verified arm/version/binary/policy mapping plus exact
managed AWS type/action and a decidable observation for every mapped check.
Eligible here means a raw observation may be interpreted under its predeclared
mapping; configuration PASS alone cannot imply introduced/unchanged/clear labels.

The existing INT-owned artifacts.py stays unchanged. Its Capture lacks a fake/live
field; only the guarded adapter bridge may supply live captures. Mapping requires
pins even when unverified, so missing-pin status lives in ScanArtifact instead of
invented Mapping values. The raw output parsers intentionally reject unrecognized
schema/profile details until a versioned compatibility adoption; such rejection
is not proof that a scanner itself is incompatible. No required C/C-custom/T arm
is measured or accepted by these sources.

Read-only upstream references (moving main/latest, not tested pins):

- [Checkov plan/action metadata](https://www.checkov.io/7.Scan%20Examples/Terraform%20Plan%20Scanning.html)
- [Checkov CLI options](https://www.checkov.io/2.Basics/CLI%20Command%20Reference.html)
- [Checkov plan parser](https://github.com/bridgecrewio/checkov/blob/main/checkov/terraform/plan_parser.py)
- [Trivy misconfiguration flags](https://github.com/aquasecurity/trivy/blob/main/pkg/flag/misconf_flags.go)
- [Trivy scan flags](https://github.com/aquasecurity/trivy/blob/main/pkg/flag/scan_flags.go)
- [Trivy report flags](https://github.com/aquasecurity/trivy/blob/main/pkg/flag/report_flags.go)
- [Trivy global flags](https://github.com/aquasecurity/trivy/blob/main/pkg/flag/global_flags.go)

Later activation must verify exact CLI flags, output schemas and local-only cache
behavior against the chosen verified distribution, exercise all action/mask/error
cells on development inputs, freeze mappings before hidden access, and retain
missing/unrepresentable cells and every failed attempt in comparative denominators.

## Capability inventory source

`eval.scanners.capabilities.inventory` and `scripts/scanner_inventory.py` export
metadata for separate C/C-custom/T arms, all four selected predicates, supported
and specifically excluded types, and the exact ordered action catalog. The
candidate custom policy contract is read as bounded JSON; optional mappings use
the existing strict artifacts.Mapping wire. No scanner binary probe/version call,
policy import, detector/gold labels or execution is performed by inventory.

Default built-in Checkov and Trivy cells have no invented check IDs. Custom policy
cells are candidate_unverified until separate compatibility work exists. Delete-only
C-custom R4 callbacks and deposed identities remain explicitly incomplete. Unknown,
sensitive, missing/invalid fact and unsupported-source limitations are retained;
there are no predicted outcomes, confusion counts or implicit true negatives.
A supplied verified mapping becomes declared_compatible metadata only, with its
exact version/binary/policy/evidence digests preserved. Every exported cell still
has measured_correctness=false and execution_eligible=false. Metadata availability
cannot replace the required scanner comparisons or approve an eligibility manifest.

The later CLI can print JSON or exclusively create a new --out metadata file.
Exit 0 means serialization succeeded, not compatibility or correctness. No inventory
command or regression source was executed during Dirty Mode. Actual activation,
scorer bridge/eligibility approval and runtime checks remain separate later work.

## Future explicitly granted pinned-local mode

The source CLI now names pinned-local for future actual local scanner execution;
legacy live is an alias with the same strict guard. Pending and fake-only remain
nonexecuting/ineligible defaults. No mode was executed during construction.
Runtime authorization, a confinement receipt and an execution-grant file with its
externally approved raw-byte SHA256 are all required. A Boolean alone cannot
activate BoundedSubprocessRunner. The existing runner remains the only subprocess
implementation; no provider/HTTP/Terraform/cloud path or second runner is added.

The closed m4-local-scanner-execution-grant-v1 metadata contains grant_id,
operator_id, build_sha256, comparison_manifest_sha256 and invocations. Required
True attestations are dirty_mode_closed, local_only, network_denied,
descendants_confined, no_provider_credentials and synthetic_input_attested.
The exact comparison manifest must itself declare development_synthetic scope and
synthetic_input_attested=true. A generated development input manifest does not
supply that operator approval automatically: its final bytes/config must be
approved independently before any later actual execution.

Each ApprovedInvocation binds arm/scanner/version, raw plan, executable,
dependency inventory, version receipt, empty config, custom/built-in policy
manifest, exact enabled check IDs and invocation_sha256. invocation_digest hashes
all fixed argv, cwd, complete sanitized environment, pinned file paths/hashes/caps
and all limits. That source helper does not execute a process. The operator must
review and approve these exact private metadata values externally; passing a
self-selected digest or reading a grant is not authentication of its author.
Missing, changed, duplicate or unknown fields/invocations refuse execution.

The local runner independently allowlists the source scanner profile in addition
to checking its approved fingerprint. Checkov is plan-only with explicit local
policy selection/config and enrichment/download/upload paths absent/disabled;
Trivy is config/terraformplan-json with pinned cache, no telemetry/version fetch
or ignore file. Cloud, external-check Git, arbitrary command and plugin flags are
rejected. C-custom is the only arm admitting its exact approved local custom-policy
directory/files. Sanitized environment is reconstructed, never inherited wholesale;
provider keys, PATH, PYTHONPATH and user-site configuration are not forwarded.
Unapproved scratch Python startup/custom Trivy module content is refused. These
source choices do not replace actual dependency/OS confinement verification.

A later authorized runner exclusively writes and flushes a payload-free start
receipt in its exact approved scratch directory before process creation; an
existing receipt prevents automatic retry/reuse there. A terminal metadata receipt
records whether a process actually started, raw exit/output hashes, time/limits
flags and the start/grant linkage. Process-start failure remains none/error,
never executed. Missing terminal receipts remain incomplete; partial files are
preserved for operator reconciliation. No raw stdout/stderr, input, secret or
private address map is written by these receipt helpers. Names are fixed by the
approved invocation digest, not submitted data. Network/process-descendant/pipe
confinement, crash durability/races and raw-output retention still need real
operator-owned runtime validation. No Docker/CI/sandbox provisioning is supplied.

Injected fake/protocol runners cannot produce live capture records merely by
returning execution_kind=live: capture marks such output invalid/none and removes
execution proof fields. FakeRunner cannot activate the real runner. Even a valid
actual captured local process is not scorer eligibility: the separate externally
approved v2 EligibleMeasurement/EligibilityManifest remains mandatory. Unknown
compatibility, mappings, output/identity failures and timeouts remain incomplete,
not true negatives. No genuine operator grant or scanner version is supplied here.

## Typed scanner RunManifest adapter source

`eval.scanners.run_manifest.adapt_scanner_report` consumes the actual normalized
driver/bridge records and actual D6 shared RunManifest, ComponentVersion,
CaseBinding, ArtifactRef, InvocationMetadata, AttemptMetadata and
EvaluationEligibility models. Callers supply externally approved report/eligibility
pins, actual policy/authority/semantic-suite digests, development-only typed ancestry
bindings and actual private artifact references. No source, oracle or artifact
payload is opened; no execution, eligibility issuer or file writer is introduced.

Exact scanner/config/installation/policy/receipt identities are retained as typed
components. Known missing-run components can be supplied explicitly as declared
metadata. Unknown mandatory fields return ScannerManifestResult.manifest=None and
explicit missing reasons, with all original bridge rows/attempts preserved. No
zero/default hash or invented unknown scanner version is generated to fill a
required shared field. Mixed/missing raw input, duplicate identities, widened
held-out scope and reused start/terminal proof across attempts are rejected.

Start/terminal/operator digests must bind supplied private producer artifact
references before an actual-source attempt may be represented as executed.
Those bindings are metadata attestations, not independent file/execution
authentication. Mock provenance overrides valid-looking execution references.
Success still cannot claim scorer eligibility without separate approved v2 evidence.
Every invocation leaves all_attempts_attested=false; source metadata cannot prove
there were no lost/crashed/unreported calls. Failed/timeout status, terminal hashes,
time and unknown billing are retained; no fake zero-cost measurement is introduced.

The typed manifest is private reproducibility metadata. A separate
public_summary_json contains count/status/kind/missing-reason fields only, excluding
private paths, raw-source hashes, locators and payloads. Hidden oracle/private-map
and outward payload artifact references are not accepted by this scanner adapter.
Missing authority/semantic/eligibility/component inputs keep a useful draft; they
are not permission to create gold or substitute implementation-generated approval.
Construction checks are AST/source inspection only. Actual imports, model joins,
receipt authenticity, runtime scanner effects and full comparative/finished-product
acceptance remain unverified.
