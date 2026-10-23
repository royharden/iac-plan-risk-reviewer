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
