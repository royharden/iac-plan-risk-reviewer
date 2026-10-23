# Public development-only scanner inputs

This change contains generator/test/documentation source only. The generator was
not imported or run, and no generated input corpus, expected labels, scanner
results, gold or hidden cases were created. Runtime behavior remains unverified.

`eval.scanners.dev_inputs.build_inputs` defines a deterministic bounded recipe.
It uses no detector, scanner, oracle, Terraform/provider tool, account, clock or
random input. Resource facts vary across the selected standalone SG/RDS/EBS shapes,
all ordered action forms, IPv4/IPv6, all/numeric TCP protocols, masks/unknowns,
absent/null fields, outside-scope resource/action shapes and malformed/deposed/
duplicate-identity probes. Case IDs and configuration/mutation ancestry are stable.
There are no expected risk or admission outcomes, truth labels or independent
oracle claims. A fact such as a Boolean after-value is input data, not a verdict.

Each recipe shares explicitly named configuration and mutation lineage with its
public ancestors. Shared lineage must never be treated as split-independent.
Every future bundle/case declares development_only=true, independent_gold=false,
heldout_eligible=false and synthetic provenance. Hidden oracle staffing, custody,
labels and independent source review remain separate nonauthoring work.

The recipe caps 96 cases, 64 KiB per raw case and 2 MiB total case bytes; admission
probes are intentionally small. The source uses complete/errored and format tags
as synthetic JSON shape assumptions, plus synthetic resource schema_version=0.
It omits terraform_version and claims neither producer nor provider compatibility.
Optional planned_values/configuration/prior-state shapes are synthetic aids for
later scanner inspection, not proof of Terraform-generated validity. Delete-only
resources are omitted from planned_values; no callbacks are invented. Raw unknown/
sensitive masks remain in resource_changes. Scanner-specific behavior over those
fields must be verified separately on actual selected distributions.

Later `scripts/build_scanner_dev_inputs.py --out <new-dir> --build-sha256 <actual>`
can write inputs, a portable bundle.json with exact raw-byte hashes and ancestry,
and driver-manifest.json with absolute paths for that output directory. No scanner
arm configuration/pins are fabricated: arms is empty and a later driver run would
remain incomplete until genuine activation inputs are supplied. Malformed and
deposed/duplicate probes are indexed in bundle.json as admission_probe and omitted
from the ordinary comparison manifest; their classification is a usage boundary,
not a measured admission result. No fake scanner output is generated.

Only explicit writes to a new nonsymlink directory are supported; existing bundles
are never replaced. STARTED remains on interruption and COMPLETE is created last.
Partial directories are preserved for inspection, not silently repaired/deleted.
Case bytes and portable metadata are deterministic for this recipe/build; absolute
driver paths vary with the caller's chosen output directory. The caller supplies
the build digest; the generator does not use Git or authenticate that declaration.

Do not run any generator/test/scanner command during Dirty Mode. Later meaningful
verification must check recipe/hash/lineage determinism, actual scanner format and
callback compatibility, malformed input rejection and no unexpected effects. No
generated count, hash match or successful write is a correctness measurement.
