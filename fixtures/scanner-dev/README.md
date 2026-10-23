# Public scanner development recipe source

No generated input corpus is checked in or created during Dirty Mode. Generator
source lives in eval/scanners/dev_inputs.py with the later explicit entrypoint
scripts/build_scanner_dev_inputs.py. See docs/SCANNER-DEV-INPUTS.md for the format.

All future outputs are PUBLIC DEVELOPMENT ONLY, synthetic and implementation
authored. They are not independent gold, expected risk labels, hidden cases,
held-out evidence, Terraform-produced plans or measured scanner compatibility.
Each generated bundle and case metadata declares development_only=true,
independent_gold=false and heldout_eligible=false. Never promote these recipes or
their configuration/mutation descendants into a newly independent holdout.
