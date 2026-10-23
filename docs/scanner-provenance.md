# Scanner provenance bridge

`eval.scanners.scoring_bridge` consumes actual driver ComparisonRow/ScanArtifact
receipt shapes and D6's ArmRow, EligibleMeasurement and EligibilityManifest. It
imports no detectors, oracle labels, scanners or source plans, and performs no
execution or file writes. Source construction is runtime unverified.

The trusted caller provides an external canonical report digest and edition ID.
Optional execution eligibility must arrive with its separately approved canonical
EligibilityManifest digest. A digest embedded in a submitted report cannot approve
that report. Missing approval leaves rows incomplete. Wrong pins/edition, duplicate
cells/attempts and malformed or foreign profile/plan identity reject the import.

For every row, `measurement_ref` identifies case/resource/rule/arm/input/capture/
mapping. `provenance_digest` binds that exact binary prediction to the capture's
version, executable, dependency/version receipts, config, invocation, custom-policy
manifest, enabled checks, raw exit/stdout/stderr hashes, duration/truncation, build
and declared output/time bounds. The external execution owner can approve an
EligibleMeasurement with that provenance digest; this module does not issue one.
Successful import requires kind=executed, actual_execution_attested, matching
input/build/reference/provenance and the manifest's external pin. Fake source,
fake receipts, simulated rows, missing observations/mappings and legacy/unverified
metadata cannot promote themselves by claiming status ok or supplying a digest.

The shared scorer receives schema_version=2, measurement_kind=executed,
eligibility_ref=record_digest(EligibleMeasurement), prediction_target=introduced_risk
and introduced_prediction=Boolean only for an eligible complete cell. outcome stays
null for positives and negatives; no clear/unchanged labels are invented. Until
D6's optional binary fields are present, rows fail closed with
shared_binary_scorer_schema_pending and status not_run. No shared file is changed.
The scorer must receive the same eligibility manifest and expected digest when it
later scores these rows; the bridge result is not authority to self-pin a manifest.

Every supplied attempt is retained in immutable canonical metadata, including
timeouts/errors and attempts with no usable row. Every supplied comparison cell
survives as a row/disposition; absent coverage is not a true negative. Declared
bounds are tied to the invocation digest and external attestation, not represented
as independently measured enforcement. Raw observations are hashed by the driver
but omitted from normalized receipts for privacy; this bridge cannot reconstruct
or independently authenticate those observations from a hash. A trusted execution
owner must inspect private raw evidence before approval. Hash agreement proves
identity, not that an attestation is truthful, compatible or sufficiently scoped.

Current implementation lineage cannot supply independent oracle/acceptance proof.
No genuine scanner pins/eligibility, runtime tests, raw-output retention or hidden
measurements were created. Those remain later activation work after Dirty Mode.

## Source interface and regression coverage checkpoint

D6's shared-wire-v2-current.txt and actual scoring.py now define optional
prediction_target (default full_outcome) and introduced_prediction (default null).
Binary rows explicitly target introduced_risk and forbid any simultaneous full
outcome. The existing bridge's guarded source path matches those fields and its
executed-kind eligibility rules; no shared source change or fabricated eligibility
is needed. This is static interface reconciliation, not an executed schema/import
or scorer result. Independent oracle and genuine scanner measurements remain absent.

Targeted regression SOURCE covers these boundaries without duplicating existing
cases; none has run during Dirty Mode:

| Boundary | Source coverage |
|---|---|
| Missing arm/observation and unmapped action/type/provider | existing test_scanner_driver.py missing-arm and cell-gate cases |
| External report/manifest/config/bounds proof and wrong plan/arm | existing test_scanner_scoring_bridge.py provenance cases |
| Binary negative retains null full outcome | existing bridge regression plus new shared-wire rejection of an invented full label |
| Malformed/non-UTF8/duplicate-key scanner JSON | new test_scanner_output_boundaries.py parser/admission cases |
| Incomplete quiet output, contradictory categories, reported parsing errors | new Checkov output cases |
| Oversized input or stderr, valid-looking stdout after timeout | new bounded admission cases, complementing earlier stdout truncation/empty timeout cases |
| Deposed/duplicate address or repeated check/resource output | new lossy-identity cases |
| Same address but raw input mutation during injected capture | new complete artificial-pin fake-runner case; no executable is launched |
| Unknown/unrecognized Trivy output state | new unknown-preservation and rejection case |

Fixture checks, artificial pin files and fake outputs are implementation-owned
plumbing data, not actual scanner versions, independent expected risk labels,
compatibility evidence or executed measurements. Tests are later activation work;
source availability and AST parsing cannot close those runtime boundaries.
