# D11 primary artifact admission and acceptance preparation

This increment keeps the feature freeze and core/client main unchanged. It
prepares the next qualification steps without substituting reports for packages
or engineering checks for independent acceptance.

## Existing run observation

The one initial recovery-run snapshot found all four contract jobs passed, the
macOS producer queued, and the three Linux producers compiling their two clean
cohorts. No failing step or uploaded artifact was present. The exact observation
is [retained here](../evidence/d11-primary-recovery-snapshot.json); it is not a
claim about later completion. A bounded artifact-availability refresh after
preparing this increment again found zero artifacts in all four runs; see
`evidence/d11-artifact-admission-status.json`. No recovery job was retried or
duplicated, and no CI completion was awaited.

The current documentation head's three workflows passed. The implementation
head's five push workflows also passed, including wrapper and retention
contracts. See [the CI snapshot](../evidence/d11-ci-snapshot.json). No new CI
result was awaited. These existing results do not qualify new D11 source.

## Prepared artifact and owner checks

The [offline admission helper](D11-ARTIFACT-SELECTION.md) validates an explicitly
selected completed producer, artifact ZIP, original source and reviewed export,
all 58 carriers, both build rounds, SDK/qxctl evidence and original toolkit. It
emits an actionable selection only after the entire check passes. The subsequent
hosted transport re-fetches authoritative GitHub metadata and the selected bytes;
a saved metadata snapshot cannot authenticate itself.

The [primary owner campaign](../qualification/d11_native_maintenance.md) uses the
same admitted capsule and exact original core source to configure and exercise
the existing 51 receipt owners in private disposable prefixes. It checks all
612 required configuration/inspection/refusal/removal commands and preserves
other packages, caller state and original evidence. Same-candidate restoration
is recovery, not an upgrade or rollback between distinct releases.

The manual `.github/workflows/d11-primary-gates.yml` requires a committed
selection and its independently selected digest. It uses the matching primary
runner and isolated inspection tools, and retains only bounded evidence. Push
events run the affected contracts, without starting a native build or campaign.

No primary selection, wrapper-only execution or 51-owner primary result has
been manufactured from the unfinished producers. Actual campaigns remain
pending completed artifacts and explicit selections. All 41 focused tests
passed, along with workflow validation, the actual reviewed dependency-map
regression and handoff binding/privacy checks. Exact evidence is recorded in
`evidence/d11-implementation.json`. The complete 267-file implementation source
export also passed privacy scanning; its exact commit and archive digest are in
`evidence/d11-toolkit-source-seal.json`.

## Remaining acceptance work

The [review handoff](D11-REMAINING-GATES.md) supplies concrete fresh-host/client,
native installer, live/shared-root maintenance, genuine version transition,
signing/trust, legal, independent acceptance and recovery workorders. The human
template preserves the user's legal-review assignment while leaving decisions
and independent roles pending. Its existing evidence files are hash-bound.

The [integration snapshot](../evidence/d11-integration-snapshot.json) verifies
13 current PR heads and their branch relationships. Core #199–#202 each have
59 successful checks, and client #8 has one successful check. Client #6 diverges
from current main, so its main-side onboarding/catalog changes must be preserved
when preparing final integration. Distribution #3 still displays three old
Linux SDK failures; the compiler-alias fix exists downstream and the later
four-profile D06 run passed. Neither a green downstream head nor this handoff
changes that old PR's status. No branch stack was rewritten or merged.

No actual legal decision, independent acceptance, recognized publisher trust,
source integration or release approval is inferred. Native `.pkg` installation,
service activation and Cloudflare installer publication remain unperformed.
