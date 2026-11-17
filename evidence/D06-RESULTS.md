# D06 construction and qualification evidence

The frozen 51-native/six-Go cohort is implemented and locally qualified at core
commit `5fd6cee1bae477048bf0045b691ee8bdf334e216`. Core main remains
`976b23290857be613005eea5cdc130d0f457b8c3`; no core source, feature or main branch
was changed. These are supplemental Intel macOS engineering observations, not
four-platform or release acceptance.

## PR errors addressed first

[Selective CI triage](d06-pr-ci-triage.json) binds the original jobs and exact
heads. PR #200 exhausted its CodeQL job time budget; the equivalent #202 CodeQL
job completed. PR #202 encountered Go dependency download timeouts after eleven
preceding ownership groups passed. Only the two affected jobs were retried.
No source defect was established, so no speculative core patch was made. Retry
results were not awaited. The focused local foundation lifecycle race test passed
with Go 1.26.5 and a verified offline module cache.

## Construction and final comparison

[Final cohort evidence](d06-clean-cohort-qualification.json) records two independent
full native/Go constructions and two separate bounded repairs. Each repair rebuilt
eight native dependency units through the existing native owners, retained the
other 43 native units and six Go commands byte for byte, and finalized external
zstd separately. Original stages and evidence were preserved. The first original
construction stopped at an owner fixture and has a separate
[read-only requalification](d06-retained-requalification.json); it was not relabelled
as a successful original two-round invocation.

The final candidates match across all **1,250 entries**: 1,248 regular files and
two relative links, including modes and native receipts. Their canonical payload
inventory SHA256 is
`f846ea311ba10a43da7f3bc9cf79c5e32cdaf6dfe12637f11f79b21bf80bf752`.
Candidate B is the selected delivery-record input. Both candidates passed:

- All 51 native receipt checks and six compiled Go command/version checks.
- The detached audit for 20 SDK producers, including 12 ordinary consumers,
  foundation/SNV mechanics and SBV C/C++/provider ABI checks (45 audit commands).
- Six existing installed-owner tests, with no skipped selections.
- Final native loader checks, privacy scans and static-archive metadata checks.

The exact [curl/zstd input build](d06-external-inputs.json) passed and a relocated
consumer linked and ran both libraries. Its TLS backend selection is recorded.
That same exact external input was reused for both constructions; independent
external rebuild reproducibility and live TLS/provider acceptance are not claimed.

## Corrections exercised by the cohort

The initial partial build exposed local ownership/timestamp metadata in static
archives. Deterministic settings and strict inner-archive checks now prevent it;
that interrupted stage remains incomplete. The
[archive privacy record](d06-static-archive-privacy.json) retains the observation.

The SNV tamper fixture assumed every file under a prefix was regular. Its corrected
fixture receives complete, byte-verified native receipt units while the other
owner tests use the full prefix with legitimate external library symlinks. Core
ownership guards were not weakened.

[Reproducibility diagnosis](d06-reproducibility-diagnosis.json) found unused Apple
archive symbol-table padding and private initial link RPATHs. The finalizer now
clears only validated unreferenced padding before receipt sealing, preserving
object bytes and offsets. Initial linking uses stable install paths so private
build paths do not influence linker UUIDs. Two independent repaired outputs match;
no UUID or receipt was hand-forged.

The source collector preserves exact original toolkit source as well as current
repair scripts, explicitly labels inherited artifacts, and checks all build,
imported and repair helper hashes. Native notices in source-declared documentation
directories receive exact source-byte verification. Unchanged public upstream
curl TLS fixtures and attribution overlaps have archive/member-hash-bound scan
exceptions; no exception applies to installed payloads or publisher-added files.

## Final source SDK and removal campaign

The [final SDK closure](d06-sdk-closure.json) passed 600 bounded commands against
candidate B. It compiled and ran five-core SNV APIs, exercised the unchanged public
Go SDK roundtrip using a synthetic 15-record native fixture, and checked every
one of the 51 native owners for applicable byte/header/export/receipt tampering,
partial-removal admission refusal, resumed removal and repeated removal. Unrelated
Go, external and sentinel files were preserved. The original final candidate and
source remained unchanged. This is disposable-stage qualification; it does not
claim live manager/process retirement or the complete historical L20/L22 campaigns.

[Focused tooling validation](d06-focused-validation.json) records 145 passing
regressions (74 build-cohort and 71 qualification cases), plus workflow validation. Unchanged broad core suites were not rerun.

## Hosted cohort repair follow-up

The first hosted D06 run completed with four platform failures. The
[repair record](d06-hosted-cohort-repair.json) binds each original diagnostic and
records 166 passing focused checks, a real Go failure/fix reproduction and a
compiled Darwin archive finalization/link test. Full frozen-graph preparation,
pre-seal archive metadata finalization and exact reachable system TLS dependency
records address the three observed failure classes. Confirmation on the four
primary hosted profiles remains pending; prior candidate evidence is unchanged.

## Delivery records and remaining gates

The [completed delivery record](d06-delivery-record.json) binds candidate B to
51 native records, six Go artifacts, 131 retained notices and 18 exact linked Go
source modules. Its corresponding-source archive contains 7,480 entries
(118,231,040 bytes), including the reviewed core source, unchanged pinned curl/zstd
archives, the exact original toolkit and the current repair toolkit. Archive
SHA256: `6952acd7fef459209af6ed42d20507195805d0ad026232e661741cdc99156f49`.
The archive and binary stages remain local candidate artifacts; code and portable
evidence are pushed. The record is complete with publisher review pending. It does
not grant redistribution approval, publisher trust or publication authority.

Remaining release/safety gates include:

- Observed results and privacy-approved final bytes on the four primary profiles;
  actual manager, privilege, fresh-host and delivered-byte qualification.
- External runtime carrier ownership; precise native restart/delete crash and
  response-loss boundaries; escaped process lifetimes, audit recovery and
  unsupported raw/C++/shared-environment ownership.
- Genuine distinct-release upgrade, swap, selection and rollback journeys.
- Publisher signing/trust, applicable notarization and system-runtime review,
  final Anaconda and Cloudflare delivery/retrieval, and independent/backup review.

Optional native SDKs, the protected administrator and physical/provider-specific
claims retain separate gates. No CI outcome was awaited, package published,
provider activated or main branch modified. The feature freeze remains in force.
