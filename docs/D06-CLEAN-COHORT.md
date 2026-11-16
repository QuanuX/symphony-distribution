# D06 clean native and SDK build cohort

D06 prepares the existing frozen suite for distribution. Core source remains
`5fd6cee1bae477048bf0045b691ee8bdf334e216`; core main remains separate. This work
adds packaging, provenance and qualification tooling in `symphony-distribution`.
It does not select packages for a user, activate providers, merge core branches,
or authorize publication.

## Selected contents

The source-derived [cohort](../build-cohort/cohort.json) reconciles six original
core records, including the W12 construction plan. Each of the four required
profiles selects 51 complete native receipt units and six core Go commands.
The eight optional native units and protected profile administrator retain their
independent selection. The Linux observer is not selected on macOS. All 73 source
roots remain classified; this is not a claim that every root is a runnable package.

The core SDK cohort contains 20 producers, with ordinary copied consumers,
foundation/SNV mechanics and SBV C/C++/provider ABI checks. Source and SDK delivery
are distinct from runtime installation and from the user's active Maestro choice.

## Clean build and final-byte checks

The builder accepts the exact bound core repository plus either the separately
verified S08 derived source export or a clean archive of the committed Git tree.
It never builds from a developer's working tree or captures their home, credentials,
profiles, stores or hardware state. The distinction between those two source modes
is retained in the evidence. A hosted raw-source build is not automatically a
privacy-approved distribution candidate.

Each build uses a new private home, temporary directory, native build tree and Go
build cache. Go module replacement and ambient dependency settings are disabled.
The exact public module cache is checked before use. Native units build in their
recorded dependency order and use installed SDK exports with exact version and
import-location proofs.

curl 8.7.1 and zstd 1.5.7 are rebuilt from the pinned upstream archives and notices.
Optional curl dependencies are disabled. macOS selects SecureTransport; Linux
records explicit system OpenSSL inputs. Build-time TLS selection is not a live
TLS test. Final loader checks reject development-prefix fallback and admit only
package-relative dependencies or recorded platform runtimes.

Native loader edits, stripping and local Apple ad hoc signatures occur before
receipt sealing. Ad hoc signatures provide no publisher identity. The native
receipts are verified again after moving the stage and after SDK/owner tests.
External dependency files have a separate build inventory: copying them into a
stage does not grant a native lifecycle owner or constitute final Conda ownership.

Two clean rounds compare final payload files, modes and relative links. Build
intermediates can be reclaimed only from the current invocation after its receipt
proof and logs are retained. Existing candidates, recovery evidence and user
installations are not cleanup targets.

## Qualification and delivery boundaries

Detached SDK consumers compile outside the source tree against the relocated
stage. Existing installed-owner fixtures require actual pass events and refuse
skipped tests. Additional retained SDK roundtrip, removal and tamper checks keep
their own report, so a focused subset cannot be mistaken for the complete historic
qualification campaign.

The local Intel macOS build is supplemental engineering evidence. The workflow
selects macOS 15 ARM64, Ubuntu 24.04 AMD64, Ubuntu 24.04 ARM64 and Ubuntu 26.04
AMD64. Pushing it requests those builds; it does not establish their results.
Neither local nor hosted build success establishes actual-manager behavior,
fresh-host acceptance, physical hardware qualification, live-provider acceptance,
or independent release approval.

The release gates still require applicable external-runtime carrier ownership,
privacy-approved final bytes on each selected platform, publisher signing/trust,
final Anaconda and Cloudflare delivery, actual fresh-host installation and lifecycle
journeys, and independent/backup review. The D05 live-removal and whole-profile
safety boundaries remain in the [S08 dossier](../dossier/README.md). No current
safe refusal is relabelled as a successful removal.

See the [build instructions](../build-cohort/README.md) and the D06 evidence report
for the exact completed checks and remaining observations. Historical S06–S08
records remain unchanged and do not silently qualify these newly built bytes.
