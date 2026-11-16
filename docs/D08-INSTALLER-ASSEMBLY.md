# D08 review installer assembly

D08 repairs the qxctl source stamp and prepares modular, inactive review delivery.
Core remains at `5fd6cee1bae477048bf0045b691ee8bdf334e216`; no product feature,
command, adapter contract or main branch is changed. The client increment is
[PR #8](https://github.com/QuanuX/symphony-codex-ipc-mcp-and-skills/pull/8), stacked
on D07. Distribution implementation is
[PR #5](https://github.com/QuanuX/symphony-distribution/pull/5).

## Honest source identity

The unchanged original-Git qxctl recipe produced two equal binaries, SHA-256
`abbcdd7e4c66ae74cf5faefe28e30600446d2a1859bb24e4bf04fdd84e40d6b4`.
All 291 compiled or embedded inputs on the recorded supplemental Intel macOS
profile match the reviewed derived export. The stamped component identifies the
original Git commit/tree and dependency map. It does not relabel the transformed
whole-repository export as an original Git tree.

A distinct immutable D08 cohort replaces only qxctl. It preserves all 51 native
receipts, the other five Go binaries, 20 SDK export units and all 1,250 payload
entries. D06/D07 candidates and their historical observations remain unchanged.
This is a bounded repair, not a fresh whole-cohort or primary-platform build.
Future clean cohort builds now call the same exact-source helper for qxctl and
retain its proof in the delivery record.

The client catalog has no command-descriptor changes. Fresh extracted-package
qualification passed 22 actual Codex cases (11 stdio, 11 same-user IPC), including
default denial, explicit disposable-owner mutations and cleanup. The original
W13 verifier now passes the embedded-source-stamp gate without modifications.
Model turns, GUI onboarding, live providers and fresh-user installation remain
outside this deterministic local qualification.

## Modular carriers and wrappers

The core cohort has 58 independently named inert Conda carriers: 51 complete
native receipt units, six Go delivery units and one explicit external runtime/SDK
unit. Complete SDK exports remain with their owners. The bound client is a
separate additional carrier. Reviewed corresponding source is a separate optional
carrier; it is not required in every standard installer.

Every original payload path belongs to exactly one carrier. Native receipts,
relative loader paths and the two external curl symlinks are preserved. Neutral inner
TAR ownership and timestamps exclude publisher account metadata. The outer Conda
container retains standard writer timestamps; this is not a claim of reproducible
outer archive bytes across separate assemblies. Conda
package handling writes the archives; this assembly step is not a compiler run
or a claim that conda-build rebuilt the native programs.

The initial full-suite selection lists exact reviewed archives once. No permanent
metapackage forces independent modules to share one version or upgrade together.
A carrier transaction changes inert delivery files. Runtime installation,
selection, service start, retirement and native cleanup still belong to their
existing authorities. In particular, this new full-cohort review format does
not inherit the smaller seven-Go kit's native installation permissions, nor
does it weaken the older signed-native-candidate trust checks. The complete
51-native review set currently delivers inert archives; it does not yet provide
a complete safe native install/upgrade/swap/remove maintenance path. Remaining
D05 ownership and live-use safety closure blocks release use.

The constructor adapter binds an exact constructor version and source hashes.
It strips publisher identities from wrapper TAR headers, uses recommended PKG
ownership and writes only allowlisted build metadata. It rechecks every embedded
Conda archive against the same selected carrier cohort after wrapping. No native
receipt or binary is edited during wrapping. Unexpected tool-source drift,
extra archives, changed nested bytes or the wrong native host are refused.

Installer options disable shell initialization, environment registration, menu
creation, user configuration writes and custom activation scripts. The bootstrap
is explicit package-maintenance tooling, not a Symphony service. The review
channel URL is deliberately nonpublic; no Anaconda or Cloudflare publication is
implied. Actual wrapper execution on a fresh host is a later acceptance gate.

Local macOS `.pkg` and `.sh` evidence applies only to supplemental Intel macOS.
A macOS shell installer is not a Linux installer. The manual native workflow
requires a matching audited cohort, exact selected artifact/digest and native
runner for macOS ARM64 or the three Linux profiles before producing their own
wrappers. Contract tests run on feature-branch changes; full platform assembly
is an explicit operation rather than an automatic unreviewed cohort selection.

## Self-signed review integrity

The publisher authorized a dedicated self-signed review identity while Apple
Developer ID credentials are unavailable. The signing helper keeps the encrypted
private key and password in separate private custody, outside all repositories,
source exports and installers. It signs an exact artifact manifest and verifies
the resulting signature before reporting success. Consumers must supply an
independently selected certificate SHA-256; bundled certificate bytes alone do
not establish publisher authentication.

The certificate authenticates possession of that review key. It provides neither
Apple Developer ID nor notarization, Gatekeeper acceptance, independent publisher
approval or permission to publish. No trust-store changes or system security
bypass are performed. The native `productsign` probe rejected this review
certificate as an installer identity, including a second isolated probe using
the installer-specific certificate purpose; therefore the PKG itself remains unsigned.
The review manifest signature covers its exact bytes externally. The probe's
private keychain is locked and excluded from the keychain search list; the
default keychain and search list were verified unchanged.

Verify a retained artifact set using the separately obtained pin:

```sh
python3 installer_assembly/review_signing.py --openssl "$EXACT_OPENSSL" verify \
  --signature-root "$REVIEW_SIGNATURE_DIRECTORY" \
  --artifacts "$REVIEW_ARTIFACT_DIRECTORY" \
  --trusted-certificate-sha256 "$INDEPENDENTLY_SELECTED_CERTIFICATE_SHA256"
```

The signing helper rejects changed artifacts, wrong keys, malformed or altered
manifests, unsafe paths and exposed private-key permissions. Public key/pin
publication and its independent trust policy still require a release decision.
See Apple's [Developer ID guidance](https://developer.apple.com/developer-id/)
for recognized macOS publisher trust.

## Remaining release gates

D08 local review evidence does not close primary-platform clean builds, native
installer execution on fresh unique-user hosts, real two-release upgrade/swap/
rollback journeys, unresolved C++/external live-use ownership or independent
backup/recovery acceptance. Final Apple signing/notarization must occur in the
proper finalization order and may require rebuilt receipts and requalification
when executable bytes change. Legal redistribution review (including the embedded Conda bootstrap and its
dependencies), independent acceptance,
trusted key distribution, integration/source selection for the open core, client
and distribution PR stacks, final exact candidate binding after that selection,
Anaconda channel retrieval and Cloudflare download
retrieval remain separate gates. No production provider or service was activated.
