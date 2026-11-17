# Symphony Public Beta distribution

Symphony **0.2.0-beta.1** is published through **QuanuX/beta on Anaconda** and
Cloudflare downloads. Start with the [release page and platform downloads](https://github.com/QuanuX/symphony-distribution/releases/tag/v0.2.0-beta.1)
and the [installation and verification guide](docs/BETA-INSTALL.md).
The [publication record](evidence/d14-publication.json) binds 240 published
packages and 304 verified download objects to the signed release.

## Install the published beta

| Supported profile | Standalone installers | Package selection |
| --- | --- | --- |
| macOS 15 Apple Silicon | `.pkg` and `.sh` | `macos15-arm64` |
| Ubuntu 24.04 AMD64 | `.sh` | `ubuntu24.04-amd64` |
| Ubuntu 24.04 ARM64 | `.sh` | `ubuntu24.04-arm64` |
| Ubuntu 26.04 AMD64 | `.sh` | `ubuntu26.04-amd64` |

Each profile supplies 59 independently maintainable default packages and a
separate optional corresponding-source package. SDK headers, libraries and
exports stay with their module owners. Native and SDK bytes come from the
selected clean CI builds; user profiles, credentials, hardware knowledge and
workflow state are created on the recipient's system.

Verify the detached signature and exact platform package list before installing.
The [installation guide](docs/BETA-INSTALL.md) covers both standalone and existing
Conda routes, first-use retention, Codex setup, and per-module install, change,
swap and removal. Select the exact operating-system profile; the two AMD64 Linux
cohorts share a Conda subdirectory but are different qualified builds.

Packages contain inert carrier files. Existing Symphony owners retain control
of runtime files, credentials, process retirement and application selection;
Maestro's selection is separate from package delivery. Independent retained
copies outside Conda prefixes and caches survive carrier upgrade or removal.
Installing packages does not activate services or select application modules.

## Qualified scope and trust

Completed release qualification includes 88 actual Codex cases, 204 native
owner receipts, 728 packaging maintenance transactions, four shell/first-use
campaigns, and installation/removal of the exact native Mac home installer.
The [publisher decision](evidence/d14-publisher-decision.json) records legal
approval and acceptance; the [publication evidence](evidence/d14-publication.json)
records the selected artifacts and public retrieval results.

This beta uses a pinned, self-signed detached publisher signature. Apple
Developer ID, notarization, Gatekeeper acceptance and separate human-reviewer
independence are not claimed. Packaging revision **0→1→0** upgrade/rollback,
independent carrier changes and same-candidate recovery are qualified.
Transitions between distinct native releases remain outside this initial beta.
Unsupported ownership, uncertain effects and unexamined live consumers retain
their existing refusal and recovery boundaries.

The feature freeze remains in force. Integration into `main` consolidates the
reviewed release fixes and documentation; it does not add features or alter the
published release. The tag and signed artifact identities are immutable. Later
builds or documentation commits do not replace the selected release bytes.
Website integration remains a later presentation step; the release page and
Cloudflare downloads are available now.

## Published beta maintenance notes

The beta.1 downloads retain their original qualified bytes and do not include
three later [core lifecycle repairs](https://github.com/QuanuX/Symphony#published-beta-maintenance-notes).
Complete a dependency's replacement before introducing a new dependent. If a
completed scoped apply reports a validation error on retry, inspect durable
status and preserve the journal instead of repeating effects. For SSIAG or
Accordare reinstall maintenance, use the exact retained owner binary outside the
installation; self-reinstall from the installed binary may report a busy package.
Existing ownership and active-use checks still apply.

A newly bound, rebuilt and qualified candidate is required before these source
repairs can be advertised as present in downloadable packages. The current
source bindings, release tag, signatures and public artifacts remain unchanged.

## Engineering and maintenance

This repository is separate from [Symphony core](https://github.com/QuanuX/Symphony).
The exact reviewed core commit and source-file hashes remain in
[source-binding.json](source-binding.json); the seven Go delivery routes remain
in [go-owner-catalog.json](go-owner-catalog.json). Builds must match these bindings
and the pinned Go 1.26.5 recipes, even after their source branches merge to main.
A passing fixture or a new build is not automatic publication authority.

| Area | Guide |
| --- | --- |
| End-user installation and independent modules | [Beta installation](docs/BETA-INSTALL.md) |
| Retained binaries and explicit first use | [Retention](delivery/README.md) |
| Scoped native proposals and uncertain effects | [Lifecycle](lifecycle/README.md), [recovery](docs/RECOVERY.md) |
| Clean native/SDK builds | [Build cohort](build-cohort/README.md) |
| Source export and privacy | [Source preparation](source-export/README.md) |
| Installer assembly and signing | [Installer tools](installer_assembly/README.md) |
| Exact signed publication and retrieval | [Channel tools](channel/README.md) |
| Fault, platform and SDK qualification | [Qualification](qualification/README.md) |
| Preserved requirements and original acceptance mapping | [Dossier](dossier/README.md) |

For focused standard-library tests, use Python 3.11 or later and a clean checkout
of the exact bound core commit:

```sh
export SYMPHONY_SCOPE_TEST_SOURCE=/absolute/core-checkout
python3 tests/check_source_binding.py "$SYMPHONY_SCOPE_TEST_SOURCE"
python3 -m unittest discover -s owner-catalog -p 'test_*.py'
python3 -m unittest discover -s lifecycle -p 'test_go_delivery.py'
python3 -m unittest discover -s lifecycle -p 'test_handoff.py'
```

Real Conda qualification uses an isolated publisher environment with Python
3.12, Conda 26.10.0 and conda-build 26.9.1. Choose fresh output directories and
preserve failed attempts for inspection. The adapter validates the complete
LINK/UNLINK set and executes the same prepared transaction in its private attempt;
it does not claim exclusion against unrelated clients of existing environments.

## Historical milestone records

These records preserve the evidence and unresolved inputs observed at each
milestone. Their historical pending gates do not override the current
[publication result](evidence/d14-publication.json), and completed release
qualification does not expand their narrower fixture claims.

| Milestone | Retained record |
| --- | --- |
| S06 guarded Conda journeys | [Results](evidence/RESULTS.md), [preparation commands](docs/DELIVERY.md) |
| S07 fault and concurrency fixtures | [Campaign and acceptance mapping](qualification/README.md) |
| S08 dossier and source delivery | [Results](evidence/S08-RESULTS.md), [dossier](dossier/README.md) |
| D06 clean native and SDK cohort | [Results](evidence/D06-RESULTS.md), [build guide](docs/D06-CLEAN-COHORT.md) |
| D07 client packaging | [Results](evidence/D07-RESULTS.md), [handoff](docs/D07-CLIENT-GATE.md) |
| D08 embedded-source repair and review installers | [Results](evidence/D08-RESULTS.md), [handoff](docs/D08-INSTALLER-ASSEMBLY.md) |
| D09 review delivery | [Status](docs/D09-STATUS.md), [acceptance packet](docs/D09-ACCEPTANCE.md) |
| D10 wrapper qualification | [Status](docs/D10-STATUS.md), [wrapper provenance](docs/D10-PRIMARY-REWRAP.md) |
| D11 artifact admission | [Status](docs/D11-STATUS.md), [selection rules](docs/D11-ARTIFACT-SELECTION.md) |
| D12 retained native recovery | [Handoff](docs/D12-NATIVE-RECOVERY.md) |
| D13 fresh-host/client qualification | [Handoff](docs/D13-FRESH-HOST-CLIENT.md) |
| D14 beta assembly and publication | [Hosted qualification](evidence/d14-beta-hosted-qualification.json), [publication](evidence/d14-publication.json) |
