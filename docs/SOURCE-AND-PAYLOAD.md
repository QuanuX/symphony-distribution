# Source and payload ownership

The release separates source, inert delivery, runtime installation and each
user's state. A package manager does not own every directory used by a program.
The current [source binding](../source-binding.json) and
[Go owner catalog](../go-owner-catalog.json) define the selected core input;
recipe/manifests and final archive audits must bind the same source and bytes.

| Material | Where it belongs | Ownership and privacy rule |
| --- | --- | --- |
| Reviewed first-party source, build/install instructions and matching notices | Optional source delivery and retained source provenance | Export exact committed inputs. Source delivery must not silently substitute for a missing promised runtime capability. |
| SDK headers, libraries and CMake exports | Their complete native receipt units and source/SDK delivery | Preserve exact independent SDK versions and their dependency closure. Do not strip or split a sealed receipt into an invented headers-only runtime package. |
| Seven Go executable carriers | Conda payloads under `share/symphony/carriers/<component>/<native-version>/<build>/` | Exactly one executable, `artifact-identity.json`, `LICENSE-AGPL-3.0` and `carrier-manifest.json`; no runtime Python dependency or activation hooks. |
| Recipe and build evidence | Build/review records outside the installed carrier | Bind renderer, builder, toolchain, dependency and final archive identity. Do not ship local build directories, caches or copied host state. |
| Independently retained controller and rollback bytes | Explicit private custody outside Conda prefix/cache and runtime roots | Independent regular-file copies, exact source/receipt/build identity; no hardlink co-ownership or invented native receipt. |
| Native executable and install receipt | Fresh installation created by the exact native owner | Owner verifies final bytes and creates the receipt. Carrier provenance alone is not runtime ownership. |
| Retirement guard, use/admission locks, root identities and ownership registry | Created and retained by the current host's actual owner | Never copy a publisher or fixture guard into a user's installation. Tombstones can remain after removal. |
| Profiles, TOPS identities, credentials, journals, enrollment, user knowledge and hardware observations | Created locally through explicit user/owner operations | No default publisher account, hardware identity, selected workflow, live endpoint or credentials. Preserve on ordinary package removal. |
| Private diagnostic logs and fault attempts | Private qualification/recovery evidence | Review before sharing. Public portable reports omit personal paths and identifiers; raw local logs are excluded from Git and packages. |
| Vendor SDK/runtime/proprietary or licensed data | Separately selected and authorized inputs | Matching provenance, runtime/notice closure and redistribution rights remain explicit gates. Public fixture licensing does not grant data or SDK redistribution rights. |

The carrier manifest records the native version separately from the Conda build
number. A build replacement must not pretend to be a new native release. Core
receipts, Go module versions and linker identities retain their own meanings.

An exported native staging payload contains the verified executable and its
receipt; it excludes host-local retirement guards and locks. The destination
owner must create its own local custody. Users establish their own system and
workflow state on first use; the installer does not silently enroll TOPS,
provision administrators, change global PATH or start services.

## Reviewed source export

The S08 source exporter operates on the exact bound Git objects, not the
publisher's working-directory contents or build trees. It creates a derived
public source export with an explicit file inventory, original/exported hashes,
exclusions and source-map rebindings. Approved personal-attribution and known
fixture transformations are recorded; the exported tree must not be presented
as byte-for-byte identical to the original commit.

Select the reviewed clean core repository, a new absolute output path and an
explicit private privacy policy. The policy is an operator input and is never
bundled. Keep any identity patterns it contains out of public commands/logs.

```sh
python3 source-export/export_source.py build \
  --repository "$REVIEWED_CORE_REPOSITORY" --output "$NEW_SOURCE_EXPORT" \
  --privacy-policy "$PRIVATE_PRIVACY_POLICY"
python3 source-export/export_source.py verify \
  --repository "$REVIEWED_CORE_REPOSITORY" --output "$NEW_SOURCE_EXPORT" \
  --privacy-policy "$PRIVATE_PRIVACY_POLICY"
```

Verification checks the export against its bound source and recorded map.
Passing privacy/provenance verification does not prove that every exported root
builds, that the complete source test suite passes, or that corresponding-source
and redistribution review is complete. Optional SDK and final D06 platform
cohort qualification remain separate. The [S08 source-export report](../evidence/s08-source-export.json)
records the actual derived export and its remaining gates.

## Trust and delivery gates

Archive hashes provide integrity and exact binding, not independent publisher
trust. Anaconda organization membership/upload rights do not identify an Apple
signing identity, notarization policy or independently distributed trust root.
An adjacent public key is not independent trust. Only approved final bytes may
be signed and then tested through their actual retrieval and installation path.

The intended destinations are QuanuX on Anaconda for Conda carriers and
Cloudflare/website downloads for `.pkg` and `.sh`. This repository's preparation
and local archive tests do not upload, announce availability or prove final
download behavior. Full-source privacy/export review, complete corresponding
source and dependency notices, publisher signing, Apple trust where applicable,
actual supported hosts and independent acceptance remain separate recorded gates.

Core implementation references at the exact bound source are
`cmake/mvp-dependencies.json`, `cmake/mvp-release-identities.json`,
`cmake/mvp-platform-profiles.json`, `tests/public-beta/PACKAGE-AND-TRUST.md`,
and `tests/launch-acceptance/GO-CANDIDATE-CLOSURE.md`. The old beta proposal's
baseline is historical; do not stamp it onto newly rebuilt bytes. The external
S08 dossier supplements that proposal without modifying core main or claiming
unavailable acceptance.
