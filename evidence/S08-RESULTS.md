# S08 dossier and candidate reconstruction

16 November 2026. This increment preserves the feature freeze and changes no
Symphony core source or main branch. The reviewed core remains
`5fd6cee1bae477048bf0045b691ee8bdf334e216`, tree
`327edd0f22860e84d30fe745f5a2b0e602f4af88`. Core main remains
`976b23290857be613005eea5cdc130d0f457b8c3`. This is E1 preparation and selected
source/payload qualification; release acceptance is incomplete.

## Dossier and delivery

The [source-bound supplement](../dossier/README.md) preserves the original
W01/W06 dossier's historical identity while recording the current distribution
source, seven Go ownership routes, four requested platforms, package contents,
trust/role requirements and acceptance mappings. All 26 capability groups,
36 core acceptance cells, 58 paper criteria, 31 supplemental requirements and
30 D05 safety requirements remain visible. None is waived or promoted to
final acceptance by a fixture, refusal test or documentation update.

The [delivery](../docs/DELIVERY.md), [recovery](../docs/RECOVERY.md) and
[source/payload](../docs/SOURCE-AND-PAYLOAD.md) guides describe the actual command
and owner boundaries. Incorrect `materialize`/`--install-native` documentation
was replaced with the implemented `retain` and `install-native` subcommands.
Conda's private live-attempt API is not documented as a restartable installer.
Runtime removal, carrier removal, selection and data purge remain distinct.

## Affected build closure and observed results

S07 changed distribution safety tooling, tests and qualification; the pinned
core source, seven candidate versions and binary recipes were unchanged. S08
therefore reconstructed all 14 carrier packages using reverified existing
candidate identities, and refreshed the optional source export from the old
D03 core revision to the corrected core source. No version or release was
invented. No product-wide build/test campaign was run merely for documentation.

| Observation | Result |
| --- | --- |
| Seven candidate identities and public Go closure | Reverified against exact core source, versions and bytes. qxctl retains its original two-build proof. |
| Fresh Conda reconstruction | 14 recipes regenerated; 14 archives rebuilt and independently audited with the unchanged frozen auditor. All four-file payload inventories match prior candidates. |
| Archive identity | All 14 Conda archive hashes differ because container/metadata bytes were reconstructed. Exact new hashes are retained; Conda archive reproducibility is not claimed. |
| Rebuilt payload journey | 25 actual install/build-upgrade/swap/rollback/remove transactions passed, including independent retained copies and unrelated sentinels. Private cache cleanup passed. |
| Native owner fixtures | Three fresh stopped retirements and three independent rollback installs passed. No enrollment, service activation, selection or whole-profile apply occurred. |
| Reviewed source export | 5,372 files, 57 explicit omissions, 27 transformed files; six dependency-map hash rebindings and two omitted private publisher test inputs. Original Git blobs and every derived mapping verified. |
| Source archive reproducibility | Two independent exports produced identical complete tar bytes. Ownership, names and timestamps are neutral; Git history, private policy, build outputs and user state are excluded. |
| Selected corresponding-source builds | Six non-qxctl Go commands rebuilt from the exact final source archive using Go 1.26.5, fresh build cache/private home and verified offline modules. Every binary matches the reviewed candidate. This does not qualify every source root or installed SDK. |
| Export safety tests | 29 focused tests and six actual-original-Git negative checks passed. Hidden archive trailers, forged original bindings/claims, altered maps, private markers and legal-attribution rewrites refuse. |
| Source-build custody tests | Four focused cases passed: failed preflight cannot mark an existing directory, outputs cannot overlap inputs, and replaced/foreign output custody is preserved. |
| Dossier contracts | 20 focused tests passed; exact-core validation binds the rebuilt candidates, final source export/build proof and completed hosted-status snapshot without granting release acceptance. |
| Delivery documentation | Seven actual CLI help surfaces, seven shell examples and all seven owner versions checked. |

The local profile is supplemental Intel macOS. Actual archives, source,
privacy policy, failed preparation attempt, rebuilt binaries, retained rollback
material and raw logs remain in private preparation directories, outside Git.
Portable exact-byte reports are [carrier reconstruction](s08-candidate-rebuild.json),
[source export](s08-source-export.json) and [selected source builds](s08-derived-go-source-build.json).
The dossier validator cross-checks those reports, preparation tools and original
core documents. A dedicated CI lane checks the affected dossier/export contracts.
New CI results are not awaited or claimed here.

A one-time review of completed S07 CI found macOS ARM64 passing and three Linux
native-fixture jobs failing; their Conda stages were skipped. The Linux default
`/tmp` ancestor was world-writable and the unchanged core correctly refused it.
The workflow now uses a private directory under the trusted runner temporary
tree and checks every ancestor. Unsafe-path refusal was reproduced locally;
all six affected tests and three subtests then passed with race detection using
trusted ancestry. The [hosted snapshot](s07-hosted-status-20261116.json) preserves
the failures, diagnosis and local repair evidence. Repaired hosted results are
pending and do not become acceptance through this documentation update.

## Remaining safety and release blockers

- S07's actual manager/privilege-domain/fresh-host gates, precise native
  restart/stop/delete fault boundaries, escaped descendants and uncertain
  mid-operation outcomes remain incomplete.
- Genuine distinct-release native upgrade/rollback and complete authorized
  profile selection remain open. Two packaging builds do not create two native releases.
- Raw/C++ consumers, external supervisors, arbitrary existing/shared Conda
  prefixes and unresolved Accordare audit recovery still require their real owners.
- D06's complete native/C++/Swift cohort, loader/TLS/notice closure, installed
  SDK and external-source consumers remain open. Six selected Go source builds
  do not close those requirements.
- D10's final-download and fresh-user/host matrix, Anaconda/Cloudflare retrieval,
  actual publisher/Apple signing and independent trust, redistribution/source
  review, named independent/backup acceptance and publication approval remain open.

The known-marker privacy checks do not assert absence of every possible secret
or identity. Legal notices are preserved or blocked for review. A release owner
must resolve the remaining acceptance cells against the exact delivered bytes;
this dossier and its hashes are not signing authority or approval to publish.
