# D07 client distribution evidence

The [D07 qualification record](d07-client-qualification.json) binds client
`71b2021aeefb704b9c3e63797d04a0cc021757a9` to core origin
`5fd6cee1bae477048bf0045b691ee8bdf334e216` and the unchanged reviewed D06 candidate.
Both main branches remain untouched. All observations here are supplemental Intel
macOS engineering evidence, with release acceptance incomplete.

| Observation | Result and retained record |
| --- | --- |
| Catalog | 525 identities, 743 operation tools; three existing lifecycle contracts/five descriptors refreshed; no added commands |
| Clean bridge | Two independent source/build/home paths produce identical finalized bytes; [build evidence](d07-client-bridge-build.json) |
| Loader/privacy | Only platform libSystem/libc++ dependencies, no RPATHs; exact private-policy/source-path scans passed; [loader record](d07-client-loader-audit.json) |
| Package | Two identical 92-member ZIPs; 91 exact committed source members plus bridge; [package record](d07-client-package-build.json), [inventory](d07-client-package-inventory.json) |
| Source | Clean committed export; [export record](d07-client-source-export.json), [packaged source inventory](d07-client-source-inventory.json) |
| Focused tests | Nine CTest groups, including 12 new provenance tests; 11 MCPB tests; case-level counts inside CTest are not additional independent totals |
| Actual Codex | Version 0.169.0-alpha.11.1, 11 stdio plus 11 same-user IPC cases passed using extracted package bytes; [final packet](d07-client-final-packet.json) |
| Owner/source closure | 1,250 payload entries and 5,372 derived source files verified; no missing evidence in the separate distribution packet |

The source ZIP and binary remain private local candidates. Private configuration,
raw transcripts, temporary owner state and scanner policy are not committed or
packaged. Optional personal publisher contact metadata is removed; project contact
routes and legal attribution remain. Each user's state is generated locally.

Actual Codex observations cover deterministic app-server transport and native-owner
behavior. They do not qualify model tool selection, GUI onboarding, real providers,
new Claude/Antigravity sessions, primary platforms, final downloads or fresh hosts.
The exact lost-response test reconciles through owner inspection after restart;
it does not replay an uncertain mutation. All disposal cleanup checks passed.

The D06 qxctl has no embedded source stamp. The new verifier checks its external
source/build/delivery chain and preserves the older W13 refusal. That gate is not
waived. Final source identity policy, client PR integration, four primary platform
candidates, D05 remaining safety boundaries, independent-release lifecycle journeys,
publisher signing/trust and legal review, Anaconda/Cloudflare retrieval, fresh-host
acceptance and independent/backup review remain open.

See [D07 handoff](../docs/D07-CLIENT-GATE.md). Neither this record nor a successful
fixture grants publication, provider activation, user-profile mutation or approval
to merge main. CI results were not awaited.
