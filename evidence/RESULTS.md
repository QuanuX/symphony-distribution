# S06 qualification record

16 November 2026. This is bounded local engineering evidence, not Public Beta release acceptance or publisher approval.

Core source: `5fd6cee1bae477048bf0045b691ee8bdf334e216`, tree `327edd0f22860e84d30fe745f5a2b0e602f4af88`. The three preceding core CI repairs were pushed to PRs 200, 201 and 202. Core main remained `976b23290857be613005eea5cdc130d0f457b8c3`; no merge occurred.

| Gate | Observed result |
| --- | --- |
| Focused distribution tests | 98 passed, zero skipped: owner catalog 13; delivery 11; original handoff 17; package journeys and custody 21; archive builder/audit 15; report binding 7; real Conda transactions/cache safety 14. |
| Clean source candidates | All seven Go candidates verified with Go 1.26.5 and the exact public module closure; qxctl matched across two isolated builds. |
| Genuine Conda archives | 14 archives: two packaging builds for each of seven Go deliveries. Every final archive passed the frozen auditor; no personal paths, host custody, recipe/build files, activation hooks, or runtime Python dependencies. |
| Main local Conda journeys | 25 observed transactions covering install, independent upgrade, exact rollback, carrier swap, reverse swap, and removal. Every transaction preserved retained candidates and unrelated files/package metadata. |
| Native owner fixtures | Three fresh stopped replacement installations retired through their exact native owners; receipt and executable absence, exact root/tombstone identity and unrelated sentinels verified. Three fresh rollback installations used retained original bytes. No selection or service activation. |
| Actual cache cleanup | Separate source-bound STAV archive install/remove followed by normal Conda cache cleaning in an owned private cache. Independently retained candidate and unrelated data survived. No global or pre-existing environment cleanup. |
| Historical controller custody | The explicitly qualified ad7ed0e source pairing verified all three real retained owners. Unknown sources, Conda environment locations, missing custody, runtime-root overlap, and unsupported authority refuse. |
| CI | Two focused distribution jobs prepared. Hosted results are not claimed and were not awaited. |

Machine-readable portable evidence: [local qualification](s06-local-qualification.json) and [seven-candidate closure](go-candidate-closure.json). Full private logs, attempts, original/final archive audits, native guards, and recovery copies were retained locally. Package archives and private state are not checked into this repository.

The observed profile was the supplemental `local-macos-amd64-fixture`, with Conda 26.10.0 and conda-build 26.9.1. Current and retained service owner executables are byte-identical; the two packaging builds are not two native releases. An unnecessary native replacement is refused rather than synthesized.

## Safety and release gates still open

- Genuine distinct-release native upgrade/rollback compatibility; complete authorized profile execution, selection, and retirement journeys.
- Advertised physical platform/fresh-host qualification. The local Intel fixture does not accept macOS ARM64 or any Linux host.
- Safe live removal for the remaining native/C++ and raw executable consumers; shared ownership, supervisors, clients, and unresolved pending work need their actual owners.
- Arbitrary existing/shared Conda environments. The supported transaction boundary is a fresh private attempt; no claim is made that a preview excludes other Conda clients.
- Final clean CI artifacts, publisher signing/trust, redistribution review, independent acceptance, and approved Anaconda/Cloudflare publication.

The feature freeze remains in force. S06 adds packaging and verification around existing owners; it does not introduce a universal process supervisor, runtime selector, automatic activation, or forced removal.
