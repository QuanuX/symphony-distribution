# S07 local qualification record

16 November 2026. These are bounded E1 engineering results. S07's final
platform/independent-acceptance gates remain open.

Core source remains `5fd6cee1bae477048bf0045b691ee8bdf334e216`, tree
`327edd0f22860e84d30fe745f5a2b0e602f4af88`. No core files, candidate identities,
module versions or source bindings changed. Core main remains
`976b23290857be613005eea5cdc130d0f457b8c3`. The work is on the distribution feature
branch `codex/s07-fault-platform-qualification`.

## Defects corrected

- S06's hosted Linux contract failure came from a macOS-only test fixture's
  retry running outside its host mock. The fixture now reaches the intended
  retained-output refusal on both hosts; a separate test verifies wrong OS and
  architecture are rejected before execution. Production platform guards remain.
- A fork inherited the live Conda attempt and its file lock. Attempt authority
  now belongs to its creating process.
- Competing calls could reach sequence/evidence mutation before the global
  Conda context lock. A per-attempt nonblocking guard excludes concurrent
  inspection, mutation and closure before any evidence changes.
- Byte-identical replacement of fixed custody directories was undetected.
  Directory and live descriptor identities are now checked.
- A reused descriptor could close an unrelated file during cleanup; an early
  setup failure could retain an owned lock. Cleanup verifies its own descriptor
  identity and covers early setup failures while preserving refusal evidence.
- Campaign evidence refuses missing, duplicate, skipped or incomplete selected
  cases. Interrupting a campaign cleans up its own subprocess group; interruption
  cannot produce a passing record.

## Observed results

| Focused check | Result |
| --- | --- |
| Go delivery contracts | 12 passed, including retained unknown outcome and wrong-host refusal. |
| Real Conda campaign | 28 test groups and 16 subtests passed, zero skips; 14 prior transaction/cache groups plus 14 new fault/concurrency groups. Conda 26.10.0, conda-build 26.9.1, Python 3.12.16. |
| Native campaign | 76 selected top-level Go tests and 71 subtests passed under the Go 1.26.5 race detector; zero skips. Four isolated dependency caches passed `go mod verify`. |
| Completed native response loss | All three real source-built native owner executables passed observed retirement, owned-byte absence, preserved foreign sentinel and explicit unchanged reconciliation. No service started. |
| Evidence and platform contracts | 4 Conda-recorder, 18 native-recorder and 10 platform-inventory tests passed, including no acceptance on missing/failed/skipped evidence and owned-process interruption cleanup. |
| Conda controller interruption | A separate actual SIGTERM check reaped the owned worker and retained an incomplete report. This is negative evidence, not a passed transaction. |
| Workflow | Changed-path selection exercised; workflow lint passed with only the exact Ubuntu 26.04 runner label excluded from the linter's outdated label catalog. The label is present in official GitHub documentation. |

Portable evidence: [Conda campaign](s07-conda-local-qualification.json),
[native campaign](s07-native-local-qualification.json), and
[local platform inventory](s07-local-platform.json). Reports bind source/test
files and raw log digests. Full private native roots/controllers, Conda source
fixtures, interrupted attempts and diagnostic logs remain outside this repository.
The successful retained Conda campaign contains 15 private fixture directories.
No package archives, build outputs, local user paths or host custody state are
checked into this increment.

The observed host is Intel macOS 26.7.1, supplemental profile
`local-macos-amd64-fixture`. Read-only launchd user, GUI and system probes were
accessible. No installed-manager lifecycle or fresh-host acceptance occurred.

## Remaining gates

- The four requested hosted profiles are wired but their results have not been
  awaited: macOS 15 ARM64, Ubuntu 24.04 AMD64/ARM64 and Ubuntu 26.04 AMD64.
- Actual manager lifecycle and applicable privilege domains, fresh users/hosts,
  process-generation changes, inaccessible domains and detached descendants
  remain unqualified. Manager accessibility does not close these gates.
- Native restart injection at every reference-scan, stop-completion and
  first-delete boundary, mid-operation response loss and all actual native
  crash points remain incomplete. Current receipt-last interruptions are
  fixtures; completed-response loss is a narrower observed case.
- Distinct genuine native releases and full authorized profile selection,
  upgrade and rollback remain open. Two package builds are not two native releases.
- Remaining C++/raw consumers, external supervisors, arbitrary shared Conda
  prefixes and unresolved Accordare audit recovery require their actual owners.
  Safe refusal preserves these states and is not successful live removal.
- S08 / D06 / D10 still require final delivered-byte binding, clean candidate
  rebuilds as applicable, signing/trust, redistribution review, independent
  acceptance and approved Anaconda/Cloudflare publication.

See the [acceptance mapping](../qualification/README.md) for the exact supported
scope and per-cell limitations. The feature freeze remains in place.
