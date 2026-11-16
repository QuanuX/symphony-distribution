# Historical D06 and S06 CI repairs

The 2026-11-16 repair pass addresses the two historical failures reported by
the release owner. The [portable repair record](../evidence/d11-ci-backports.json)
binds original failures, repair heads, file digests, focused validation and
targeted dispatches. No CI completion was awaited.

## D06 Linux SDK linking

[PR 3](https://github.com/QuanuX/symphony-distribution/pull/3) now preserves the
selected `clang++` executable alias. Resolving that symlink to `clang` changed
driver behavior and omitted C++ runtime linkage during detached SDK tests.
The exact downstream repair was backported to the historical D06 branch.

All 30 focused SDK and workflow-selection tests passed. The
[targeted run](https://github.com/QuanuX/symphony-distribution/actions/runs/43945383060)
uses repair head `7422b6fc59479da43cbd7d2694f4767643246f5f` and requests only
the three affected Linux cohorts plus their contract prerequisites. The passing
macOS cohort from run 43866449586 is preserved. Normal pushes and default manual
runs still select all four platforms.

## S06 native-result fixture

[PR 7](https://github.com/QuanuX/symphony-distribution/pull/7) keeps the simulated
Darwin/x64 host active through the retained-unknown-outcome retry assertion.
Previously Linux encountered the production cross-host refusal before reaching
that assertion. A separate regression confirms that incompatible hosts still
refuse before output creation or native execution; production guards are intact.

All 12 delivery tests passed. An outer Linux/x64 simulation reproduced the
original error and passed after the fix. The
[targeted run](https://github.com/QuanuX/symphony-distribution/actions/runs/43945410578)
uses repair head `3677c186c619181e418882ce14f4b77bc8c0bd86` and explicitly omits
the previously passing Conda transaction job. Automatic runs and default manual
runs retain that job.

## Integration boundary

The distribution repository's default is `codex/s06-conda-journeys`; there is
no distribution branch named `main`. That default remains unchanged pending
review of PR 7. Core and client main also remain unchanged. Repair commits use
`[skip ci]` to avoid duplicate automatic runs, followed by explicit targeted
dispatches. These dispatches do not retroactively alter failed historical runs.

The D06 branch advanced by fast-forward. No descendant branch was rewritten,
no candidate bytes were replaced and no merge occurred. The hash-bound
[integration snapshot](../evidence/d11-integration-snapshot.json) remains its
original point-in-time record; this addendum supersedes only its observation
that PR 3 has not received the downstream repair. Refresh ancestry and evidence
bindings before separately authorized integration.

The existing fresh-host/client, installer and live maintenance, genuine version
transition, integration, recognized signing/trust and human review gates remain
open. These CI repairs do not grant release acceptance or publication authority.
