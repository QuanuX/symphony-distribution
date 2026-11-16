# Primary host and client qualification

This increment keeps the feature freeze, core/client main and the distribution
default unchanged. It fixes wrapper construction and starts bounded hosted
qualification using the already verified primary native outputs. It does not
approve a release, integrate branches or publish installers.

## Completed investigation

The D06 ARM job passed, completing all four jobs in the targeted D06 run. The
four D12 wrapper attempts failed at one shared bootstrap lookup. The Conda
stream reader inferred a component name from the temporary `standalone.conda`
filename, while the pinned archive retains its full package identity.

The repair selects that identity from the existing version/build/URL pin and
requires the exact ZIP components and format metadata. It rechecks archive and
executable hashes; no upstream bytes or notices are changed. All 33 focused
tests passed, including the real archive reader. The actual selected upstream
archive reproduced the original failure under the temporary name and passed
after the fix. See the [triage](../evidence/d13-ci-triage.json),
[repair validation](../evidence/d13-bootstrap-repair.json) and
[actual archive regression](../evidence/d13-bootstrap-archive-regression.json).

The failed attempts retained reports only. Their original native archives
remain verified and reusable. Replacement runs recreate the missing carriers
and wrappers without native recompilation or original SDK replay. D12 now
audits and uploads a completed carrier checkpoint even if a later wrapper step
fails. Such a checkpoint must be paired with its exact source, native selection
and same-attempt recovery evidence before later admission; upload alone does
not qualify it as a release.

## Disposable native-owner campaign

The [maintenance workflow](../.github/workflows/d13-native-maintenance.yml)
accepts one committed native selection and its independently selected digest.
It authenticates the original native and SDK archives again, restores their
exact bytes, and verifies the original source and build identity on the matching
host. It then uses the existing 51-owner, 612-command refusal, removal, retry
and same-candidate recovery campaign in new private prefixes.

Source inputs are explicitly native owner configuration rows; no carrier-shaped
record is fabricated. Two small pure helper extractions preserve the existing
D09/D11 carrier entrypoints. All 33 affected tests passed, and all four real
retained platform inputs passed the source/map/51-owner preflight. Original
native files, source, helpers, tools and caller state are rechecked afterward.
See [focused validation](../evidence/d13-native-maintenance-validation.json) and
[platform source preflights](../evidence/d13-native-source-preflight.json).

## Matching primary client

The client gate binds core `5fd6cee1bae477048bf0045b691ee8bdf334e216` to the
separate client feature source `572627e939250763756167a9dc05d8cb37ab4e30`.
It retains the exact original client Git export and derives only the explicitly
listed platform catalog bindings in a separate tree. Generated package metadata
is identified as derived source; it is not relabeled as the original Git tree.
The observed qxctl identity, exact command records and generated tool descriptors
must match the selected core and existing client contracts.

The [client workflow](../.github/workflows/d13-primary-client.yml) builds and
qualifies a clean bridge for each matching primary platform. It preserves the
nine existing focused suites and maintained Claude, Antigravity, generic stdio
and explicit WSL adapters. Its real-client campaign uses the exact final client
package and retained qxctl for 22 deterministic Codex app-server cases across
stdio and same-user IPC, in private client profiles. It does not run model turns,
log into accounts or contact providers.

Codex 0.169.0 is a newly selected qualification tool from the official pinned
release. Native platform assets are selected by exact URL, size and SHA-256 in
the [tool lock](../qualification/primary-client-tools.json), rather than a
moving latest release. It is not bundled into the Symphony client package.
Earlier Intel/alpha-client observations retain their original scope.

All 23 focused preparation tests, workflow lint and independent source review
passed. The actual 101-file client Git export passed blob, mode and privacy
checks, and the selected official Mac ARM Codex archive passed hash, size and
layout verification. These preparation results do not claim completion of the
nine native suites or 22 Codex cases on the new primary inputs. See
[client validation](../evidence/d13-primary-client-validation.json) and
[original source inventory](../evidence/d13-client-original-source.json).

## Results and remaining gates

The [dispatch record](../evidence/d13-dispatches.json) identifies the exact
source and selections for replacement wrappers, disposable native maintenance
and primary client jobs. These are dispatched qualification attempts; CI
completion is not awaited or claimed. A fresh disposable runner does not by
itself establish independent physical-host acceptance.

Native `.pkg` execution, live/shared-root process retirement, external runtime
ownership, genuinely distinct-release upgrades/rollbacks, final source
integration, recognized signing/trust, actual legal approval and independent
acceptance/recovery reviews remain separate gates. The client main divergence
still requires reconciliation when source integration is authorized. None of
the new engineering records changes the existing hash-bound human decisions.
