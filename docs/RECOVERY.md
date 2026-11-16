# Recovery and refusal handling

Packaging, native runtime maintenance and user-data purge have different owners.
An incomplete result is not permission to repeat the operation, switch to a
generic uninstaller, erase a directory or bypass dependency checks. Preserve the
exact controller, source/recipe identities, receipts, attempted scope and user
data while the owning operation is reconciled.

## Conda private attempts

| Observation | Meaning and next action |
| --- | --- |
| Rejected caller reports an active operation | The competitor acquired no attempt authority. Let the already admitted operation report its outcome; do not close or mutate its live attempt from another thread. |
| Forked caller refuses creator-process authority | Its inherited descriptor is not permission to use the attempt. The original process retains authority if otherwise healthy. |
| `refused-retained` | The adapter recorded a failure before its execution marker. The live object is poisoned; preserve and inspect the retained scope and reason. No replay/adoption API is provided. |
| `execution-started.json` without a validated final result | An effect may have happened, including a partial unlink. Preserve the prefix, channel, cache and evidence. Process exit or elapsed time cannot establish rollback or completion. |
| `uncertain-retained` | Execution began and the adapter could not prove the complete outcome. Do not issue a replacement transaction against this prefix. |
| `observed-complete` | The same reviewed transaction's complete installed inventory and unaffected-file checks passed. It says nothing about native runtime activation or retirement. |
| Changed root, directory, descriptor, package files or foreign metadata | Custody is no longer proven. Preserve both the known original evidence and the observed replacement; do not repair ownership implicitly. |

Creation failures preserve the fresh root rather than silently reusing it.
Closing an attempt releases only its own valid descriptor. A terminated or
closed attempt cannot be reopened. Independently investigate a failed attempt
before selecting a new private qualification output; a fresh path must not hide
an unknown previous outcome or mutate the old prefix. This tooling deliberately
does not offer recovery adoption of arbitrary existing Conda environments.

The S07 recorder retains fault sources and interrupted attempts beneath its
private output directory. These are diagnostic fixtures, not installable state
or approval for operator replay. Public reports contain portable identities and
digests; keep private logs and host-local evidence separate from release payloads.

## Native owners and scoped apply

1. Identify the exact retained attempt/journal, scope, owner executable, receipt,
   installation root and retirement epoch. Re-observe through the existing
   owner contract under its locks; a different controller or newer binary is
   not an automatic recovery substitute.
2. Preserve admission closure while state is uncertain. Inactive metadata,
   undocking, a missing PID file, an empty process-name scan or an accessible
   service manager does not establish released use.
3. Resolve actual supervisor, enrollment, producer/consumer and shared-profile
   references through their owners. Unknown or inaccessible domains retain old
   bytes. Do not signal by a guessed PID, widen scope, or supply a force flag.
4. Reconcile only the same exact authorized effect. Completed native response
   loss has bounded fixture evidence: durable exact tombstone and owned-byte
   absence are observed before unchanged reconciliation. That result does not
   qualify mid-operation loss, every stop/delete crash point or escaped children.
5. Finalize only the observed scoped outcome. Selection, restart and rollback
   require their existing explicit authorization. A stopped or retiring service
   is not restarted as hidden compensation; unrelated ownership is not pruned.

Native materialization writes `intent.json` before invocation and retains
`owner-call.json`/`outcome-unknown.json` on uncertain outcomes. An absent
`custody.json` is not a completed installation. The helper refuses the existing
output on retry. Inspect the retained native state through its owner; do not
rerun `install-native` at the same output or delete the directory to evade refusal.

Accordare intents/outbox and required audit recovery must be resolved through
their actual authority. Packaging cannot choose `audit-deferred`, purge pending
work, erase credentials or remove the sole recovery/controller copy to make a
maintenance request pass. System/cross-user reclamation, unsupported old owners,
remaining raw/C++ consumers and unknown external use remain safety blockers.

The [S07 acceptance mapping](../qualification/README.md) records exactly which
faults were exercised. Passing a refusal test is evidence that the unsafe path
stops; it is not successful live-removal acceptance. Final host and independent
review gates remain open until they bind the delivered bytes and actual owners.
