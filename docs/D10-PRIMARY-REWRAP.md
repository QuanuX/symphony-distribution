# Retained primary builds and wrapper repair

The four replacement D09 runs use distribution revision
`f7ec266c7b5c4d18a431fa5d01927cf82668369e`. Their wrapper producer still disables
the pinned standalone bootstrap's required `constructor` plugin. Assembly and
archive inspection do not execute that command; the separate disposable-user
job does. A native job can therefore retain useful audited build and carrier
outputs even when its later shell-installer qualification fails.

Preserve those runs. No additional full build or rewrap dispatch is selected by
this document, and no new CI result was awaited. Rerunning an existing job uses
its original revision and does not apply the wrapper repair.

| Profile | Selected original run |
| --- | --- |
| macos15-arm64 | [43919872052](https://github.com/QuanuX/symphony-distribution/actions/runs/43919872052) |
| ubuntu24.04-amd64 | [43919876976](https://github.com/QuanuX/symphony-distribution/actions/runs/43919876976) |
| ubuntu24.04-arm64 | [43919882342](https://github.com/QuanuX/symphony-distribution/actions/runs/43919882342) |
| ubuntu26.04-amd64 | [43919888963](https://github.com/QuanuX/symphony-distribution/actions/runs/43919888963) |

The existing workflow uploads `d09-primary-<profile>-<run-attempt>` after native
qualification and packaging, before the separate consumer runs. That artifact
contains the complete audited 58-carrier layout, original wrapper files and
audit, primary `result.json`, and `fresh-host-requirements.json`. The companion
`d09-evidence-<profile>-<run-attempt>` retains the aggregate build, SDK-closure
and delivery records. These artifacts have a 14-day retention period. Their
existence and successful qualification have not been inferred from dispatch.

## Inputs required before a bounded follow-up

- Exact repository, run ID, run attempt, workflow revision, profile, artifact
  IDs/names, and GitHub artifact digests; retrieve and verify the actual bytes.
- Independently selected primary `result.json` SHA-256, carrier cohort digest,
  source commit/tree, reviewed export digest and source-manifest SHA-256.
- Original aggregate build, SDK-closure and delivery record hashes, matched to
  the retained records; original wrapper-audit hash and acceptance-packet hash.
- A fixed, committed wrapper-toolkit revision and its helper hashes, the exact
  native publisher/standalone tool identities, and the selected privacy policy.

## Bounded reuse sequence

1. Admit a completed original native result and its separately selected artifact
   on the matching native platform. Verify the original 58-carrier audit,
   archive bytes, source/profile bindings, build and SDK evidence, and unchanged
   36-cell acceptance requirements. Refuse missing, expired or mismatched input;
   do not adopt an arbitrary local prefix or substitute a newer candidate.
2. Copy the admitted carrier layout into a fresh private output and regenerate
   only the shell wrapper and, for macOS, the package wrapper. Audit all nested
   archives and bootstrap identities. Every carrier must remain byte-identical.
   Preserve the original artifacts and failed consumer evidence unchanged.
3. Emit a distinct repair record binding both the inherited native-build/toolkit
   identities and the new wrapper-toolkit identity, new wrapper hashes and
   audit. Do not relabel the original build as executed by the repair revision
   or rewrite its aggregate result. Any signature covers the new selection.
4. Qualify only the repaired installer and affected consumer contracts on a
   separate disposable native runner, using a private verified execution copy.
   Retain installation, refusal, removal and caller-state evidence with explicit
   scope. Independent acceptance, matching primary clients, native runtime
   installation and release authority remain separate gates.

This follow-up is preparation only. A reuse helper/workflow still requires
implementation, focused tests and an explicit artifact selection. If a native
job fails before producing the required artifacts, its actual failure must be
diagnosed separately; no reusable build proof is manufactured from partial logs.
