# Retained primary builds and wrapper repair

All four selected D09 runs completed their two native build rounds, then failed
while collecting corresponding source at distribution revision
`f7ec266c7b5c4d18a431fa5d01927cf82668369e`. The old source included a private
marker in `docs/D09-ACCEPTANCE.md`; the current source has the existing repair.
The separate shell-wrapper plugin repair is also present in the current branch.
Neither repair changes native Symphony features.

The run and artifact inspection below supersedes the earlier expectation that
those runs might have retained reusable native bytes. Preserve their evidence;
repeating the original jobs would execute their old source again.

| Profile | Selected original run |
| --- | --- |
| macos15-arm64 | [43919872052](https://github.com/QuanuX/symphony-distribution/actions/runs/43919872052) |
| ubuntu24.04-amd64 | [43919876976](https://github.com/QuanuX/symphony-distribution/actions/runs/43919876976) |
| ubuntu24.04-arm64 | [43919882342](https://github.com/QuanuX/symphony-distribution/actions/runs/43919882342) |
| ubuntu26.04-amd64 | [43919888963](https://github.com/QuanuX/symphony-distribution/actions/runs/43919888963) |

The inspected replacement runs completed compilation, then failed during the
corresponding-source collection step. Their SDK supplement, packaging and
consumer steps did not execute. All eight selected D09/D06 artifact ZIPs were
retrieved and checked against GitHub's recorded hashes and sizes: they contain
reports, with no retained native payload, reviewed source archive, carrier or
wrapper bytes. A report digest cannot reconstruct those missing bytes. No
existing primary build is currently selectable for a wrapper-only rerun.

The producer now prepares a distinct `carrier-capsule` after final SDK and
carrier qualification and before invoking constructor. It contains all 58
complete audited carriers, unchanged build/round/SDK/delivery reports, source
manifest, qxctl proof, dependency and acceptance plans, and the exact committed
producer toolkit source. This preserves an independently verifiable checkpoint
when later wrapper assembly or consumption fails. Post-build recovery retention
is a separate earlier checkpoint; it does not assert completed SDK or carriers.

The native checkpoint is uploaded immediately after the two clean builds and
before source collection. It contains one verified payload round, both original
round reports, the reviewed export, exact qxctl compiled-source proof, configure
evidence and helper identities. Internal curl link chains are resolved only
within their selected payload namespace; cycles, missing targets and escapes
are refused. This is engineering recovery material, not an installer or release.

One recovery producer run was dispatched for each primary profile at
`e3544e729b0013df505ef2e2ad8f9963a58e7e5d`, using the same independently reviewed
core/export pins. The lost payloads cannot
be recovered from reports. These producers retain both checkpoints before later
failures can discard them; the existing fresh-user option remains disabled.
After actual capsule IDs, digests and result pins are verified, a separately
committed selection enables the new wrapper-only workflow. No primary wrapper
qualification or Public Beta acceptance is claimed in advance of those bytes.

`evidence/d10-primary-wrapper-input-selection.json` records the eight downloaded
report artifacts and old failure diagnosis. `evidence/d10-wrapper-ci-triage.json`
records the unchanged passing core, client and distribution checks.
`evidence/d10-retention-schema-review.json` checks the new retention assumptions
against the actual four primary report inventories, while explicitly recording
that their payload bytes are absent. `evidence/d10-wrapper-transport-replay.json`
records successful bounded extraction of all eight original ZIPs.

## Recovery dispatches

The exact dispatch record is `evidence/d10-primary-recovery-dispatches.json`.
Only each dispatch identity and source revision were checked; no new CI result
was awaited. The complete 247-file implementation source passed collection and
privacy checks before dispatch (`evidence/d10-wrapper-toolkit-source-seal.json`).

| Profile | Recovery producer run |
| --- | --- |
| macos15-arm64 | [43939021560](https://github.com/QuanuX/symphony-distribution/actions/runs/43939021560) |
| ubuntu24.04-amd64 | [43939059852](https://github.com/QuanuX/symphony-distribution/actions/runs/43939059852) |
| ubuntu24.04-arm64 | [43939100597](https://github.com/QuanuX/symphony-distribution/actions/runs/43939100597) |
| ubuntu26.04-amd64 | [43939137887](https://github.com/QuanuX/symphony-distribution/actions/runs/43939137887) |

## Inputs required before a bounded follow-up

- Exact repository, run ID, run attempt, workflow revision, profile, artifact
  ID/name/size and GitHub artifact digest; retrieve and verify the actual bytes.
- Independently selected primary `result.json` SHA-256, carrier cohort digest,
  source commit/tree, reviewed export digest and source-manifest SHA-256.
- Original aggregate build, round, SDK-closure and delivery record hashes,
  matched to the retained records, plus the acceptance-packet hash. The selected
  input is explicitly a completed pre-wrapper capsule; no original wrapper is
  required or invented.
- A fixed, committed wrapper-toolkit revision and its helper hashes, the exact
  native publisher/standalone tool identities, and the selected privacy policy.

## Bounded reuse sequence

1. Admit a completed original native/carrier capsule and its separately selected artifact
   on the matching native platform. Verify the original 58-carrier audit,
   archive bytes, original committed helper/source/profile bindings, build and SDK evidence, and unchanged
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

The reusable helper is implemented in `qualification/primary_rewrap.py`. Its
focused tests cover independent input pins, immutable copies, source/host scope,
wrapper format and count, private execution custody, refusal preservation and
named removal. The test's small orchestration fixture is not primary-native
qualification. No actual wrapper-only run has been performed, because the
inspected retained artifacts do not contain the required bytes.

## Explicit helper interface

The portable selection uses protocol
`symphony.distribution.primary-rewrap-selection.v1`. It names one original run
and one `d10-carrier-capsule-<profile>-<attempt>` artifact, with its ID, hash and
size, plus independently selected source, cohort, build, round, SDK, delivery
and acceptance hashes. `qualification/primary_artifacts.py` validates the
GitHub run/step/artifact metadata, bounded safe ZIP extraction and exact
extracted file inventory. A failed later wrapper step does not invalidate an
already successful native/SDK/carrier checkpoint.

```sh
python3 -B -m qualification.primary_rewrap rewrap \
  --selection SELECTED.json --selection-sha256 SELECTED_SHA256 \
  --artifact EXTRACTED_CAPSULE --transport-proof VERIFIED_TRANSPORT.json \
  --output NEW_PRIVATE_OUTPUT --toolkit-commit NEW_WRAPPER_TOOLKIT_COMMIT \
  --python PINNED_PUBLISHER_PYTHON --standalone PINNED_STANDALONE \
  --standalone-archive PINNED_STANDALONE_ARCHIVE --privacy-policy PRIVATE_POLICY
```

Upload only `NEW_PRIVATE_OUTPUT/artifact/`. It contains the unchanged capsule,
selection and transport proof, final wrappers and their audit, exact new wrapper
toolkit source, and a distinct result binding both toolkits. Constructor work,
private logs and machine state remain outside that portable directory. No
carrier is rebuilt or globally pinned by this operation.

The separate native hosted consumer prepares the existing isolated inspection
tool environment and selects the exact new result digest. Its Python includes
the Conda archive reader and codec; stock runner Python is insufficient. The
report binds the tool-preparation result, resolved package lock, executing
interpreter and decoder identities before and after the exercise. Those tools
inspect inert archives and do not invoke native Symphony owners:

```sh
PINNED_INSPECTION_PYTHON -B -m qualification.primary_rewrap fresh-user \
  --artifact DOWNLOADED_REWRAP_ARTIFACT --result-sha256 REWRAP_RESULT_SHA256 \
  --inspection-tools PRIVATE_INSPECTION_TOOLS_ROOT \
  --output NEW_PRIVATE_CONSUMER_OUTPUT --allow-ephemeral-install
```

The consumer must have a different hosted job identity and match the selected
primary OS/architecture. It verifies every inherited proof and wrapper byte,
audits a private read-only execution snapshot, installs all 58 inert carriers
without a solver override, exercises existing/force/upgrade/dangling-prefix
refusals, and removes only the selected package names through the installed
bootstrap with explicit offline/classic settings. It checks every carrier byte
and mode, package identity, private caller state, outside sentinel, notices and
bootstrap, and rechecks the original artifact and helpers afterward.

This is an automated shell-installer engineering check. It does not execute the
native Apple package installer, native owners, services or providers; qualify a
primary client or the separate CLI route; exercise two distinct releases;
complete any independent 36-cell acceptance requirement; establish publisher
trust; or authorize publication. Missing or mismatched capsules fail before
wrapping or execution. No evidence is manufactured from partial logs.
