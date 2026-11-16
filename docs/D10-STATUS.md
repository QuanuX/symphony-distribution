# D10 selected Mac and acceptance-gate follow-up

The selected local Mac shell-installer check passed. The broader Public Beta
acceptance gate remains incomplete for the reasons listed below.

The release owner selected the retained Intel Mac build and assigned themselves
as the human redistribution reviewer. The feature freeze remains in effect.
Core and client `main` are unchanged; no source pull request has been merged.
The assignment is retained in `evidence/d10-reviewer-assignment.json`, with
the concrete review materials described in [the legal review handoff](D10-LEGAL-REVIEW.md).

## Existing runs and bounded repairs

The three Linux primary-platform runs failed before source export or building:
the private-policy writer supplied `opener` to `Path.open`, which does not accept
that argument. The writer now creates its private file exclusively using the
supported file-descriptor interface, retaining restrictive permissions and link
refusal. All 21 focused platform tests passed, including execution of the actual
workflow block. The cancelled Mac job received no runner and executed no steps.
Replacement runs were dispatched on the repaired revision for all four profiles;
their results were not awaited. See `evidence/d10-ci-triage.json` and
`evidence/d10-fixed-platform-dispatches.json`.

The inspected D06 cohort snapshot showed both Linux x64 profiles passing, with
macOS ARM64 and Linux ARM64 still running and no failing steps observed. The
client compatibility run had passed. Core PRs #200, #201 and #202 each had all
59 checks and all 11 PR workflows passing, including CodeQL; no reruns were
needed (`evidence/d10-core-pr-checks.json`). Distribution PR #1's older branch was
fast-forwarded to its existing, already-tested fixture repair, leaving its
descendant work and all main branches intact. The retained CI and branch-repair
records distinguish these observations from newly requested runs.

## Selected Mac installer

The first actual run of the original signed shell wrapper stopped before
installing any carriers. Its global plugin-disable setting suppressed the
embedded bootstrap's required `constructor` command. The original signed
artifacts remain unchanged; the failure and private-log hashes are retained in
`evidence/d10-original-mac-wrapper-failure.json`. Earlier carrier-only Conda
installation evidence remains valid for that separately tested delivery route.

The [selected Mac campaign](D10-MAC-SHELL.md) passed against the separately signed
repair using the shipped installation defaults. All 59 packages installed and
all 177 carrier files matched their selected bytes and modes. Existing-prefix,
forced-replacement, upgrade and dangling-link requests refused without changing
installed or caller state. Named offline removal removed every selected carrier
and preserved private-home/user/outside state, wrapper notices and the bootstrap.
`evidence/d10-selected-mac-shell.json` retains the exact result, six command-log
hashes and 23 executing-helper hashes. Original signed inputs, the new overlay
and the verified private execution copy were rechecked unchanged.

Both repaired formats now pass their final audits and a separate automated
artifact review, preserving all 59 original carrier archives. Their separate six-artifact
review signature and exact source binding are retained in
`evidence/d10-repaired-wrapper-overlay.json` and
`evidence/d10-repaired-wrapper-manifest.json`. The original review identity and
all published carrier bytes are unchanged. The Mac package is audited but has
not been installed through Apple's system installer.

The final affected suites passed: 21 platform, 25 constructor, 15 package
finalizer and 17 selected-Mac/overlay tests. The final constructor and Mac changes
were independently rechecked across all 42 tests. Workflow lint and the private
source-policy scans passed. These checks are separate from actual installer
execution and from hosted CI results.

## Primary wrapper-only follow-up

The later completed-run inspection found all four replacement primary builds
compiled successfully, then failed while collecting the old toolkit source.
The private-marker defect is already repaired in the current branch. All eight
D09/D06 artifacts were downloaded and matched to their recorded hashes and
sizes, but contain reports only. The successful four-platform D06 run likewise
retained no native payload bytes. The earlier expectation of reusable outputs
was therefore not established.

The [wrapper-only implementation](D10-PRIMARY-REWRAP.md) now verifies explicit
run, artifact, source and carrier pins, rebuilds only wrappers, and exercises
installation, safe refusals and named removal on a separate matching hosted
runner. It preserves the original carrier bytes and distinguishes native-build
source from wrapper-repair source. An isolated, identity-bound archive reader is
prepared for the consumer; stock runner Python cannot inspect these archives.

Native payloads are now retained immediately after compilation, and completed
carriers before wrapper assembly. One recovery producer run per primary profile
was dispatched to obtain bytes that the old jobs did not preserve. The exact
run links are in `evidence/d10-primary-recovery-dispatches.json`. These runs use
the unchanged reviewed source/export pins; no core/client checks are rerun and
no new CI result is awaited. Wrapper-only execution remains pending verification
and selection of actual completed carrier capsules.

All 81 focused tests passed across transport, retained-build validation,
platform capsules and wrapper/consumer contracts. Workflow lint and the entire
247-file implementation source collection/privacy scan also passed. The exact local results are recorded in
`evidence/d10-wrapper-implementation.json`. Actual old artifact transport and
report-schema checks supplement these fixture tests; they do not create a
primary-native or fresh-host acceptance result.

## Gate interpretation

The unchanged original core and companion acceptance checkers ran against newly
initialized requirement packets and returned their expected **incomplete** state.
The 36 scenario cells, 58 paper criteria and 31 supplemental requirements remain
in scope. These initial packets are not a regression count, and their missing
entries do not erase the separately retained D09 delivery and maintenance
observations. See `evidence/d10-original-gates.json`.

The broader release gate still requires:

- Primary-platform outcomes, matching clients and scoped fresh-host observations.
- Full native installation and live-use/shared-root maintenance safety.
- Independently qualified distinct versions and real upgrade/rollback journeys.
- Authorized source integration and exact final artifact/protocol bindings.
- Recognized publisher signing, notarization and independently obtained trust.
- A dated, scope-bound human legal decision, independent acceptance and backup/recovery review.

Selecting the local Mac does not establish primary ARM/Linux coverage or an
independent fresh host. Assigning a reviewer does not manufacture their review
decision. Self-signing supplies review integrity, not Apple publisher trust.
No public-beta promotion, Cloudflare installer upload or runtime activation is
authorized by these records.
