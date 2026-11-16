# D10 selected Mac and acceptance-gate follow-up

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

The [selected Mac campaign](D10-MAC-SHELL.md) separately verifies wrapper
installation, refusal of unsafe existing-prefix operations, named inert-carrier
removal, and preservation of caller state. Repaired wrapper bytes must receive
their own source and signature binding before this campaign can pass.

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
