# Retained native outputs to wrapper qualification

This engineering increment repairs the primary packaging handoff under the
feature freeze. It does not close the release-decision gate named D12 in the
original distribution plan. Core/client main and the distribution default
remain unchanged.

## Observed failures and repair

The targeted S06 contract run 43945410578 passed. At the bounded observation,
D06 run 43945383060 was still running its three selected Linux cohorts with no
failed step. No duplicate job was requested and no CI completion was awaited.
The [targeted snapshot](../evidence/d12-targeted-ci-snapshot.json) preserves
that observation rather than asserting a later result.

All four primary producers at toolkit commit
`e3544e729b0013df505ef2e2ad8f9963a58e7e5d` completed their two native build rounds,
native retention, delivery collection and supplemental SDK checks. Packaging
then failed because the carrier builder expected repair-specific per-component
provenance on fresh whole-cohort records. Fresh records now retain their exact
original source, aggregate and round bindings; repaired/inherited provenance
is unchanged. The [producer snapshot](../evidence/d12-primary-failure-snapshot.json)
records the original failures and retained artifacts.

## Verified inputs and recovery scope

The four [explicit selections](../evidence/native-selections) select the original
native capsule and SDK/delivery evidence ZIP independently by GitHub artifact
ID, size and digest. They bind the exact producer run/attempt/commit and the
previously reviewed core source/export. A native recovery archive is an earlier
checkpoint than a completed carrier capsule; the existing carrier-only selector
continues to refuse it.

Local admission verified all eight ZIP digests, the four complete canonical
native archives (6,990 entries each), 51 native receipts per platform, the two
recorded identical payload inventories, original Git helper identities and
original successful SDK evidence. Raw downloads, API snapshots, extracted
custody and the private scan policy remain outside this repository. See the
[admission record](../evidence/d12-native-admission.json).

The manual [recovery workflow](../.github/workflows/d12-native-rewrap.yml) takes
a committed selection path and its independently selected SHA-256. It:

1. Fetches current authoritative GitHub metadata and both exact archives again.
2. Restores and verifies the native bytes, source, receipts, qxctl proof and
   original helper closure on the matching primary runner.
3. Reuses the original passed SDK report. It reconstructs notices and matching
   source material from exact public dependency inputs without rebuilding the
   native payloads or repeating the SDK/removal campaign.
4. Assembles 58 inert carrier packages and matching wrappers. Original native
   provenance and new packaging-toolkit provenance remain separate.
5. Sends the exact verified result to a separate matching hosted job. That job
   executes a private wrapper copy, checks fresh-prefix refusals, and removes
   the named carrier packages while preserving caller state and wrapper support
   files. It never invokes native runtime owners or activates services/providers.

Normal pushes run only focused contracts. Manual runs require a reviewed
selection; they cannot silently fall back to native compilation. Recollection
retains the existing exact OS-release requirement and current/original helper
identity checks. A changed runner image or changed selected helper causes a
refusal requiring investigation.

## Remaining boundaries

New carrier and wrapper results remain pending their dispatched runs. A dispatch
is not a passing result. Shell installation in a disposable hosted job does not
establish native `.pkg` installation, physical independent-host/client acceptance,
live/shared-root maintenance, a genuine two-release upgrade/rollback, final source
integration, recognized publisher signing/trust, legal sign-off or independent
acceptance and recovery review. Existing hash-bound review records and original
candidate bytes are preserved. No publication or merge is performed.
