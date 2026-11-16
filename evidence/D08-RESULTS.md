# D08 retained review delivery

D08 repaired qxctl's missing embedded source identity and assembled inactive,
modular review packages without changing core, client or distribution main.
The implementation is frozen at distribution toolkit
`f4a1467ee119a54e8941d3e13b3afe09861e39cf`. Later evidence/documentation commits do
not replace that assembly-source identity. The new client source is
`572627e939250763756167a9dc05d8cb37ab4e30`; core remains
`5fd6cee1bae477048bf0045b691ee8bdf334e216`.

## Observed results

| Gate | Retained observation |
| --- | --- |
| qxctl source identity | Two unchanged original-source recipe builds match; 291 compiled/embedded inputs match the reviewed export. The whole derived export is not relabeled original Git. |
| Client compatibility | All 22 actual Codex cases pass. The unchanged original W13 source-stamp verifier now passes; existing descriptors and adapters remain unchanged. |
| Default packages | 59 audited inert carriers: 51 native units, six Go delivery units, external runtime/SDK and client. Every original payload entry is assigned once; 20 SDK exports remain complete with their owners. |
| Conda qualification | All 59 packages/177 carrier files link and remove in a new private environment. User-state/outside sentinels and original archives remain unchanged. |
| Optional source | Separate source package and direct TAR bind the retained D06 archive, exact client/toolkit Git trees, original recipe and all 291 compiled inputs. One package/three carrier files link and remove with sentinels preserved. |
| Wrappers | Supplemental Intel macOS PKG and macOS SH each contain exactly the selected 59 Conda archives and pinned bootstrap. No wrapper installer was executed. |
| Privacy and scope | Publisher metadata is removed from wrapper headers/CPIO/BOM. Only recognized metadata companions are omitted; real file bytes/modes remain unchanged. Existing-prefix overwrite and ambient Conda-home ownership changes are refused. |
| Focused verification | Source/identity, packaging, privacy, refusal, signature, client and lifecycle boundaries pass their focused checks. The combined installer run had 89 passing cases; final additional Apple-finalizer coverage also passes. No CI completion was awaited. |

The selected carrier cohort digest is
`sha256:0b5ad60ceaafeb13b7e7edf0a1908cb2c04774d29823ced6b017216c40fdea70`.
The optional source package is separate and excluded from the default installer.
Package assembly uses the official archive writer; it is not a claim that
Conda rebuilt native binaries or that all outer archives reproduce across runs.

The [wrapper audit](d08-wrapper-audit.json),
[default package journey](d08-final-carrier-link.json),
[optional source journey](d08-optional-source-link.json),
[source index](d08-corresponding-source.json),
[client packet](d08-client-final-packet.json),
[qxctl proof](d08-qxctl-original-source.json) and
[focused validation record](d08-focused-validation.json) retain exact bindings.
Earlier failed/intermediate attempts remain separate; no old D06/D07 evidence
was rewritten into a later pass.

## Trust and remaining gates

The dedicated self-signed review manifest has been verified over all 76 final
delivery files. Its SHA-256 is
`7a6b055dc7478b23c5183941163145ce747619c9f3ee53b5fe968f4aa6a44da8`.
The [signature verification record](d08-signature-verification.json) and
[independent wrapper inspection](d08-independent-wrapper-review.json) bind the
completed observations. Signing used stable local staging after a prior copied
file and certificate changed filesystem metadata during reads; those attempts
refused before signing. Exact audited bytes were recovered and reverified,
without relaxing the check. The temporary private key copy was removed after
verification. The authorized key provides detached integrity with an explicit
certificate pin. The PKG itself remains unsigned. Two isolated
native signing probes, including the installer-specific certificate purpose,
were refused. No system trust was granted; the separate private keychain is
locked, and the default/search list remain unchanged. Private signing material
is excluded from repositories, artifacts and source exports.

This is supplemental local Intel macOS engineering evidence. A macOS SH is not a
Linux installer. Four primary-platform clean cohorts and native wrappers,
fresh unique-user host installations, complete native ownership/live-use safety,
real two-release maintenance/recovery journeys, final PR integration/source
selection, Apple Developer ID/notarization, independent key trust and acceptance,
redistribution review (including bootstrap dependencies), and approved
Anaconda/Cloudflare retrieval remain release gates. No provider, application
selection or Symphony service was activated; no release packages were uploaded to Anaconda or Cloudflare.

See the [D08 handoff](../docs/D08-INSTALLER-ASSEMBLY.md) for exact boundaries and
verification instructions.
