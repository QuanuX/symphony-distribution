# Remaining Public Beta gates and human handoff

This is preparation for the accepted distribution plan's D10–D12 gates. It
keeps the feature freeze and all source integration decisions intact. The
release owner is already assigned as the human redistribution reviewer; the
decision itself is pending. Independent reviewers, fresh-host operators and
recognized Apple signing identities have not been selected. This document does
not appoint them or supply their approval.

The accompanying [human review template](../evidence/templates/d11-human-review.json)
pins the retained evidence by SHA-256. Copy it to a new private review record;
keep the template and historical packets unchanged. Null decision fields mean
pending, never approval. The template is a handoff, not an executable gate or an
authenticated human decision.

## Candidate scope to carry into every decision

| Scope | Selected evidence | Established boundary |
|---|---|---|
| Package-only Anaconda review delivery | [D09 stage plan](../evidence/d09-anaconda-stage-plan.json), [fresh retrieval](../evidence/d09-anaconda-fresh-retrieval.json), [CLI journey](../evidence/d09-public-conda-install.json) | 60 immutable review carriers, including optional source; no standalone bootstrap or native runtime activation |
| Selected local Intel Mac | [repaired wrapper supplement](../evidence/d10-repaired-wrapper-overlay.json), [manifest](../evidence/d10-repaired-wrapper-manifest.json), [actual shell journey](../evidence/d10-selected-mac-shell.json) | Default 59 carriers including the client; repaired shell installed and removed locally; native `.pkg` audited but unexecuted |
| Four primary platforms | [recovery dispatches](../evidence/d10-primary-recovery-dispatches.json), [wrapper-only handoff](D10-PRIMARY-REWRAP.md) | Recovery producers dispatched; no completed carrier capsule selected for wrapper-only qualification in this handoff |

The original selected core is `5fd6cee1bae477048bf0045b691ee8bdf334e216`;
client `572627e939250763756167a9dc05d8cb37ab4e30`; original carrier toolkit
`f4a1467ee119a54e8941d3e13b3afe09861e39cf`. The repaired local wrappers use
toolkit `afa7f9f127112564dc917152071bdf07da560fca`. These distinct identities
remain visible. The complete core source is a reviewed derived export; qxctl
has a separately verified original-Git component build with equal compiled
inputs. Neither a later documentation commit nor a wrapper repair changes the
origin of retained native bytes.

Primary capsules contain 58 core carriers and do not establish the local
candidate's client coverage. A matching final client and actual Codex evidence
must be selected separately for primary claims. The local Intel result does not
substitute for macOS ARM64, either Ubuntu 24.04 architecture, Ubuntu 26.04 x64,
or an independent fresh host. Preserve the original **36 scenario cells,
58 paper criteria and 31 supplemental requirements**.

## Work that can proceed in parallel

| Gate | Concrete next action | Completion evidence / missing input |
|---|---|---|
| Redistribution | Give the assigned release-owner reviewer the exact original packet and repaired-wrapper supplement. Review package-only and standalone scope separately. | Dated actual human decision, exact artifacts/routes, remaining conditions and original review-record digest; still pending |
| Primary delivery | Admit completed, digest-selected native/carrier capsules, then use the prepared wrapper-only and separate consumer jobs. | Actual completed capsule, exact GitHub transport/source/profile pins, resulting wrapper and fresh-consumer records; no output invented from a running job |
| Independent payload/trust/acceptance | Prepare the final source, inventory, privacy, signature and acceptance packet for named reviewers. | Independent people, declared relationships, actual evidence access and dated decisions; unassigned |
| Recovery and operations | Select genuine versions, state owners, disposable destinations and bounded workorders before live drills. | Supported owner paths, second distinct qualified version, operators, approved effects, RTO/RPO and measured recovery; pending |
| Recognized Apple trust | Prepare the signing inventory, least-required entitlement review and certificate/custody checklist below. | Authorized identities and notary credentials held outside the repository, independently obtained publisher identity, final signed-byte checks; pending |
| Source integration | Reconcile the exact stack and client divergence in an isolated proposed integration, then present resulting trees. | [Current integration snapshot](../evidence/d11-integration-snapshot.json), reviewed integration strategy and explicit authority; no merge in this increment |
| Release decision | Populate the original checkers and client companion with actual final-bound observations and unresolved limitations. | Structurally complete packets plus separate human decisions and explicit promotion authorization; pending |

The prepared executors and their focused tests are useful engineering work.
They do not mean their full campaigns have run. The [original-gate observation](../evidence/d10-original-gates.json)
used newly initialized packets and returned incomplete as expected; its missing
entries are not a new product regression count. Retain passing evidence with
its original scope instead of copying it into unrelated acceptance cells.

## Fresh-host, matching-client and native installer sequence

1. Select a completed primary 58-carrier capsule using the exact request and
   audit in [artifact selection](D11-ARTIFACT-SELECTION.md). Its saved metadata
   still requires the hosted transport's authoritative recheck. Use the
   [current recovery snapshot](../evidence/d11-primary-recovery-snapshot.json)
   as an observation, not as a completed selection or an instruction to wait.
2. Run wrapper assembly and the separate matching hosted consumer against that
   selection. Keep the install prefix and user/cache state new. Verify actual
   downloaded archive identities, nested carrier bytes/modes, fresh-prefix
   refusal behavior and named removal with user/outside state preserved. These
   inert carrier journeys do not install or activate the native payloads.
3. Select a clean matching client build for the same core/catalog identity and
   native profile. Bind its artifact and source inventories, observed qxctl
   stamp and actual Codex executable. Run the existing focused client checks
   and actual Codex campaign against those final bytes; keep the existing
   adapter compatibility labels. The Intel client result cannot fill this
   primary-specific slot.
4. The prepared [primary gate workflow](../.github/workflows/d11-primary-gates.yml)
   exercises the existing 51 native owners in disposable unmanaged prefixes,
   with a source-bound configuration and the exact selected carrier payloads.
   It checks refusals, partial removal, safe retry and same-candidate recovery.
   It remains pending selected artifacts and does not claim native installation,
   live retirement or a two-release transition.
5. For the native Apple `.pkg` route, select a disposable matching macOS host
   and its authorized operator before running the system installer. No such
   independent host is assigned. Record installer privilege/destination scope,
   download/trust assessment, baseline state, exact installed carrier bytes and
   the actual package receipt. Exercise the documented removal path and verify
   user/unrelated state and package ownership afterward; unexplained system
   changes or an unavailable supported removal route keep the gate incomplete.
   Native Symphony installation/owner receipts require their own supported
   owner campaign; an Apple wrapper receipt does not establish them.

Retain command outcomes and independent oracles, including failures, for the
exact final host/profile and entry route. None of these steps authorizes a main
change, production activation, an invented second version or a claim that an
unexecuted installer passed.

## Redistribution review package

Use the [original packet](../evidence/d09-acceptance-packet.json) with the
[existing assignment](../evidence/d10-reviewer-assignment.json). It binds all
131 native/Go/external notice files and the standalone bootstrap's 115 declared
components. The package-only Anaconda set excludes that bootstrap; the `.pkg`
and `.sh` contain it. The reviewer must resolve the existing bootstrap matching
source/build/offer and exception questions against its exact component texts.
Notice presence, an accessible source archive and a successful install do not
resolve that review for them.

The standalone decision must additionally bind repaired-wrapper manifest
`97152020349962e044f4e89971da3cecd7deba89babee1be001b3c7aeda9c8b7` and its
six artifacts, including the new wrapper-toolkit source. Record any conditions
separately for packages, repaired local wrappers, and later primary outputs.
A decision on one scope does not approve another or approve changed artifacts.
Use the existing [legal handoff](D10-LEGAL-REVIEW.md) for the complete material
list; this document makes no license-applicability decision.

## Independent author, acceptance and operational campaigns

Give the independent author or documentation-only agent the final public
SDK/packages and shipped instructions. Retain the exact task, public entry
routes, expected oracle, questions, failed attempts and resulting programs.
Author self-review or an implementation agent's automated review does not
establish the independent role required by the accepted plan.

For each selected provider/fault/performance campaign, bind the artifact and
client pair, host/profile, native owner, protocol/schema, approved account and
environment, entitlement, allowed effects and expiry. Predeclare workload,
duration, ceilings, stop conditions, resource/latency measurements and an
independent endpoint oracle. Record proof that each injected fault occurred,
uncertain effects and authorized cleanup. Do not infer live provider success
from fixtures or retry an operation whose effect is unknown.

These are the retained W09–W11 obligations in the selected core's
`tests/public-beta/execution/CAMPAIGN-HANDOFF.md`; they are not new runtime
features. Unsupported credential/OS/provider routes and deferred capabilities
retain their explicit disposition. Any changed beta claim needs the release
owner's scope decision; a blank cell is not a waiver.

## Recovery, upgrade and rollback workorder

The [D09 maintenance campaign](D09-NATIVE-MAINTENANCE.md) exercised one version
of each selected native owner in disposable unmanaged prefixes. Its same-
candidate copy recovery does not establish an upgrade, downgrade or rollback
between distinct versions. Before a distinct-version transition campaign,
select **two genuine,
independently qualified versions** with their immutable bytes, source, receipts,
compatibility/schema declarations and notices. Renaming or rebuilding the same
candidate solely to fill a version slot is not that evidence.

Name the backup operator, independent reviewer and escalation owner. Inventory
state roots, independent stores, active writers, WAL/checkpoints, pending effect
identities and authority records through the selected supported owners. Agree
RTO/RPO, quiescence/consistency requirements and permitted outage before the
drill. Restore into a new private destination; verify acknowledged data, pending
work and fresh authority. Retain wrong-owner, corrupt/mixed-chunk, active-writer,
stale-authority, capacity and incompatible-version refusals where applicable.
Measure actual recovery against the declared targets.

Use [recovery guidance](RECOVERY.md): preserve uncertain attempts and old bytes,
reconcile through the native owner, and leave user state and other modules
intact. Live/shared-root retirement, external dependency ownership and supported
restore routes remain prerequisites, not permissions for forced cleanup. Prepare
a withdrawal/rollback and support-routing rehearsal with exact destinations,
scope and escalation ownership; this handoff sends no tickets or messages and
does not invent a service commitment.

## Recognized publisher trust

The selected self-signed review certificate proves integrity under the explicit
review pin. It is not recognized Apple publisher identity, notarization or an
independently authenticated trust policy. Retain that original evidence intact.

For the Apple route, select the authorized team and appropriate Developer ID
Application and Developer ID Installer identities. Apple distinguishes signing
code outside the Mac App Store from signing its installer package.
[Apple certificate types](https://developer.apple.com/help/account/certificates/certificates-overview/)

Apple's notarization preparation requires valid executable signatures, suitable
Developer ID certificates, Hardened Runtime for application/command-line
targets, secure timestamps and appropriate entitlements. Notarization checks
code-signing and malicious-content issues; it is not App Review. Use the current
`notarytool` workflow and retain the returned log/ticket and final assessment.
[Apple notarization documentation](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution)

The nonsecret handoff needs team/certificate identities, public fingerprints,
selected signing/notary tool versions, custody owner and opaque credential-store
references. Keep keys and credential values outside source, artifacts and review
records. Select entitlements per actual target, including bundled dependencies;
do not grant broad exceptions simply to make a check pass.

Treat signing as a new immutable candidate operation. Finalize and sign affected
inner executables before their exact-byte receipts and carrier manifests are
sealed; apply outer package signing/notarization afterward. Recompute the final
download inventory after all byte-changing steps. Recheck native receipt/loader/
SDK behavior, wrapper preservation, downloaded trust and fresh-user execution
on those final bytes. Preserve old candidates; do not attach new identity claims
to their old signatures. Independently authenticate the publisher/trust channel
and exercise applicable native `.pkg` installation before claiming that route.

## Integration and final decision

The [integration snapshot](../evidence/d11-integration-snapshot.json) is a
point-in-time graph, not merge approval. It identifies two concrete items:

- Client #6 diverges from current client main. Preserve main's merged #5
  onboarding/catalog changes when reconciling the stack, then bind the actual
  resulting client tree and rebuild/requalify its affected delivery.
- Distribution #3 retains three historical Linux SDK failures. Their compiler
  alias repair exists downstream and the later four-profile D06 run passed.
  Select a propagation/integration strategy; do not label that old head green
  or rerun known-broken historical source to manufacture a clean badge.

Before an authorized merge, refresh exact refs/checks, review the proposed
result and preserve recovery evidence. Rebind resulting core/client/toolkit
identities and rebuild only affected dependency/receipt/client/trust closures.
Unchanged passing checks need no broad rerun for this handoff. All mains remain
untouched now.

The final release packet must map all original cells, actual final downloads,
independent decisions, limitations, incident/withdrawal ownership and applicable
trust results to the exact proposed release. Existing checker success is
structural readiness only. `d09_acceptance.verify_decisions` likewise validates
handoff shape and packet binding; it cannot authenticate a human or establish
independence. Keep the original dated human record and its digest, authenticate
it through the release owner's process, and obtain the explicit release
decision separately. No Public Beta promotion, Cloudflare installer upload,
source merge or live activation follows from completing this template.
