# Selected Mac candidate and human redistribution review

On 16 November 2026, the release owner selected the retained Mac build for the
next qualification and identified themselves as the human legal reviewer.
`evidence/d10-reviewer-assignment.json` records that direction and binds the
selected candidate and prepared review packet. The public record uses a release-owner role alias; the original user direction binds the assignment.
This records an assignment; it does not invent a completed legal review,
independent review, source-integration approval or public beta promotion.

The selected candidate is the existing Intel macOS review delivery. Its exact
package URLs and checksums are in `evidence/d09-anaconda-stage-plan.json`, and
the existing manifest signature covers the unchanged artifacts. Local Mac tests
remain supplemental to the four retained primary profiles. The user's choice
does not silently reduce the 36-cell acceptance campaign or turn an existing
Mac user account into a fresh independent host.

## Material available for the decision

- `evidence/d09-acceptance-packet.json` binds all 131 selected native/Go/external
  notices and the standalone bootstrap's 115 declared components. It preserves
  the original legal and source review limitations.
- `evidence/d08-corresponding-source.json` identifies the exact original-versus-
  derived source scope. The source package listed first in the staging plan is
  publicly available and was freshly retrieved before binary uploads.
- `evidence/d09-anaconda-fresh-retrieval.json` and
  `evidence/d09-public-conda-install.json` demonstrate source/package access and
  exact-byte CLI delivery. Download success does not establish license rights.
- The package-only Anaconda review stage excludes the standalone bootstrap.
  The Mac `.pkg`/`.sh` include it, so installer redistribution needs its own
  component source/build/offer and exception review. No wrapper was uploaded to
  Cloudflare, and this step does not authorize that publication.

## Decision to retain after review

The human review record should identify the exact packet digest, selected
artifacts, delivery route and date; state approved, rejected or needs changes;
and list any remaining conditions. Keep package-only and standalone-installer
scope explicit. A reviewer can accept or reject the selected materials without
claiming independent technical testing or recognized Apple signing.

The existing handoff checker checks record structure and exact packet binding.
It cannot decide legal applicability or authenticate an external approval.
Retain the human's actual decision separately; do not substitute generated text
for it. The earlier D09 packet remains unchanged, with this assignment supplied
as a later overlay. Release authority remains with the release owner.

## Repaired wrapper supplement

The original signed shell wrapper failed its first actual installation check.
Its replacement preserves all 59 selected carrier archives and adds a separately
signed wrapper/source supplement. The existing Anaconda staging record still
describes the original, unchanged 60 carrier packages; it has not been recreated
or relabelled as a new wrapper publication.

Review `evidence/d10-repaired-wrapper-overlay.json` together with the original
packet. The selected supplement manifest is
`97152020349962e044f4e89971da3cecd7deba89babee1be001b3c7aeda9c8b7`.
Its six artifacts include the repaired `.pkg` and `.sh`, wrapper audit and repair
binding, and the exact 231-file wrapper-toolkit source archive/index from
`afa7f9f127112564dc917152071bdf07da560fca`. The signature uses the original review
certificate; it does not grant Apple publisher trust or notarization.

The repaired shell SHA-256 is
`98ba45f86fe3f2603713d73a550edc08bcf18c99f7bbb8b6fa0b4dd191d288d6`;
the repaired package SHA-256 is
`dfe548bf595bf5cb8524c84ca7b332674cc92c71cfa6ae9d18786bfe522110d0`.
Any standalone-installer decision must identify this supplement as well as the
original carrier/bootstrap notice and source materials. The earlier assignment
remains in force; no legal approval is inferred from rebuilding or signing.

The repaired shell subsequently passed its local installation, refusal and
removal check (`evidence/d10-selected-mac-shell.json`). The package wrapper is
audited but unexecuted through Apple's installer. These technical results are
supporting review material; they do not supply the human's legal decision.
