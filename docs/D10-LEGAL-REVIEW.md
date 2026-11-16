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
- `evidence/d09-corresponding-source.json` identifies the exact original-versus-
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
