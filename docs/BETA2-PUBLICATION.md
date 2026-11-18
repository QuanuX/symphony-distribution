# Public beta.2 publication

**0.2.0-beta.2** is published on QuanuX/beta and Cloudflare downloads.
The [publication record](../evidence/beta2-publication.json) binds all 240 packages
and 304 download objects to their signed release and completed public readbacks.
The procedure below records how those artifacts were assembled and published.

The publisher authorized **0.2.0-beta.2** as the live beta and latest
release. The separately pinned [publisher decision](../evidence/beta2-publisher-decision.json)
records that instruction and the existing legal acceptance and detached-signature
trust policy. It does not assert that a future build, installer or publication
has succeeded. The older [review authorization](../evidence/beta2-candidate.json)
and all beta.1 evidence remain unchanged.

The native artifacts retain exact Symphony source
`bae2e817120467561ae051c1b08cf61be3436bac`, with original client source
`572627e939250763756167a9dc05d8cb37ab4e30`. The source checkpoint after the
Symphony merge is `8a6889597eef3d2713f48bf6962456f989188e18`; it must not be
presented as the commit embedded in the already built native artifacts.

## Assembly and qualification

Select completed D12 package and D13 client artifacts using the existing strict
hosted-artifact selectors. Dispatch `d14-beta-assembly.yml` with
`authorization=evidence/beta2-publisher-decision.json` for each profile. This
builds fresh public-beta wrappers from verified native and client bytes; it does
not relabel a review wrapper. The constructor retains the normal `Symphony`
name and private `${HOME}/symphony` default prefix. Service activation, credentials,
application selection and system trust remain unchanged.

The resulting four final assembly artifacts must pass their carrier maintenance,
shell install/removal and first-run retention checks. Qualify the exact final
Mac `.pkg` through `d14-native-pkg.yml`. Assemble the complete release with
`channel/release_bundle.py`, using `release: 0.2.0-beta.2` and the exact new
publisher decision path and SHA256 in the private request. The bundle refuses a
beta.1 decision, a review-only candidate, a different source, incomplete owner
maintenance or a mismatched final PKG.

## Signing and publication

Use the existing private publisher custody and exact certificate/public-key pins.
`installer_assembly/beta_signing.py` selects the approved release policy from the
release index and requires that release's exact decision before signing. No key
rotation or Apple trust is implied. The standalone verifier can verify either
preserved beta with an explicit expected release:

```sh
python3 verify_beta.py --release 0.2.0-beta.2 --artifact release-index.json
```

Prepare new plans using `channel/beta_publish.py` and `channel/beta_downloads.py`.
Anaconda publication uses **QuanuX / beta** and an additional immutable
`beta-0.2.0-beta.2-<index-hash-prefix>` label. Download objects use only
`https://downloads.quanux.org/symphony/0.2.0-beta.2/`. Existing differing objects
or packages are never overwritten; uncertain writes require reconciliation.
Corresponding source must be publicly retrieved before native packages.

Only after signed artifacts and public bytes are verified should the GitHub
release be made live/latest and its links announced. GitHub's `latest` designation
[requires a non-prerelease release record](https://docs.github.com/en/rest/releases/releases#create-a-release) even when the version and prose clearly
identify Public Beta; the tag must retain `v0.2.0-beta.2`. No mutable download
alias or website deployment is part of these immutable publisher helpers.

The scope remains a public beta with publisher acceptance. It does not claim
review by another independent person, Apple Developer ID, notarization,
Gatekeeper acceptance, or upgrade/rollback between distinct native releases.
