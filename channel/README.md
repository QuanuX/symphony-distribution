# Signed beta publication and review staging

Choose your operating system and installation method on the
[Symphony downloads page](https://quanux.org/downloads). It links the public
QuanuX/beta packages, signed installers and matching verification instructions.
The [beta.2.1 publication record](../evidence/beta21-publication.json) includes
checksums and public readbacks for all four profiles.

## Anaconda package overviews

The package summary describes the individual component. The overview links installation instructions, explains how to find corresponding source for a particular build and identifies historical D09 review files where applicable. The optional Ubuntu node keyring has its own Debian installation directions. [Anaconda installation guide](https://quanux.org/downloads/anaconda)

Run this command from the repository root to print the package and version overview fields as JSON. Both use identical Markdown because Anaconda can mirror an edit to a version description onto the package. The two original beta.1 client and corresponding-source cards retain their four platform-specific URLs from the signed release's publication records. The D09 review source links come from the original staging plan.

```sh
python3 channel/package_metadata.py
```

The beta, optional keyring and D09 publishers use the same summaries and documentation links when creating catalog records. Each published file carries its own exact source reference. The legacy `quanux` package uses a separate publication path within the organization.

## Public download links

The downloads hostname and its `/symphony/` directory lead to the platform
selector. Each version directory opens that version's tagged release. Saved
package links under `/symphony/<version>/packages/<profile>/` resolve to the
same archive on that release's immutable Anaconda label. Installers, signatures,
explicit package lists and other signed objects are served directly from R2.

Render the Cloudflare configuration from the repository's publication records.

```sh
python3 channel/beta_download_redirects.py > downloads-redirects.json
```

The output contains the `symphony_public_downloads` Bulk Redirect List definition,
its exact source and destination pairs, and the rule for the account's
`http_request_redirect` phase. Provision the dedicated list, load the items,
and check the completed list operation and item readback before enabling the rule.
When updating an existing account entry point, add or update only the rule
with that list's reference. Verify package responses by following the redirects
and comparing file SHA-256 values with the release index. A request for an
unknown filename continues to R2. [Cloudflare Bulk Redirects API](https://developers.cloudflare.com/rules/url-forwarding/bulk-redirects/create-api/)

## Publication tools

`release_bundle.py` admits the explicitly selected completed qualification and
publisher decision. `beta_publish.py` and `beta_downloads.py` require the exact
signed plans and explicit publication flags; they preserve immutable remote
identities and stop on uncertain writes. `verify_beta.py` checks selected public
downloads against the pinned certificate, key and signed manifest. Publication
is not an automatic consequence of a branch merge or passing CI.

The self-signed detached publisher signature does not assert Apple Developer ID,
notarization or separate human-reviewer independence. The completed publication
record supplies the accepted beta scope; historical D09 review labels
remain distinct from that release.

The [beta.1 publication record](../evidence/d14-publication.json) and its exact
build source links remain historical evidence for beta.1. Use a fresh installation
prefix and retention directory for beta.2; in-place native transitions between
beta.1 and beta.2 are not qualified. Each exact Anaconda build description names
its own corresponding source; a reused native version alone does not select
a release, platform or source cohort.

## D09 review-stage contracts

`staging.py prepare` verifies the independently selected review certificate pin,
detached signature and every signed D08 artifact before deriving the exact 59
core/client carriers plus optional corresponding-source carrier. It preserves
native/module identities and assigns a cohort-specific `d09-review-<digest>` label
under QuanuX. The label is publicly reachable, not access control. It does not
change the embedded review-only scope, the selected payload or the original
signed manifest.

`stage` requires that exact prepared plan, signed input set, certificate pin and
`--allow-public-review-upload`. Use the selected Anaconda client 1.16.0 with its
existing account authentication. Account/token values are never arguments or
retained evidence. Existing immutable builds must match bytes, size and selected
label; different builds are refused. There is no overwrite, deletion, promotion
to `main`/`beta`, or implicit relabel operation. The exact corresponding-source carrier is uploaded and freshly retrieved first;
its URL and extraction directions accompany each binary record. A durable
mutation-intent record precedes each upload. An uncertain result stops the attempt: inspect the journal
and remote identity before making a new explicit decision; do not blindly retry.

`retrieve --plan PLAN --output NEW_DIRECTORY` uses an empty authentication/cookie
context with no proxy environment, downloads each exact URL into a fresh directory,
and checks actual length and SHA-256. Redirects require HTTPS and selected
Anaconda/object-storage hosts; signed redirect query values are never retained.
A partial retrieval produces incomplete evidence and cannot satisfy the gate.
Changing only labels does not change the signed artifact identity.

The supplemental Intel macOS D08 delivery is a review candidate, not a primary
macOS ARM or Linux result. Conda linking/removal manipulates inert carrier files;
runtime installation, selection, live retirement and rollback remain with the
native owner. The `.pkg` and `.sh` wrappers are outside this historical Anaconda
review-stage operation. The later beta release publishes
its selected wrappers through Cloudflare with source/notices evidence; website
integration remains a separate presentation step.

A staging success does not establish public beta approval, Apple Developer ID,
notarization, independent publisher authentication, a trusted key distribution
channel, live provider acceptance, or independent legal/backup review.

`install_qualification.py` separately verifies the selected completed stage and
signed delivery, then uses Conda 26.10.0 with explicit HTTPS URLs and SHA-256
fragments. It starts with an empty private cache, environment and user folder;
checks all 60 downloaded archives and 180 linked files; and removes only those
carriers offline while preserving caller/outside sentinels. This tests the real
public CLI route without invoking native owners or claiming fresh-host acceptance.
