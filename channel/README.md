# D09 immutable review staging

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
native owner. The `.pkg` and `.sh` wrappers are outside Anaconda staging and remain
selected for the later Cloudflare/website step. Their bootstrap notices/source
review is a separate open gate.

A staging success does not establish public beta approval, Apple Developer ID,
notarization, independent publisher authentication, a trusted key distribution
channel, live provider acceptance, or independent legal/backup review.
