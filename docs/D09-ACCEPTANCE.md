# D09 source integration and independent review preparation

This packet makes the remaining decisions reviewable. It does not merge a PR,
approve redistribution, authenticate a reviewer, grant publisher trust, or
release Symphony. Core main remains unchanged. The feature freeze remains in
place; no additional runtime capability is introduced.

## Exact candidate and integration graph

`evidence/d09-review-selection.json` selects the retained D08 candidate:

| Source role | Commit | Meaning |
|---|---|---|
| Symphony core | `5fd6cee1bae477048bf0045b691ee8bdf334e216` | Origin of the reviewed derived source; qxctl separately uses the original Git recipe with equal compiled/embedded inputs |
| Client | `572627e939250763756167a9dc05d8cb37ab4e30` | Package that passed the original source-stamp gate and 22 actual Codex cases |
| Distribution implementation | `f4a1467ee119a54e8941d3e13b3afe09861e39cf` | Source that assembled the selected carriers and wrappers |
| Distribution review head | `1b76f2a51860a5ebd719c1bdcba6ab277e84cfe4` | Later evidence/documentation head; not a claim that it rebuilt the candidates |

The immutable one-time snapshot is `evidence/d09-pr-stack-snapshot.json`.
The integration dependency order is:

- Symphony: main → #199 → #200 → #201 → #202.
- Client: main → #6 → #7 → #8.
- Distribution: default branch `codex/s06-conda-journeys` → #1 → #2 → #3 → #4 → #5.

The distribution repository currently has no `main` branch; its existing
default branch is an explicit integration anchor, not permission to rename or
replace it. GitHub reported all twelve PRs mergeable at capture time. Ten exact
local base/head ancestry checks passed. The two initial core/client base commits
were absent from the shallow local checkouts, so their ancestry was not locally
verified. No scratch merge was needed or performed.

At capture, the returned PR-triggered workflows for core #199–#202 were
successful. Client #8 had a failed aggregate workflow, and distribution #1
retained its older failed S07 workflow. Other returned client/distribution PR
workflows were successful. The connector query is first-page and PR-triggered
only: it does not establish required-check coverage, dispatched platform results,
review approvals, or continued branch freshness. A later selective retry does not
rewrite this historical snapshot or qualify a different head.

Before an authorized integration, refresh exact refs and required checks,
classify every historical failure against the exact proposed result, select the
integration strategy, and record the resulting commits/trees. Rebuild and rebind
affected candidates when their selected source identity changes. Keep the old
candidate records intact. A passing old artifact cannot silently acquire a new
commit stamp after a merge or squash. No merge is authorized by this preparation.

## Notice and source review

The packet verifies all 131 retained D06 notice files against their exact hashes
and lengths. These cover the selected native units, Go modules/toolchain and
external dependencies; their original scopes remain visible. It also verifies
the separate installer bootstrap's two original notice files. The selected
bootstrap manifest declares 115 bundled components; each declaration and notice
text digest is retained without copying upstream builder paths into the public
packet.

Notice presence is not a completed redistribution review. The bootstrap manifest
includes GPL/LGPL declarations and exceptions alongside permissive declarations.
Its exact component source/build/offer closure is not established by Symphony's
corresponding-source archive. The bootstrap is outside the package-only D09
staging set and remains a separate installer release gate.

Reviewers should assess the exact selected license texts, attribution, matching
source and build material, applicable exceptions, and the actual delivery route.
For AGPL-covered material, the upstream license describes object-code/source
delivery in section 6 and an additional modified-network-program condition in
section 13. Applicability and the selected compliance route require qualified
review. [GNU AGPLv3](https://www.gnu.org/licenses/agpl-3.0.en.html)

Conda's own BSD license does not describe every component bundled into the
standalone executable. Use the exact retained third-party manifest as well as
the package's license, rather than treating the executable as one uniformly
licensed component. [Conda license](https://docs.conda.io/en/main/license.html),
[conda-standalone source](https://github.com/conda/conda-standalone)

The review must also cover client/toolkit source, original-versus-derived source
scope, upstream source exceptions, OS/TLS dependencies, optional/vendor
exclusions, and source-access directions and retention at the eventual download
location. Public review staging is still public distribution. Make the exact
corresponding source available with clear directions for the staged binary set;
the label is not access control or a legal approval.

## Human handoff

No independent reviewer or fresh host has been selected. All seven packet roles
remain unassigned:

| Role | Concrete handoff |
|---|---|
| Source integration owner | Exact PR graph, source trio, required checks, proposed integration result and rebuild/rebinding consequences |
| Redistribution reviewer | All exact notice files, 115-component bootstrap inventory, source index, delivery routes and unresolved source/offer obligations |
| Independent payload reviewer | Final artifact inventory, privacy evidence, source transformations and wrapper byte-preservation proof |
| Independent trust reviewer | Explicit certificate pin/custody, signature scope, independent authentication, applicable Apple signing/notarization |
| Independent acceptance reviewer | Four primary platform/fresh-host campaigns, client pair, delivered-byte checks and limitation register |
| Backup reviewer | Retained rollback bytes, restore drill, RTO/RPO, interrupted-operation recovery and operator handoff |
| Release approver | All preceding exact-bound decisions, remaining limitations, withdrawal plan and explicit promotion authorization |

Assign reviewers explicitly and confirm independence outside this tool. Give each
reviewer the packet digest and its evidence, obtain a dated decision identifying
the exact scope, and retain the original review record. Do not enter model output
as a human decision. Test completion, a GitHub author identity or the included
self-signed certificate does not establish independent acceptance.

`verify_decisions()` checks a handoff's packet digest, role, declared human name,
decision and the format of its declared review-record digest. It does not fetch
or authenticate the original review record. It deliberately reports authentication and
independence as unestablished; even a structurally valid `approved` JSON row
leaves legal/release/publication approval false. Authenticate the actual record
and reviewer through the release owner's separately selected process.

## Reproduce the packet check

Use the public selection with the original digest-bound notice directory and
the inspected wrapper's `share/symphony/installer` directory containing
`BOOTSTRAP.json` and `bootstrap-notices/`. These inputs are not rewritten.

```sh
python3 -B qualification/d09_acceptance.py \
  --selection evidence/d09-review-selection.json \
  --evidence-root evidence \
  --notice-root "$REVIEWED_DELIVERY_ROOT" \
  --bootstrap-root "$INSPECTED_BOOTSTRAP_ROOT" \
  --output "$NEW_PRIVATE_REVIEW_DIRECTORY/packet.json"
```

Re-run with `--verify` in place of `--output` to compare the entire regenerated
packet against the retained one. A new selection, changed source identity,
changed notice, escaping/link path or changed evidence digest fails. Output must
be a new file separate from all selected inputs. Optional `--decisions` consumes
a JSON array of handoffs for structural checking only.

Focused regressions run with:

```sh
python3 -B -m unittest discover -s qualification -p test_d09_acceptance.py -v
```

The prepared packet does not replace D10 fresh-host tests, remaining native
lifecycle safety, genuine two-release journeys, live provider/fault campaigns,
backup/support drills or the D12 release decision. These retain their own exact
artifact and human acceptance gates.

The accepted distribution plan retains @quantDIY as release/scope approver and
rollback primary. The packet's unfilled role entries represent outstanding
review handoffs for this exact candidate; they do not transfer that authority
or imply that the assistant can make an independent release decision. The user
has not yet selected independent acceptance, redistribution or backup reviewers.

Current follow-up: the release owner selected the existing Mac candidate and
assigned @quantDIY as human redistribution reviewer. See
[D10 legal review](D10-LEGAL-REVIEW.md) and
`evidence/d10-reviewer-assignment.json`. This later assignment does not rewrite
the historical packet or record a legal approval that has not been supplied.
