# Exact package handoff preparation

For the supported carrier commands, ownership stages and explicit maintenance
flows, start with the [delivery guide](../docs/DELIVERY.md). This document covers
the lower-level proposal inputs. [Recovery guidance](../docs/RECOVERY.md) keeps
retained or uncertain outcomes separate from completed effects.

`handoff.py` writes a private proposal and never runs qxctl, a native package owner,
a selector, or a service. The complete caller-selected profile, observation,
native boot journal and plan, apply status, expected prior-state digests, receipt,
catalog, and controller build binding remain required and hash checked. The
generated scope admits one existing package effect; unrelated plan actions remain
in the retained full plan and are excluded from that scope.

The original `symphony.distribution.scoped-install-request.v1` request remains
supported for installation into an absent component. A
`symphony.distribution.scoped-package-request.v2` request has the same fields,
`format_version: 2`, and these additional fields:

| Field | Meaning |
| --- | --- |
| `operation` | `install`, `upgrade`, `swap`, `remove`, or `rollback` |
| `prior_receipt_digest` | Exact installed prior candidate receipt for upgrade, swap, or rollback; otherwise `null` |
| `prior_install_root` | Exact observed prior installation root for those transitions; otherwise `null` |

V2 is bounded to the reviewed user-scope SSIAG, STAV append authority, and Accordare
native service contracts. Its desired component must remain inactive and undocked.
The installed component must be deselected, inactive, undocked, and compatible for
any removal or transition proposal. An observation alone does not prove released
processes or other profiles' references: the actual native owner rechecks those
under the runtime locks when a separately approved command executes.

| Intent | Proposed effect | Required retained evidence |
| --- | --- | --- |
| Install | One native `install`, ownership `retained` | Exact target receipt, staged payload, independent target controller/carrier |
| Remove | One native `uninstall`, ownership `release` | Exact single installed receipt at the desired root; full desired absence; retained copy of its payload, receipt, and matching controller/carrier outside installation roots |
| Upgrade / swap | One target `install`, ownership `retained` | Exact single prior installed candidate plus independent prior and target controllers/carriers; distinct nonoverlapping target root |
| Rollback | One selected retained target `install`, ownership `retained` | The same two-candidate evidence; a fresh distinct root, with the current candidate retained |

Upgrade, swap, and rollback are caller-selected intents for a package preparation
stage. They do not assert version ordering, prior deployment history, completed
selection, activation, or a completed rollback. They cover one component's existing
owner contract. Cross-owner transitions, unreviewed historical owner versions, and
new executable names require their own qualified contract before preparation.
This kit does not infer compatibility from a package name or native version alone.

Use the existing required handoff arguments and, for a transition, also supply:

```text
--prior-receipt /absolute/retained-prior-receipt.json
--prior-receipt-sha256 <independently-selected-file-sha256>
--prior-native-owner <component-id>=/absolute/retained-prior-carrier/<binary>
--prior-native-owner-manifest-digest sha256:<independently-selected-manifest-digest>
--prior-native-owner-custody /absolute/independent-prior-custody
--prior-native-owner-custody-digest sha256:<independently-selected-custody-digest>
```

If the retained prior candidate uses the qualified older catalog, also supply its
`--prior-catalog`, `--prior-catalog-sha256`, and `--prior-catalog-digest` together.
Without those arguments it must match the explicitly selected target catalog.
The existing `--catalog` arguments select the target catalog, including a
qualified older target for rollback. Callers cannot introduce a source-binding
file, compatibility waiver, or new owner policy.

`--native-owner` and `--native-owner-manifest-digest` select the target controller
(or the exact retiring controller for removal). V2 also requires
`--native-owner-custody` and `--native-owner-custody-digest`. Create independent
controller-only custody with `python3 lifecycle/go_delivery.py retain`;
its `custody.json` and `retained-carrier` must validate under
the selected catalog. A bare Conda carrier, or a custody record coupled to a
possibly retired installation, is insufficient. The selected executable must be
the exact retained executable named by that record.

Custody cannot overlap configured runtime roots or have an ancestor containing
`conda-meta`. Supply every selected known carrier, cache, or environment root with
repeatable `--conda-owned-root`; overlapping custody is refused. The helper does
not infer arbitrary cache ownership outside these checks. This is explicit
private qualification custody, not a universal claim about all package managers
or concurrent external writers. Both carriers must match their
explicitly selected qualified source catalog, receipt, executable bytes, build
identity, and platform. `--source-root` always names a separate verified payload copy; it is not
an installed root. For removal, this retains the old candidate without copying
its host-local retirement guard. Sole installed controllers, raw command owners,
system removal, live or unknown state, multiple installed candidates, unfulfilled
native prerequisites, changed receipts, in-place replacement, and unsupported
source versions refuse before proposal output.

`install-native` is a separate `go_delivery.py` subcommand for fresh stopped
user-scope materialization. There is no CLI `materialize` subcommand or
`--install-native` flag. A v2 scoped handoff needs the controller-only `retain`
route, rather than custody coupled to a disposable runtime installation.

The only retained source pairing is S05 `ad7ed0e0857a1d8cc9d0fa3617579bbf5fc46b70`
with current controller `5fd6cee1bae477048bf0045b691ee8bdf334e216`. Its binding and
catalog are under `qualified-sources/`; the binding's file digest is code owned.
The selected native owner implementations and dispatcher must match the current
source hashes. This permits explicit review of retained older controllers without
accepting arbitrary historical catalogs. It adds no publisher trust or runtime
acceptance claim.

The actual ad7ed0e and 5fd6cee builds have identical executable hashes for all three
native owners:

| Native owner | SHA-256 in both builds |
| --- | --- |
| SSIAG | `042572fb4b8dd5c3fb3277c043c03f057785d504de85dbebe11a2525c360a2e6` |
| STAV append authority | `6798f6a2a3c83298eec1bac85b709a2304d6adb961a5a0a7a7a4ac16bc89c4d1` |
| Accordare | `28588a619eafe53a86fbffc520c7d5c927cc2a7321469cd328ef19321f8604b8` |

They therefore have identical native receipts. A transition request between them
refuses with a packaging-only explanation: the carrier may change, but a native
replacement is unnecessary and no native install scope can be invented. A genuine
distinct-release runtime transition remains an acceptance gap until another exact
source, owner contract, and artifact pairing is qualified.

The private `handoff.json` records all input hashes, source identity, exact scope,
retained controllers, excluded actions, and a review-only native apply argument
list. `journey_completed`, `execution_authorized`, `owner_invoked`,
`runtime_selection_changed`, `runtime_activation_changed`, and
`live_removal_qualified` remain false. Each subsequent selection or retirement
step needs its existing owner's fresh full-profile observation, plan, and exact
scope; this helper does not synthesize those results or automatically retry an
uncertain mutation. Recovery of an in-flight or scoped predecessor remains an
explicit native recovery flow.

Focused tests require a clean checkout at the commit and tree recorded in
`SOURCE-BINDING.json`. They read schema objects from Git and fail if the checkout
or source binding differs; there is no missing-source skip:

```sh
SYMPHONY_SCOPE_TEST_SOURCE=/absolute/reviewed-core-checkout \
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s lifecycle -p 'test_handoff.py'
SYMPHONY_SCOPE_TEST_SOURCE=/absolute/reviewed-core-checkout \
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s lifecycle -p 'test_journeys.py'
```

These are synthetic preparation checks, including refusal and no-owner-invocation
tests. The source binding contains immutable source checks only. Neither artifact
is a fresh-host, signing, publisher-trust, runtime-journey, or release acceptance.
