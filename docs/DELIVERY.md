# Delivery and maintenance guide

This guide describes the preparation tools in this repository at the core source
recorded in [source-binding.json](../source-binding.json). It is not a published
installer announcement. Conda carriers are intended for **QuanuX on Anaconda**;
macOS `.pkg` and Linux `.sh` installers are intended for Cloudflare storage and
website downloads. Public URLs, approved signatures and final-host acceptance
are still release inputs. Do not infer an available package from its reserved name.

The default distribution choice is clean CI-built binaries, with optional
reviewed source/SDK delivery. Users do not inherit a publisher's home directory,
credentials, profiles, machine identities or build cache. A whole-suite selection
may compose independently versioned units; it must not turn them into one
inseparable runtime package or force all modules to share a release version.

## What each stage changes

| Stage | Supported effect | Separate decision still required |
| --- | --- | --- |
| Verify/build carrier | Prepare exact inert payload and source/recipe evidence. | Publisher trust and release approval. |
| Conda install/upgrade/swap/remove/rollback | Apply the reviewed complete carrier transaction in one new private attempt. | Runtime installation, application selection and process retirement. |
| `retain` | Copy the verified carrier into independent private custody. | Any native operation. |
| `install-native` | Retain an independent controller and create a fresh stopped installation through one of the three exact user-scope native owners. | Enrollment, grants, selection, docking, service start and existing-root maintenance. |
| Scoped handoff preparation | Write a proposal for one exact owner effect using full-profile safety inputs. | Fresh native authorization and execution. |
| Native removal | Existing owner verifies references, use, receipt, guard and exact scope before reclaiming its bytes. | Carrier cleanup and any separately requested user-data purge. |

Application composition remains user controlled. The existing lifecycle owners
perform selection and activation under their contracts. Maestro records
authenticated receipt/executable docking presence; its current contract does not
schedule, select or start engines. Undocking or changing inactive metadata does
not establish process termination. Packaging introduces no additional selector.

## Seven Go delivery owners

These are exact current candidates, not floating public Go module versions.
The [owner catalog](../go-owner-catalog.json) binds the source, versions and
capabilities. Equal version strings do not make older binaries compatible.

| Component | Compiled version | Runtime owner and limit |
| --- | --- | --- |
| `secure-identity-access-governance` | `0.1.0-dev` | `symphony-ssiag package`; exact native receipt, user-scope retirement and foundation lifecycle. |
| `stav-append-authority` | `0.2.1` | `symphony-stav-append-authority`; exact native receipt, user-scope retirement and foundation lifecycle. Published historical `v0.2.1` is not proof of the current retirement guard. |
| `accordare-stav-producer` | `0.1.0-dev` | `symphony-accordare-stav-producer`; native receipt, enrollment, supervision and pending audit work. |
| `qxctl` | `0.1.0-dev` | Exact client executable or Linux host binding. No generic runtime receipt or self-updater. |
| `sov-ssh-adapter` | `0.1.0-dev` | Exact SOV endpoint/invocation; protected profiles need their separately qualified dependency and administration closure. |
| `sov-stdio-adapter` | `0.1.0-dev` | Exact target/invocation; changing future admissions does not stop admitted jobs. |
| `sov-transport-profile-admin` | `0.1.0-dev` | Protected host provisioning. A carrier does not install sudo policy or grant administrator authority. |

The last four may be retained as inert executable delivery, but `install-native`
refuses them. No raw executable is relabeled as a receipt-owned native service.
The larger native/C++ inventory retains its separate owners and open live-use
qualification; this seven-command kit does not close that inventory's gates.

## Supported preparation commands

Run commands from the distribution repository. Use the isolated publisher
environment's Python for archive and Conda work: Python 3.12, Conda 26.10.0 and
conda-build 26.9.1. Use exact Go 1.26.5 when rebuilding the bound core candidates.
No publisher account login is required for these local commands.

For a verified four-file carrier, the following variables stand for independently
reviewed inputs. Select existing absolute paths for `VERIFIED_CARRIER` and a new
absolute path for each output; never derive a trusted expected digest solely
from the same untrusted input that it is meant to authenticate. Hash validation
binds bytes but does not replace independently trusted publisher signatures.

```sh
python3 lifecycle/go_delivery.py retain \
  --catalog go-owner-catalog.json --catalog-digest "$REVIEWED_CATALOG_DIGEST" \
  --carrier "$VERIFIED_CARRIER" --manifest-digest "$REVIEWED_MANIFEST_DIGEST" \
  --output "$NEW_CUSTODY_ROOT"
```

For one of the three native service owners, `install-native` performs a real
fresh stopped installation beneath its new output root. It refuses root
execution, a mismatched host and pre-existing output. It is not an upgrade of an
existing application installation:

```sh
python3 lifecycle/go_delivery.py install-native \
  --catalog go-owner-catalog.json --catalog-digest "$REVIEWED_CATALOG_DIGEST" \
  --carrier "$VERIFIED_CARRIER" --manifest-digest "$REVIEWED_MANIFEST_DIGEST" \
  --output "$NEW_NATIVE_CUSTODY_ROOT"
```

Both operations write private custody evidence. To inspect a successful record,
`--output` identifies that existing custody directory rather than a new output:

```sh
python3 lifecycle/go_delivery.py inspect \
  --catalog go-owner-catalog.json --catalog-digest "$REVIEWED_CATALOG_DIGEST" \
  --output "$EXISTING_CUSTODY_ROOT" --custody-digest "$REVIEWED_CUSTODY_DIGEST"
```

The explicit `--fixture` switch permits the supplemental Intel macOS fixture
profile; it is not a compatibility waiver, a publisher signature or acceptance
of a primary platform. The `cleanup` subcommand intentionally refuses automatic
live cleanup. `materialize` is the internal Python function name, not a CLI
subcommand, and there is no `--install-native` flag.

For an exact audited carrier, generate and build one recipe using fresh outputs:

```sh
python recipes/go_generate.py \
  --catalog go-owner-catalog.json --catalog-digest "$REVIEWED_CATALOG_DIGEST" \
  --carrier "$VERIFIED_CARRIER" --manifest-digest "$REVIEWED_MANIFEST_DIGEST" \
  --output "$NEW_RECIPE_ROOT"
python recipes/build_go_carriers.py build \
  --recipe "$NEW_RECIPE_ROOT" --manifest-digest "$REVIEWED_MANIFEST_DIGEST" \
  --output "$NEW_ARCHIVE_ROOT"
python recipes/build_go_carriers.py audit \
  --recipe "$NEW_RECIPE_ROOT" --manifest-digest "$REVIEWED_MANIFEST_DIGEST" \
  --archive "$BUILT_ARCHIVE"
```

Pass `--fixture` consistently to these three commands only when the carrier is
an explicitly selected fixture. Audit final archive bytes, not a prior staging
directory. [Source and payload ownership](SOURCE-AND-PAYLOAD.md) explains what
must be included and excluded.

## Conda journey semantics

`lifecycle/conda_transaction.py` is an importable API, not a persistent shell
session or standalone installer CLI. `Attempt.create(new_root, channel, subdir)`
creates the private prefix, channel copy, cache and evidence under `new_root`.
One live creator process owns it. A child created by fork cannot reuse that
authority; competing method calls refuse before evidence mutation. Closing the
object leaves files for inspection but permanently ends its authority. A new
process cannot reopen or adopt that prefix.

During that one live attempt, `transact` accepts these exact effects. `expected_link`
and `expected_unlink` contain complete reviewed archive identities returned by
`artifact_identity`, including payload files; package names alone are insufficient.
Add specifications are exact `name=version=build` selections. The real solved
and prepared transaction must match the complete reviewed delta.

| Operation | Exact API arguments | Resulting boundary |
| --- | --- | --- |
| Install | `transact('install', add_specs=[target_spec], expected_link=[target])` | Carrier added; no runtime installation or activation. |
| Upgrade | `transact('upgrade', add_specs=[target_spec], expected_link=[target], expected_unlink=[old])` | Explicit replacement of this carrier build; unrelated packages preserved. No inferred newest version. |
| Swap | `transact('swap', add_specs=[target_spec], remove_names=[old_name], expected_link=[target], expected_unlink=[old])` | Carrier exchange only; application binding is unchanged. |
| Remove | `transact('remove', remove_names=[old_name], expected_unlink=[old])` | Exact carrier files removed; independently retained runtime/recovery bytes remain. |
| Rollback | `transact('rollback', add_specs=[old_spec], expected_link=[old], expected_unlink=[current])` | New reviewed transaction to a retained old archive; add `remove_names=[current_name]` for a cross-name reverse swap. No history replay or native unretire. |

Review and retain the old controller, exact receipts and rollback bytes outside
the Conda prefix/cache before a carrier replacement or removal. `clean_cache()`
is supported only on the still-live attempt after its owned prefix is empty. It
uses ordinary bounded cleanup of that attempt's cache, never global cache cleanup
or forced dependency removal. This adapter makes no exclusion guarantee against
arbitrary external clients writing an existing shared environment.

The existing source-bound qualification harness supplies a complete runnable
example. It requires all seven clean Go identities and qxctl's reproducible build
output; its two packaging builds are not two native releases:

```sh
python tests/conda_journeys.py prepare \
  --go-root "$VERIFIED_GO_BUILD_ROOT" --qxctl-root "$VERIFIED_QXCTL_BUILD_ROOT" \
  --output "$NEW_PREPARED_ROOT" --profile local-macos-amd64-fixture --fixture
python tests/conda_journeys.py build \
  --prepared "$NEW_PREPARED_ROOT" --output "$NEW_ARCHIVES_ROOT"
python tests/conda_journeys.py run \
  --archives "$NEW_ARCHIVES_ROOT" --output "$NEW_JOURNEY_ROOT"
```

`run` executes real disposable carrier transactions and fresh native fixtures.
It preserves independent custody and user sentinels; it does not activate a
service or qualify an existing user's environment. For focused fault checks,
use the [S07 campaigns](../qualification/README.md).

## Existing application maintenance

Use [scoped handoff preparation](../lifecycle/README.md) for the full-profile
inputs, exact receipts, independent controller custody and required hashes.
`python3 lifecycle/handoff.py --help` lists its actual arguments. Every full
profile and observation remains a safety input; the immutable execution scope
permits only the reviewed component effects and ownership writes. An action
count limit is not a scope. Completion of one scope is not full-profile
convergence.

An upgrade, swap or rollback proposal stages a target in a distinct immutable
root. Selection/docking and old-version retirement require their own fresh
owner observations, authorization and scope. Shared-root mutation goes through
the exact native dispatch contract; copied internal descriptor numbers are not
user permission switches. Byte-identical native receipts refuse an unnecessary
native replacement even if their Conda build numbers differ.

There is no automatic retry after a failed or lost outcome. Follow
[recovery and refusal handling](RECOVERY.md), preserving evidence and user data.
Final release gates include fresh-host and actual-manager journeys, real
two-release transitions, remaining raw/C++ ownership, publisher trust,
redistribution review and approved public delivery.
