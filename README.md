# Symphony distribution preparation

This repository contains source-bound packaging and qualification tools for Symphony Public Beta. It is separate from [Symphony core](https://github.com/QuanuX/Symphony). It does not publish packages, choose an application module, start services, or change an existing installation automatically.

The reviewed core commit and source-file hashes are in `source-binding.json`. The current seven Go delivery routes are in `go-owner-catalog.json`. Clean build identities must match that exact source and the pinned Go 1.26.5 recipes. A passing local fixture is not publisher trust, fresh-host acceptance, or permission to upload.

Conda owns inert carrier files. Existing Symphony and host owners retain control of runtime files, profiles, credentials, selection, and process retirement. Runtime and rollback files are independent copies outside Conda prefixes and caches. Carrier removal cannot remove them. Python and Conda are preparation tools; these Go carriers introduce no runtime Python dependency.

## S06 supported boundary

| Journey | Implemented boundary |
| --- | --- |
| Install | Verified archives into a new private delivery prefix; explicit independent retention; the three recognized service owners may create a fresh stopped user installation. |
| Upgrade | Exact package build replacement with the complete Conda LINK/UNLINK set checked; old runtime and recovery files remain independent. |
| Swap | Explicit carrier replacement with unrelated packages preserved. Existing user-authorized application selection remains a separate owner operation. |
| Remove | Exact carrier removal; runtime removal requires a separately reviewed native-owner scope. Unknown, raw, active, shared, or unsupported use is not erased. |
| Rollback | Exact old archive restored from retained local input; fresh runtime restoration uses independently retained bytes through the existing owner. No automatic replay after an uncertain outcome. |

The Conda adapter accepts only prefixes it creates inside a fresh private attempt. It validates the complete solved transaction and the prepared actions, then executes that same transaction object. It does **not** claim exclusion against arbitrary concurrent Conda clients in existing environments. The adapter pins Conda 26.10.0 because it checks that implementation's transaction behavior. Conda's ordinary preview and a later install/remove invocation are not an atomic authorization boundary.

After exact carrier removal, an empty owned prefix may request normal cleanup of its private Conda cache. Global caches and existing environments are outside that operation. Completed local checks and remaining gates are recorded in [the S06 qualification report](evidence/RESULTS.md).

S07 adds process-bound attempt authority, concurrent-call exclusion, custody
identity checks and focused crash/recovery evidence. The [S07 campaign guide](qualification/README.md)
maps the fault cases to acceptance requirements and the four requested CI
platforms. It explicitly separates source/owner fixtures from real-manager and
fresh-host acceptance.

The current [S08 dossier](dossier/README.md) binds the corrected core source,
seven Go owners, retained beta requirements, rebuilt carriers and reviewed
source export. Start with the [delivery guide](docs/DELIVERY.md) for supported
preparation commands and the [recovery guide](docs/RECOVERY.md) for interrupted
or uncertain operations. [S08 results](evidence/S08-RESULTS.md) distinguish
reconstructed payloads from pending D06/D10 release acceptance.

| Go delivery | Runtime owner |
| --- | --- |
| SSIAG | `symphony-ssiag package`; native user receipt and retirement fence |
| STAV append authority | `symphony-stav-append-authority`; native user receipt and retirement fence |
| Accordare STAV producer | `symphony-accordare-stav-producer`; native user receipt and retirement fence |
| qxctl | Explicit executable/client selection; Linux host ownership remains separate |
| SSH adapter | Exact endpoint and invocation; protected transport provisioning remains separate |
| stdio adapter | Exact target configuration and invocation; outstanding jobs require their owner |
| transport profile administrator | Inert carrier only; fixed protected-path provisioning remains separate |

The broader historical owner inventory under `owner-catalog/catalog.json` is retained for compatibility and refusal checks. Its recorded source revision is historical; it does not qualify the remaining native/C++ units for safe live removal. No legacy build directories or machine-specific prototype inputs are included here.

## Run focused qualification

Use Python 3.11 or later for the standard-library contract tests. Select a clean checkout containing the exact bound core commit:

```sh
export SYMPHONY_SCOPE_TEST_SOURCE=/absolute/core-checkout
python3 tests/check_source_binding.py "$SYMPHONY_SCOPE_TEST_SOURCE"
python3 -m unittest discover -s owner-catalog -p 'test_*.py'
python3 -m unittest discover -s lifecycle -p 'test_go_delivery.py'
python3 -m unittest discover -s lifecycle -p 'test_handoff.py'
```

For real Conda archive and transaction qualification, use an isolated publisher environment with Python 3.12, Conda 26.10.0, and conda-build 26.9.1. Run the archive and transaction test modules with that environment's exact Python executable. No account login or upload token is needed. Preserve failed attempt directories for inspection; choose a new output directory only after resolving the recorded failure.

Build all seven candidates with the existing core build recipes. qxctl requires the two-build reproducibility gate. Verify `tests/launch-acceptance/check-go-candidate-closure.sh` in core before packaging. Then:

```sh
python tests/conda_journeys.py prepare \
  --go-root /absolute/go-candidate-build \
  --qxctl-root /absolute/qxctl-reproducible-build \
  --output /absolute/new-prepared \
  --profile local-macos-amd64-fixture --fixture
python tests/conda_journeys.py build \
  --prepared /absolute/new-prepared --output /absolute/new-archives
python tests/conda_journeys.py run \
  --archives /absolute/new-archives --output /absolute/new-journey
```

This local harness explicitly uses the supplemental Intel macOS fixture profile. Its two packaging builds retain the same real native versions. It cannot satisfy two-native-release acceptance or physical beta-platform qualification. It does not change global PATH, client configuration, supervisors, Anaconda channels, Cloudflare storage, or production trust.

## Distribution and remaining gates

Conda packages are intended for the QuanuX organization on Anaconda. macOS `.pkg` and Linux `.sh` downloads are intended for Cloudflare storage and the website. Neither destination is activated by this repository.

Remaining release gates include genuine two-version compatibility where available; real supported-host journeys; complete native/C++ and raw-consumer retirement coverage; external/shared ownership and pending-work recovery; final clean CI builds; publisher signing and trust; license/redistribution review; and approved publication. Installation preparation must never promote a refused or untested cell into acceptance.

Conda behavior references: [create](https://docs.conda.io/projects/conda/en/stable/commands/create.html), [remove](https://docs.conda.io/projects/conda/en/stable/commands/remove.html), and [package metadata](https://docs.conda.io/projects/conda-build/en/stable/resources/define-metadata.html). Pinned local source inspection and executable tests provide the transaction evidence; documentation alone does not establish safe runtime removal.

## D07 client gate

The [D07 client handoff](docs/D07-CLIENT-GATE.md) and [source-bound results](evidence/D07-RESULTS.md) record clean client packaging, all existing adapters maintained and 22 passing actual Codex cases on the exact retained D06 candidate. The separate distribution verifier preserves the unavailable embedded-source-stamp gate; final-platform, channel, trust and fresh-host acceptance remain open. Neither main branch is changed.

## D08 source identity and review installers

The [D08 handoff](docs/D08-INSTALLER-ASSEMBLY.md) and [retained results](evidence/D08-RESULTS.md) close qxctl's embedded-source identity defect and bind the refreshed client to the repaired bytes. The review delivery has 59 independent default carriers, a separate optional source package, and same-cohort supplemental Intel macOS PKG/SH wrappers. Source and native ownership remain explicit; self-signed review integrity does not establish Apple trust or release acceptance. See the results for focused tests, exact artifact proofs and remaining release gates.
