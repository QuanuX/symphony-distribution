# S07 fault, concurrency and platform qualification

Current **0.2.0-beta.2** results are recorded in the
[publication evidence](../evidence/beta2-publication.json), which binds the
selected hosted qualification and public retrieval results. The
[beta.1 hosted record](../evidence/d14-beta-hosted-qualification.json) remains
historical evidence for its original bytes.
The S07/D06 methods and tables below retain their engineering-stage scope;
historical unobserved cells are not current release status. The beta qualifies
packaging revision changes and same-candidate recovery, with distinct-native-version
transitions and unsupported live ownership remaining outside its accepted scope.

This campaign qualifies bounded distribution and existing native-owner behavior
against `source-binding.json`. It preserves the Public Beta feature freeze. It
does not modify core, select a module in Maestro, start a host service, authorize
publication, or establish that an arbitrary existing installation is safe to remove.

The Conda boundary is a fresh private attempt owned by one live creator process.
Fork inheritance is not authority. One operation at a time may inspect or mutate
the attempt; competing calls refuse before touching its evidence. The root,
prefix, fixed custody directories and live lock descriptor must retain their
identities. A failure poisons the attempt. A terminated process's attempt cannot
be reopened, adopted or automatically retried. These restrictions concern this
packaging adapter, not users' freedom to compose Symphony modules.

## Run the focused campaigns

Use an isolated Python 3.12 environment with Conda 26.10.0 and conda-build 26.9.1.
No Anaconda login or upload token is needed. Each output directory must be fresh.

```sh
python -m unittest discover -s qualification -p test_conda_campaign.py -v
python qualification/conda_campaign.py --output /absolute/new-conda-evidence
python3 -m unittest discover -s qualification -p test_platform.py -v
python3 qualification/host_platform.py --profile ubuntu24.04-amd64 \
  --output /absolute/new-platform-report.json
```

The Conda campaign executes the real solver, prepared transaction and package
manager with inert fixture carriers. Process and thread barriers confirm the
contender or fault reached the intended boundary. Tests assert both the expected
refusal/effect and preservation of unrelated data. The portable report includes
all test and subtest outcomes, exact tool versions and source/test hashes. Empty,
skipped, expected-failing, failed or incomplete results cannot pass. Raw logs and
interrupted fault attempts remain in the private evidence directory; they are
not installable payloads. Prior S06 transaction fixtures remain disposable.

For native-owner fixtures, select a clean checkout of the exact bound core
commit and Go 1.26.5. Prepare an isolated module cache from the public checksummed
module versions before running offline:

```sh
python3 -m unittest discover -s qualification -p test_native_campaign.py -v
python3 qualification/native_campaign.py --source /absolute/reviewed-core \
  --profile ubuntu24.04-amd64 --output /absolute/new-native-evidence \
  --go /absolute/go1.26.5/bin/go \
  --gomodcache /absolute/verified-module-cache --gocache /absolute/test-build-cache
```

The native campaign runs exact named tests under the Go race detector. Every
selected test must appear and pass; skipped tests and truncated event streams
fail. Source paths, line numbers, file hashes, acceptance IDs, expected oracles,
observed outcomes and log hashes are retained. Three additional real native
owner executables exercise completed-response loss: discard the response, first
observe exact durable retirement and owned-byte absence, then explicitly
reconcile the same completed identity. This does not authorize replay of an
uncertain or still-running operation. No host service is activated.

## Historical S07 acceptance mapping and limits

All results below are **E1** engineering fixtures. A refusal passes its refusal
oracle; it does not demonstrate successful live removal. Exact native selectors
and per-owner oracles are maintained in `native_campaign.py` and its report.

| Acceptance cells | Conda campaign | Native campaign | Remaining boundary |
| --- | --- | --- | --- |
| D05-S09 concurrency | Forked authority refuses; contending thread operations refuse; independent creators reach exclusive creation and produce one effect. | Execution lease, concurrent admission/retirement and foreign-claim changes. | No exclusion claim against unrelated clients of existing Conda environments. |
| D05-S10–S12 use and admission | Carrier operations never claim to stop runtime consumers. | Real bounded child leases, closed-admission starts, exact recovery, missing-custody refusal. | Restart injection at each reference-scan, stop-completion and first-delete boundary remains incomplete. |
| D05-S13–S14 identity and lifetime | Not a process-manager authority. | Descriptor/reference refusal and unavailable-manager fixture. | Actual stale/reused process identities, inaccessible user domains and detached-descendant lifetime need applicable host-owner evidence. |
| D05-S15 crash and lost acknowledgement | Real child termination after validation, after execution marker, after real effect and during real unlink; retained partial state cannot be reopened. | Controller-crash fixture, receipt-last recovery and real completed-response-loss observation/reconciliation. | Native mid-operation response loss and all actual stop/delete crash boundaries remain incomplete. |
| D05-S16 custody and rollback | Directory/lock replacement after preparation, damaged/missing archives or installed payload, hardlinks/symlinks, foreign metadata and intent-write failure refuse. | Exact controller custody, root/lock/receipt replacement, evidence inode and publication-path refusal. | Unknown custody is retained; there is no universal repair/adoption path. |
| D05-S17–S19 owner authority | Inert carriers only; native execution remains separate. | Shared-root claims, exact native dispatch, self/controller survival and bounded output. | Raw executables, remaining C++ units, external supervisors and unresolved Accordare audit work require their real owners. |
| D05-S26 carrier ownership | Same prepared transaction, exact complete delta, independent runtime copies and private cache cleanup. | Retained controller independence. | Arbitrary pre-existing/shared prefixes remain outside the adapter. |
| D05-S27 release transitions | Exact install/build-upgrade/swap/remove/rollback carrier journeys. | Fresh stopped installations and exact same-identity reconciliation. | Distinct genuine native releases, full authorized profile selection and native rollback acceptance remain open. |
| D05-S28 user data | Foreign files and claims, partial-state preservation and independent copies. | Unrelated profile/root fields and user sentinel preservation. | Fixture success does not establish preservation on an unexamined user system. |
| D05-S29 platform | Real Conda campaign on each requested CI profile. | Source-bound fixtures on each requested profile; read-only manager inventory. | Hosted results must be observed separately. Actual manager lifecycle, privileges, fresh hosts and physical hardware remain E2 gates. |
| D05-S30 delivered release | No publication. | No publisher or installer trust claim. | S08 / D06 / D10 final byte binding, signing, trust, redistribution and independent acceptance. |

## Platform evidence

The workflow requests macOS 15 ARM64, Ubuntu 24.04 AMD64, Ubuntu 24.04 ARM64 and
Ubuntu 26.04 AMD64. It verifies the actual OS/version/architecture before
qualification. Runner unavailability or a mismatch is incomplete, never a
replacement platform. `local-macos-amd64-fixture` is supplemental only.

Read-only launchd/systemd probes report each scope as accessible, inaccessible,
missing or timed out. Accessibility is not lifecycle acceptance. WSL is not
silently promoted to the native Linux profile. No manager is installed, enabled
or provisioned by this campaign.

Changed paths select the affected contract, Conda and native boundaries. A
Conda-only implementation change does not rerun unrelated native fixtures.
Workflow/source/platform changes rerun their affected matrix cells. Hosted
reports and diagnostic logs are retained, excluding candidate binaries, runtime
trees, private homes, interrupted attempt directories, caches and custody files.
Local raw logs may contain local paths; only reviewed portable reports belong
in this source repository.

The runner labels are defined by [GitHub's hosted-runner documentation](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).
Bootstrap assets are pinned by digest to the [official Miniforge release](https://github.com/conda-forge/miniforge/releases/tag/26.9.4-2).

## D06 final-source SDK and removal closure

After `build-cohort/build.py` completes, the additional closure runs against one
exact final round. Repeated-build equality is established by the cohort builder;
this campaign verifies the selected round's source provenance, helper hashes,
51 native receipts and full payload inventory before using it.

```sh
python3 qualification/d06_sdk_closure.py \
  --repository /absolute/exact-core-checkout \
  --cohort-output /absolute/completed-cohort --output /absolute/new-closure-work \
  --go /absolute/go1.26.5/bin/go --gomodcache /absolute/verified-module-cache \
  --cmake /absolute/cmake --cc /absolute/clang --cxx /absolute/clang++
```

On Apple hosts, also pass the same explicit `--developer-dir` used to build the
cohort. The copied original L20 census function produces the synthetic native
evaluation used by the unmodified shipped `libraries/sbv-go/examples/roundtrip`.
This runs independent source compilation, typed streaming, cancellation,
proposal evaluation, resume and comparison against final qxctl/native bytes.
Its declared synthetic probabilities do not become calibrated provider evidence;
the broader L20 process-fault campaign is not claimed by this selection.

An additional consumer imports, explicitly links and calls `operations()` on all
five core SNV SDKs: SNIV, SNRV, SCIV, SCNV and SNV. It does not require the optional
local observer. This is a separately reported `core_snv_api_smoke` gate: the
original cohort audit's all-imports check does not itself establish these API
calls. The copied native import proof binds every imported header/library to the
selected relocated prefix and rejects source fallback.

Each native owner is configured without rebuilding or installing its payload.
The resulting detached uninstaller's configured file set must exactly match the
final receipt. On a disposable full-prefix copy, the campaign checks owned-byte,
SDK header/export, receipt-digest and resealed-identity tamper refusal; incomplete
receipt admission; resumable removal; exact retry; and unrelated-file preservation
in reverse dependency order. A timeout is a failed gate, never a successful
refusal. External libraries, Go binaries and caller evidence remain outside these
native removal claims and must survive unchanged.

The final candidate, source inventory and helpers are checked again afterward.
Only the bounded `result.json` is retained for sharing; raw fixture outputs and
logs remain private. A passing report closes these observed engineering checks,
not live process retirement, publisher trust or fresh-host acceptance.


D06 local evidence binds the final cohort comparison, source SDK/removal campaign
and delivery record to the same selected payload. The delivery collector verifies
all build/imported/repair helper identities and preserves exact original toolkit
source when artifacts are inherited. Source-defined SSIAG and Cloudflare notice
files under `share/doc` must match their two original legal files byte for byte;
arbitrary documentation is never treated as a license.

`d06_upstream_source.py` admits only the pinned curl archive's exact public TLS
fixture members and unchanged attribution overlaps during corresponding-source
scanning. Archive bytes stay unchanged and exceptions are included in the source
index. Installed payloads and publisher-created files receive no such exception.

See [D06 results](../evidence/D06-RESULTS.md) for the historical local evidence
and gates outstanding at that stage. The selected final artifacts and accepted
beta.2 scope are recorded in the [publication record](../evidence/beta2-publication.json).
