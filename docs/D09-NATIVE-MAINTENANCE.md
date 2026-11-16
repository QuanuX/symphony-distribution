# D09 native maintenance qualification

The selected delivery contains one version of each of 51 native components. D09
adds a source-bound maintenance register and a disposable delivered-byte campaign;
it does not enable production native installation, live removal, upgrade, rollback,
or automatic Maestro selection. Conda continues to own inert carriers only.

## Exact owner scope

The register is generated from core commit
`5fd6cee1bae477048bf0045b691ee8bdf334e216`, tree
`327edd0f22860e84d30fe745f5a2b0e602f4af88`, and the selected D06 build plan.
Every component's CMake source, owner template/shared generator, receipt helpers,
version, dependency roots, installed options and SDK exports are bound by hash.
Each configured uninstaller must describe exactly the delivered receipt's file
set before any disposable removal is attempted.

| Source owner form | Selected units | Scope |
| --- | ---: | --- |
| Component-local uninstall template | 36 | Exact configured receipt-v2 owner |
| Shared SNV generator | 6 | SNV common library and five core SNV engines |
| Shared SCV generator/template | 7 | Two SCEV and five SCHV engines |
| Component-local inline generator | 2 | SSIAG private store and SOV Cloudflare adapter only |

These owner forms share receipt validation, but their inventory is checked per
component. The existing qxctl managed native-controller dispatcher covers the
three Go receipt owners; its process-retirement guarantees are not generalized
to the 51 CMake units.

## Bounded campaign

`qualification/d09_maintenance.py` accepts a separately selected SHA256 for the
signed delivery's `CARRIER-COHORT.json`, verifies every delivered Conda archive and
nested payload, and creates a new private output. It reconstructs all 1,250
native, Go and external entries without running the binaries. It configures the
51 existing owners without compiling the native graph or activating services.
The selected tools retain their invocation names, including the C++ driver alias.

For each native unit, the campaign checks:

- Reinstallation of its existing immutable version refuses without writes.
- Each existing shared-root marker blocks raw install preflight and removal.
  This tests marker-presence fencing, not authenticated shared-root acceptance.
- An aliased receipt and changed owned bytes refuse without changing caller state.
- A partial removal resumes through the existing owner, then an absent-removal
  retry is idempotent. Other packages, external libraries and user state survive.
- Empty-version install preflight succeeds without writes.
- Copying the exact retained candidate back into absent paths restores the exact
  byte/mode snapshot. This is harness recovery, not native install or rollback.

Original archives, retained candidate bytes, source inputs, configuration tools
and imported qualification helpers are checked again before success is recorded.
Raw logs remain private; portable results contain their relative names, hashes
and exit codes. A partial or interrupted run does not produce a passing result.

The focused helper tests cover release-pair refusal, existing target and alias
protection, exact recovery, the deliberately injected receipt-alias observation,
source-owner classification and preservation of the compiler driver alias.

## Still required before a maintenance promise

No second independently qualified version is selected for any of these 51 units.
A rebuilt copy or changed label of the same candidate does not establish an
upgrade. The release-pair admission helper requires different native versions,
source identities, receipt hashes and artifact hashes, while leaving compatibility
and execution unqualified until an actual transition is tested.

The remaining gates are:

1. Per-owner live-use/process retirement and shared-root lifecycle authority.
2. Independently qualified distinct releases, side-by-side native installation,
   explicit selection, genuine upgrade and compatible rollback journeys.
3. Ownership and preservation of the external curl/zstd runtime and SDK closure.
4. Native primary-platform and independent fresh-host acceptance, including user
   state preservation and uncertain-operation reconciliation.

Historical development artifacts are not silently selected as rollback releases.
This campaign cannot grant publisher trust, reviewer approval or publication.
