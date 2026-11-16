# S08 Public Beta distribution dossier

This is the current distribution supplement to Symphony's preserved W01–W12
dossier. It binds core source `5fd6cee1bae477048bf0045b691ee8bdf334e216`, the seven
Go delivery owners and the S06/S07 engineering evidence. It keeps the feature
freeze in force and leaves release acceptance incomplete. Core remains unchanged.

The original `tests/public-beta/dossier.json` still describes its historical
W01/W06 baseline `887e074780e1d0633bd6e6f57c3d4e07ca3925fc`. Its preparation-only
authorization fields are historical; later explicit user instructions authorized
W01–W13 and distribution preparation. This supplement records current distribution
choices without altering earlier source records or inventing a release decision.

[s08-dossier.json](s08-dossier.json) is the machine-readable record. It retains
all 26 historical capability groups, 36 core acceptance cells, 58 paper criteria,
31 supplemental requirements and the additional 30 D05 safety cells. Existing
capabilities are not silently waived, expanded or requalified. The dossier binds
the original core documents and maps by SHA-256 at the exact selected source.

## Distribution choices and contents

Standard delivery is clean CI-built binaries; the current local candidates are
supplemental engineering evidence. Conda carriers will use the QuanuX organization
on Anaconda. macOS `.pkg` and Linux `.sh` downloads will use Cloudflare storage and
the website in a later step. No channel upload or downloadable release is accepted
by this dossier. Optional reviewed source/SDK material remains a separate delivery.

Modules retain independent versions and may be installed, upgraded, swapped and
removed independently within their owners' contracts. Packaging does not become
an application selector. Existing user-authorized composition and Maestro's
authenticated docking-presence contract remain distinct from real process use.

| Delivery | Exact native version | Runtime authority |
| --- | --- | --- |
| SSIAG | `0.1.0-dev` | SSIAG package installer and retirement fence |
| STAV append authority | `0.2.1` | STAV user package installer and retirement fence |
| Accordare STAV producer | `0.1.0-dev` | Accordare package installer, pending-work checks and retirement fence |
| qxctl | `0.1.0-dev` | Explicit executable/client and Linux host binding |
| SSH adapter | `0.1.0-dev` | Exact endpoint/profile and invocation owner |
| stdio adapter | `0.1.0-dev` | Exact target/configuration and admitted invocation owner |
| Transport profile administrator | `0.1.0-dev` | Protected host provisioning; no Conda privilege elevation |

Each Go carrier contains exactly its binary, artifact identity, AGPL license and
carrier manifest. Runtime files and retained rollback/controller bytes use
independent inodes outside Conda prefixes and caches. Runtime Python, lifecycle
hooks, automatic activation and host provisioning are absent. Native SDK units
retain their complete receipt-owned exports; this supplement does not split
sealed receipts or claim all native/C++ packages have qualified live removal.

See [delivery instructions](../docs/DELIVERY.md), [recovery](../docs/RECOVERY.md)
and [source/payload review](../docs/SOURCE-AND-PAYLOAD.md). User profiles, hardware
identity, credentials, journals and workflow state must be generated on each
user's own system, never copied from a publisher build environment.

## Capability and platform status

| Scope | Current evidence | Final support status |
| --- | --- | --- |
| macOS 15 ARM64 | Completed S07 native and Conda CI steps passed; E1 fixtures | Fresh-host and actual-manager acceptance incomplete |
| Ubuntu 24.04 AMD64 | S07 native CI failed; Conda step skipped | Fresh-host and actual-manager acceptance incomplete |
| Ubuntu 24.04 ARM64 | S07 native CI failed; Conda step skipped | Fresh-host and actual-manager acceptance incomplete |
| Ubuntu 26.04 AMD64 | S07 native CI failed; Conda step skipped | Fresh-host and actual-manager acceptance incomplete |
| Intel macOS supplemental | S06 package journeys; S07 real Conda and native owner/child fixtures | E1 only; does not substitute for the four core profiles |
| Other retained capability groups | Exact historical core source inventory retained | Not requalified by this packaging increment |

No profile is marked release-supported. Missing manager/host observations are
incomplete, and manager accessibility is not lifecycle acceptance. Cloudflare's
separate admitted vendor closure and provider-specific/physical hardware limits
remain in their existing source contracts; a generic architecture or source build
does not accept those operations.

The [hosted status snapshot](../evidence/s07-hosted-status-20261116.json) was
observed on November 16, 2026 at distribution head `8d9474e89b4974ecbf139ca7e95c60772e7127de`.
It binds exact completed jobs and retained failure evidence. Linux fixtures
used an untrusted temporary ancestor; the core ownership guard correctly
refused it. The correction supplies a private fixture directory through
`TMPDIR`. No result from a corrected CI head is claimed, and the Linux Conda
skips are not passes. The successful macOS job does not establish installed
manager, final-download or independent acceptance.

## Owners, trust and acceptance

Role assignments are referenced from the exact core `owners.json`; no person is
newly assigned or notified. Existing release/rollback ownership remains visible
through that source. Payload, signing-custody, platform, independent acceptance
and backup coverage that remains unassigned is still a release input.

Archive hashes establish bytes, not publisher authority. Publisher signing
identity, independently obtained trust policy, applicable macOS signing/notary
requirements, final Linux installer trust, payload redistribution review and
real download verification remain open. User-confirmed Anaconda organization
upload rights are not a signed-package or final-retrieval result.

The D05 acceptance array links each applicable native test to its actual S07
case and oracle. Conda evidence is scoped to carrier effects, not process
shutdown. Safe refusals, held references, unknown effects and pending audit work
remain distinct from successful live removal. The original criteria are retained
in [d05-requirements.json](d05-requirements.json) with their source-document digest.

S08 attaches the rebuilt Conda candidate report and reviewed derived source
export by exact digest. Packaging rebuilds retain the same native versions and
verified executable bytes; they are not a second native release. The source
export records original blobs, redactions/exclusions and map rebindings; a
selected clean-source build does not claim every source root builds. Final D06
CI cohorts, D10 delivered-byte campaigns and W12 independent acceptance remain open.

The recorded S08 reconstruction produced 14 fresh Conda archives for seven
commands across two packaging builds. Every payload matches its prior verified
candidate; archive bytes themselves were not reproduced. Separately, the exact
derived source archive was rebuilt identically and all six non-qxctl Go commands
were compiled from it with a fresh build cache and private home. Those executable
bytes match the prior candidates. This selected source proof does not change the
origin of the Conda payload inputs, rebuild qxctl, qualify a whole native/SDK
cohort, or accept another physical platform.

## Validate or refresh

Use the exact clean bound core checkout. The validation command checks source
maps, owner identities, required coverage, evidence hashes and both candidate
reports. It returns a consistency result; it cannot grant release acceptance.

```sh
python3 -m unittest discover -s dossier -p test_validate.py -v
python3 dossier/validate.py --source /absolute/reviewed-core \
  --require-rebuild --require-source-export --require-hosted-status
```

After a reviewed source/evidence change, regenerate this supplement with the
new exact reports and rerun validation. Do not rewrite historical evidence as
if it tested a new candidate.

```sh
python3 dossier/refresh.py --source /absolute/reviewed-core \
  --rebuild-report evidence/s08-candidate-rebuild.json \
  --source-export-report evidence/s08-source-export.json \
  --hosted-status-report evidence/s07-hosted-status-20261116.json
```

The remaining safety gates are actual manager/privilege/fresh-host behavior,
precise native restart/delete crash boundaries, escaped process lifetimes,
mid-operation native response loss, genuine distinct-release selection/rollback,
unresolved audit recovery and unsupported raw/C++/shared-environment ownership.
No source/documentation consistency check closes those gates.
