# D09 distribution status

The feature freeze remains in force. Symphony core main and client main are
unchanged; the distribution work is on `codex/d09-review-channel-gates`, PR #6.
No source PR was merged, runtime service activated, or Cloudflare object uploaded.

## Completed review delivery

The retained signed D08 review set has been staged as 60 immutable Conda packages
under QuanuX, label `d09-review-0b5ad60ceaaf`: 59 default core/client carriers and
one optional corresponding-source carrier. The source package was uploaded and
freshly retrieved before the first binary carrier; its exact URL and extraction
directions accompany every release/file description. No `main` or `beta` label
was selected, and no existing build was overwritten.

`evidence/d09-anaconda-stage-plan.json` binds the exact package URLs, sizes,
SHA-256 values, source revisions, signed manifest, review certificate and upload
helper. `d09-anaconda-staging.json` records server metadata equality for all 60.
`d09-anaconda-fresh-retrieval.json` records all 60 fresh downloads without account
credentials, exact byte equality and sanitized redirect observations.
`d09-public-conda-install.json` additionally records an actual Conda CLI journey:
all 60 public HTTPS URLs fetched into an empty cache, 180 linked files matched
the signed inputs, and named offline removal preserved user/outside sentinels.
No account credentials or native owner commands were supplied.
The review label is publicly reachable; it is not an access-control boundary.

This remains the supplemental local Intel macOS review cohort. It does not claim
primary macOS ARM/Linux qualification or public beta approval. Conda packages
contain inert payloads, and removing a carrier is separate from native removal.
The detached self-signature remains review integrity only; Apple Developer ID,
notarization and an independently distributed trust policy are not established.
The later TLS guard also rejects `None`, zero and empty verification settings;
the original completed upload plan retains its exact original helper binding.

## Parallel qualification

| Area | Current evidence | Remaining gate |
| --- | --- | --- |
| Primary platforms and fresh users | Reviewed source independently reproduced; four hosted profile workflows dispatched with separate disposable-user jobs | Hosted outcomes, matching primary clients, Apple PKG installation and full 36-cell independent acceptance |
| Native maintenance | All 51 delivered-owner cycles passed: 612 commands, 1,250 retained entries preserved | Live-use retirement, native installation and managed shared-root authority remain separate |
| Upgrade and rollback | Distinct-release admission rejects rebuilds/relabels of one candidate | Second independently qualified native versions and real transition/rollback compatibility |
| Final integration | Exact core/client/distribution PR graph and source-bound acceptance packet | Authorized integration, fresh required-check review, rebuild/rebinding when source identity changes |
| Signing | Selected self-signed certificate and all 76 original artifact signatures verified | Recognized publisher identity, notarization and independent key/trust policy |
| Legal and independent acceptance | 131 selected notices plus 115-component bootstrap inventory and seven review-role checklists | Qualified redistribution review, bootstrap source/build/offer closure, named independent/backup reviewers and their actual decisions |

The user has not selected independent reviewers or physical fresh hosts. Disposable
hosted machines supply automated evidence; they do not impersonate independent
human review or physical hardware acceptance. See `D09-ACCEPTANCE.md`,
`D09-NATIVE-MAINTENANCE.md`, and `qualification/d09_platform.md` for the concrete
review inputs and execution boundaries.

## CI handling and source protection

The prior client PR #8 cancellation had no runner and no executed steps. Only
that cancelled job was retried. The Linux D06 SDK failure was caused by resolving
`clang++` to `clang`; the audit now preserves the selected C++ driver name.
All 90 focused regression tests passed; workflow lint and the public-evidence privacy scan passed. New D09 checks and the four primary profile
workflows were started without waiting for results.

The source privacy policy was configured as an encrypted repository secret;
its contents never enter public source, artifacts or workflow inputs. Both
reviewed source pins were reproduced locally before dispatch. Published D09
source/evidence files passed the existing private-policy scan.
