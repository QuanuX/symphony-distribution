# D08 unsigned installer review

This directory assembles reviewed independent package carriers into standalone
installers. It does not install a Symphony runtime, select an application module,
start a service, enroll an identity, grant authority, write credentials, or
publish an artifact. Production signatures, notarization and acceptance remain
separate required gates.

`cohort.py` admits the reviewed D06 payload and the independently reproduced
original-source qxctl identity. The original D06 payload remains unchanged.
`carriers.py` preserves each complete native receipt unit, each separate Go
delivery unit and the external runtime inventory as independent packages. SDK
exports remain with their native owners. Optional client and public-source
units must have their own exact provenance; they are not silently added from a
publisher checkout.

`construct.py` accepts only `carriers.audit_cohort()` output in the
`archives_audited` state. It copies the already audited channel into a new
private workspace and indexes precisely that archive set. Constructor's solved
set must match the selected package identities, subdirectories and hashes.
After assembly, the inspector reads the final nested `.conda` archives and
checks that every byte still matches the CLI carrier cohort. It does not run
the resulting `.pkg` or `.sh` installer. Removing a carrier through Conda remains
separate from removing an installed runtime through its existing native owner.

The standard suite is a one-time selection. There is no installed suite
metapackage, so removing an independently selected carrier does not create a
dependency rule that restores it later. Constructors do not configure shell
startup, activate Conda, register environments, create shortcuts, or run custom
pre/post-install hooks. Package extraction uses the pinned bootstrap's offline
link operation. Error reporting and external Conda plugins remain disabled by
default. The pinned standalone's embedded constructor extraction command requires
a command-local plugin override: assembly first verifies that all Python search
paths and distribution metadata remain inside the frozen bundle and a caller
plugin fixture is ignored. Only the four shell extraction calls and one native
PKG preparation call receive that override, with user Python paths disabled and
Conda configuration restricted to `/dev/null`. Install/removal calls retain plugin
denial. Original signed wrappers are immutable; this repair produces new wrappers.
Existing or dangling-link destinations are refused, including the shell
installer's force/update options. The installer does not change ownership of
an existing user's `.conda` directory or `.condarc` file. Explicit maintenance
of an existing installation remains with the separate owner-controlled flow.

The selected constructor is 3.17.3 with Conda 26.10.0 and Python 3.12.16.
`tool-lock.json` binds its reviewed source/resources and the exact public
conda-standalone 26.9.4.post1 archives for each supported target. The bootstrap
executable is compared to its pinned package; its license notices accompany the
wrapper. No publisher environment is copied into an end-user installer.

`constructor_runner.py` makes bounded, source-checked adaptations before
wrapping: neutral tar ownership/timestamps, Apple's recommended package
ownership, public build metadata instead of a host inventory, and explicit
inactive bootstrap environment. A single observed bootstrap version is reused
only for the same unchanged binary. Generated history uses neutral relative
arguments. These adaptations never rewrite a supplied Conda archive or native
receipt. The final inspector also scans metadata for the selected private
publisher markers and build locations.

On macOS, `pkg_finalize.py` also removes recognized, metadata-only AppleDouble
records from generated wrapper containers and neutralizes CPIO owner/time
fields. A record with an orphan name, unknown format, real resource-fork data,
or actual hard-link alias is refused. Every real file byte and mode is compared
before and after this step. Apple's `mkbom` recreates the BOM from the exact
filtered original listing; the final XAR uses distribution metadata and is
independently inspected. Original unsigned wrappers are retained privately.
This finalization happens before any outer signing; signed input is refused.

An unsigned local review is prepared with:

```sh
PUBLISHER_PYTHON installer_assembly/construct.py \
  --cohort AUDITED_CARRIER_ROOT --output NEW_OUTPUT \
  --python PUBLISHER_PYTHON --standalone PINNED_STANDALONE_EXECUTABLE \
  --standalone-archive PINNED_STANDALONE_PACKAGE \
  --format pkg --format sh --privacy-policy PRIVATE_REVIEW_POLICY \
  --supplemental
```

`--supplemental` applies only to the local macOS Intel fixture profile. It does
not turn that hardware into a supported macOS ARM64 or fresh-host acceptance
result. Linux `.sh` assembly requires a matching native Linux payload, host
release and locked bootstrap; cross-labelled wrappers are refused.

The `D08 unsigned installer assembly` workflow runs only affected preparation
contracts on a branch push. Its full native assembly job is manual and requires
an explicitly selected artifact from this repository, the expected cohort
digest and the matching profile. It downloads no unselected product modules.
The job retains unsigned review wrappers and bounded reports; it does not
upload to Anaconda or Cloudflare.

The resulting `result.json` distinguishes wrapping from installation, signature
verification, notarization, fresh-host qualification and public release.
`INCOMPLETE.json` preserves a failed attempt. A later signed candidate must be a
new, separately reviewed construction: signing covered native bytes after they
were sealed, or attaching a production flag to this unsigned record, is not
supported. Existing signed native-candidate verification is not weakened.
