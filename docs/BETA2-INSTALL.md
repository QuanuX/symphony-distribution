# Symphony 0.2.0-beta.2

Symphony Public Beta supplies clean CI-built native binaries and a Codex client,
with each module delivered as an independently maintainable Conda package.
Source and its build instructions are available separately. The SDK headers,
libraries and CMake exports remain with their respective module owners.

The supported profiles are macOS 15 on Apple Silicon, Ubuntu 24.04 on AMD64,
Ubuntu 24.04 on ARM64, and Ubuntu 26.04 on AMD64. Choose the exact operating-system
profile: the two AMD64 Linux cohorts share a Conda subdirectory but are distinct
qualified builds. Use the explicit package lists below to preserve that choice.

## Verify a download

Release files are under
`https://downloads.quanux.org/symphony/0.2.0-beta.2/`.
Download `beta-manifest.json`, `beta-manifest.sig`, `beta-cert.pem` and
`release-index.json` into a new directory. The release page lists each platform's
installer and corresponding source. Preserve their relative paths when saving.

Use Python 3.11+ and OpenSSL with the verifier from the immutable source revision:

`https://raw.githubusercontent.com/QuanuX/symphony-distribution/bd70dc3c3e6204a85a65f2a4de21b29a9dad9cf1/channel/verify_beta.py`

From the download directory, verify the index and your chosen installer:

```sh
python3 verify_beta.py --release 0.2.0-beta.2 --artifact release-index.json
python3 verify_beta.py --release 0.2.0-beta.2 --artifact "$SELECTED_INSTALLER_PATH"
```

`SELECTED_INSTALLER_PATH` is the relative `installers/<profile>/<filename>`
listed in the verified index. The verifier checks only the selected downloads;
you do not need to fetch other platforms. It embeds these publisher pins:

- Certificate SHA256: `03e9535b87e040410cf7130f2491d4e053298f3171071faee26b076d43e3da91`
- Public-key SHA256: `34621e652aef5649ba2eea9310a93a108cfc65466abc2c164d8fab0079715010`

This beta uses a detached publisher signature. The Mac PKG has no Apple
Developer ID signature or notarization; macOS may require explicit user
approval. No system trust changes are part of this distribution. The verified
shell installer is also available for the Mac profile.

## Install the package set

Run the verified `.sh` installer as your normal user, selecting a new private
prefix. For example, set `SYMPHONY_PREFIX` to a new absolute directory and run:

```sh
bash "$SELECTED_INSTALLER_PATH" -b -p "$SYMPHONY_PREFIX"
```

The Mac `.pkg` is the native Apple installer format and selects the current
user's home installation domain. The release gate exercises native installation/removal
in a disposable hosted Mac user account; interactive GUI and Gatekeeper
acceptance are separate from the detached signature. The release dossier records
the actual result for the exact downloadable bytes.

For an existing Conda installation, download and verify
`setup/<profile>/default-explicit.txt`, then use:

```sh
conda create --prefix "$SYMPHONY_PREFIX" --file "$VERIFIED_PROFILE_EXPLICIT_FILE"
```

Conda 26.10.0 was qualified. Each explicit URL names the exact QuanuX/beta archive
and its SHA256; this avoids choosing another platform through a solver. The
standalone installer already contains the qualified package manager. Neither
route activates services, creates credentials, chooses application modules or
uses the publisher's local state.

## Make the supplied binaries ready

Python 3.11+ is required for the setup scripts; a compiler, source checkout or SDK
is not required to run the supplied binaries. Choose a new absolute private
custody directory outside the installed package prefix. Read the platform's
`retention_index_sha256` from the verified `release-index.json` and run:

```sh
python3 "$SYMPHONY_PREFIX/share/symphony/installer/symphony-retain.py" \
  --prefix "$SYMPHONY_PREFIX" --index-sha256 "$VERIFIED_RETENTION_INDEX_SHA256" \
  --output "$NEW_PRIVATE_CUSTODY" --owners
```

For a direct Conda installation, download and verify the same platform's
`setup/<profile>/symphony-retain.py` and `BOOTSTRAP-INDEX.json`, then run:

```sh
python3 "$VERIFIED_SETUP_SCRIPT" --prefix "$SYMPHONY_PREFIX" \
  --index "$VERIFIED_SETUP_INDEX" --index-sha256 "$VERIFIED_RETENTION_INDEX_SHA256" \
  --output "$NEW_PRIVATE_CUSTODY" --owners
```

The default retains qxctl and the client; `--owners` also retains the three Go
controllers. `--all` retains the complete native candidate and SDK contents.
Every selected file is checked before use, and the new directory receives a
`CUSTODY.json` record. These independent copies survive package removal. They
are candidate files; native installation and activation remain explicit.

Select a workspace that belongs to the installing user and create a new private profile directory with mode 0700. The existing client scripts create new profiles with mode 0600
and refuse to overwrite an existing selection:

```sh
QXCTL="$NEW_PRIVATE_CUSTODY/candidate/go/qxctl/bin/qxctl"
CLIENT="$NEW_PRIVATE_CUSTODY/client"
"$QXCTL" version --json
"$QXCTL" commands manifest --json
python3 "$CLIENT/scripts/configure_connection.py" --qxctl "$QXCTL" \
  --working-directory "$USER_WORKSPACE" \
  --output "$NEW_PRIVATE_PROFILE_DIRECTORY/connection.json"
python3 "$CLIENT/scripts/configure_clients.py" --client codex \
  --binary "$CLIENT/bin/symphony-mcp" \
  --config "$NEW_PRIVATE_PROFILE_DIRECTORY/connection.json" \
  --tool-catalog "$CLIENT/catalog/tools.json" \
  --output "$NEW_PRIVATE_PROFILE_DIRECTORY/codex-fragment.toml"
```

Review the generated fragment and add it to your intended Codex configuration.
Existing host configuration is preserved. Codex is the primary qualified client;
Claude, Antigravity and generic adapters remain available through the existing
configuration generator. Profiles expose reads by default. Credentials, grants,
enrollment and live service start require the respective owner's explicit flow.

See the accompanying `RETENTION.md` for the existing fresh, stopped native Go
owner installation commands and their distinct private roots.

## Maintain independent modules

Each `setup/<profile>/units/<package-name>.txt` contains one exact package.
Download it, verify it, and install or change that carrier explicitly:

```sh
conda install --prefix "$SYMPHONY_PREFIX" --file "$VERIFIED_UNIT_EXPLICIT_FILE"
conda remove --prefix "$SYMPHONY_PREFIX" --offline --solver classic "$SELECTED_PACKAGE_NAME"
```

For standalone installations, use `"$SYMPHONY_PREFIX/_conda"` in place of `conda`.
To swap the SSH and stdio carrier choices, install the selected alternative's
verified file and remove the unwanted named carrier. Native routing and
application selection remain under existing owners. Changing packages does not
implicitly change retained binaries, running processes or active profiles.

Before a future upgrade, retain the accepted explicit list and archives. Apply
the separately verified new profile or unit list; to roll back, apply the
retained prior exact list. This beta qualifies packaging revision 0→1→0 with
identical native bytes, independent module changes, swap, removal and retained
same-candidate recovery. An in-place native upgrade or rollback between beta.1 and beta.2 is not qualified.
Use a fresh prefix and separate retention directory for beta.2. Native
version transitions and live retirement outside the qualified owner contracts
remain refused. Never force altered receipts or blindly retry an unknown native
mutation outcome.

Optional corresponding source has its own verified
`setup/<profile>/optional-source-explicit.txt`. It is also directly downloadable
under `source/<profile>/`. The source archive includes the exact native/Go source,
external dependency source and notices, original client source with explicit
catalog derivations, and the packaging toolkit. No user profiles, credentials,
host inventory or publisher build directory are included.

## Maintenance changes in beta.2

This release includes dependent-replacement ordering, completed scoped-close replay,
and installed SSIAG/Accordare self-repair fixes. Its native build source is
`bae2e817120467561ae051c1b08cf61be3436bac`. The Symphony tag
`v0.2.0-beta.2` captures main at `8a6889597eef3d2713f48bf6962456f989188e18`;
only README text differs from the native build revision. Every package retains
its actual source identity. Existing ownership, active-use and recovery checks
continue to apply.
