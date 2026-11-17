# Retaining the supplied binaries

The standard installer links immutable carriers. It does not start Symphony,
choose modules, register client profiles or install native services. Python 3.11
or newer is required for this explicit setup step; a compiler, source checkout
and SDK are not required to run the delivered binaries.

After verifying the publisher's detached release manifest, select its exact
platform retention-index SHA256. Run the installed helper as your normal user:

```sh
python3 "$SYMPHONY_PREFIX/share/symphony/installer/symphony-retain.py" \
  --prefix "$SYMPHONY_PREFIX" --index-sha256 "$PUBLISHED_RETENTION_INDEX_SHA256" \
  --output "$NEW_PRIVATE_CUSTODY" --owners
```

Use a new absolute destination outside the Conda prefix and caches. The command
refuses existing paths and aliases. The trusted digest must come from the
verified release manifest, not from hashing an untrusted local index. Without
`--owners`, it retains qxctl and the client. `--owners` also retains the three
existing Go controllers; `--all` retains all candidate files, native receipts
and their SDK exports. Those are verified candidate copies, not a new assertion
that native owners installed or selected them. Retention never invokes an owner.

The helper checks every selected carrier and archive member before writing a
new private directory. It preserves file modes, verifies native receipt seals,
allows only the exact selected curl aliases, and writes `CUSTODY.json` after
checking the original and retained bytes. The retained copies survive carrier
upgrade or removal. A partial failed output is evidence: preserve and inspect
it, then select a separate new destination; do not overwrite it or retry native
effects blindly. Automatic custody deletion is intentionally unavailable.

CLI-only Conda installations use the identical `symphony-retain.py` and
`BOOTSTRAP-INDEX.json` downloads named by the verified release manifest. They do
not require the standalone installer's extra files. Pass the downloaded index
explicitly, retaining the same independently trusted index digest:

```sh
python3 "$VERIFIED_SETUP/symphony-retain.py" \
  --prefix "$SYMPHONY_PREFIX" --index "$VERIFIED_SETUP/BOOTSTRAP-INDEX.json" \
  --index-sha256 "$PUBLISHED_RETENTION_INDEX_SHA256" \
  --output "$NEW_PRIVATE_CUSTODY" --owners
```

Both routes verify the same script and index identities and retain the same
candidate bytes. The setup files do not modify the Conda environment.

Select the retained executables explicitly:

```sh
QXCTL="$NEW_PRIVATE_CUSTODY/candidate/go/qxctl/bin/qxctl"
CLIENT="$NEW_PRIVATE_CUSTODY/client"
"$QXCTL" version --json
"$QXCTL" commands manifest --json
python3 "$CLIENT/scripts/configure_connection.py" \
  --qxctl "$QXCTL" --working-directory "$USER_WORKSPACE" \
  --output "$NEW_PRIVATE_PROFILE_DIRECTORY/connection.json"
python3 "$CLIENT/scripts/configure_clients.py" --client codex \
  --binary "$CLIENT/bin/symphony-mcp" \
  --config "$NEW_PRIVATE_PROFILE_DIRECTORY/connection.json" \
  --tool-catalog "$CLIENT/catalog/tools.json" \
  --output "$NEW_PRIVATE_PROFILE_DIRECTORY/codex-fragment.toml"
```

The workspace and private profile directory must already exist. Choose an empty
profile filename; both scripts refuse overwriting it. The final command creates
a configuration fragment for the user to review and add to their intended Codex
configuration. It does not modify the host configuration. The same generator
maintains the `claude`, `antigravity` and `generic` adapters; actual qualification
of those clients is separate. Profiles expose reads by default. Explicit
non-read delegation remains subject to each native owner's authority.

Retained native controllers expose existing fresh stopped install operations:

```sh
"$NEW_PRIVATE_CUSTODY/candidate/go/secure-identity-access-governance/bin/symphony-ssiag" \
  package install --prefix "$NEW_SSIAG_ROOT" --version 0.1.0-dev
"$NEW_PRIVATE_CUSTODY/candidate/go/stav-append-authority/bin/symphony-stav-append-authority" \
  install --prefix "$NEW_STAV_ROOT" --version 0.2.1 --scope user
"$NEW_PRIVATE_CUSTODY/candidate/go/accordare-stav-producer/bin/symphony-accordare-stav-producer" \
  install --prefix "$NEW_ACCORDARE_ROOT" --version 0.1.0-dev
```

These are separate explicit native mutations on the matching platform, using
distinct new user-owned installation roots. They do not enroll identities,
grant access, dock modules or start supervisors. Existing receipt, retirement
and shared-root checks apply unchanged. This helper supplies no generic CMake
native installer and no live removal or different-native-release upgrade path.
The older four-file Go-carrier `go_delivery.py` flow is a distinct protocol and
must not be pointed at these three-file beta carriers.
