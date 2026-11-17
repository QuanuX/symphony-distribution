# Native Apple beta installer and trust scope

The native installer gate is implemented in `qualification/d14_pkg.py` and
`.github/workflows/d14-native-pkg.yml`. It consumes a separately selected,
completed macOS beta assembly through the authenticated artifact transport.
The selected result, carrier inventory, wrapper audit and PKG SHA256 remain
separate exact bindings; a later assembly must supply its own selection.

The gate runs only on a fresh GitHub-hosted macOS 15 Apple Silicon VM. It checks
all carrier archives, the complete nested PKG payload and scripts, and the
current-user-home destination before execution. Apple installer requires root
for these existing package components. This gate therefore uses the disposable
VM root account's home domain and refuses any pre-existing destination. It does
not install on the publisher's Mac or use `/Applications` as its target.

After native installation it compares each carrier's bytes and modes, all Conda
package identities and the pinned bootstrap. It removes the explicitly named
carriers offline and checks user/outside sentinels, account configuration and
installer support files. Apple's installer receipts are retained on the
throwaway VM; the VM's teardown is their cleanup boundary. This is an actual
native PKG route check once the hosted job passes. It is not a GUI interaction,
service activation, distinct-release upgrade/rollback or physical-host claim.
The independent 51-owner maintenance campaign remains separate.

At preparation time, the selected retained Apple PKG passed a read-only native
archive/layout preflight. The new hosted installer campaign is pending its final
beta artifact selection and execution. The gate must not borrow success from a
prior review wrapper with different bytes.

## Self-signed beta integrity

The publisher has authorized beta release and self-signed integrity.
`installer_assembly/beta_signing.py` creates a dedicated **Symphony Public Beta**
identity, leaving the historical review-only key and verifier unchanged. The
detached manifest must be generated from the final selected
artifacts, verified immediately, and distributed with the public certificate and
explicitly published certificate and public-key SHA256 pins. Private signing
credentials remain outside the repository and distribution. Publisher
authorization is the separate content-bound decision record. The beta manifest
binds that exact record, release `0.2.0-beta.1`, the release index and every
selected artifact, including qualification and corresponding-source metadata.
The release index must contain `"release": "0.2.0-beta.1"`; the index and decision
are themselves included in the signed file list.

The local nonsecret tool inspection on 2026-11-16 found no valid Apple signing
identity. Apple `productsign`, `notarytool`, `stapler`, `pkgutil` and `installer`
tools are available. Earlier isolated native-signing probes rejected the review
certificate as an installer identity. The beta PKG therefore remains unsigned
by Apple, while its exact bytes can be covered by the detached signature.

Apple identifies **Developer ID Installer** as the certificate for installer
packages. Its notarization workflow requires Developer ID signing. A detached
self-signed manifest does not grant either identity or a notarization ticket.
See [Apple certificate guidance](https://developer.apple.com/help/account/certificates/create-developer-id-certificates)
and [Apple notarization guidance](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution).

Release instructions should say that the beta uses a self-signed integrity
manifest and is not notarized by Apple. Users verify the selected certificate
pin and manifest before opening the installer, then make any item-specific
approval decision macOS presents. The native test does not disable system trust
checks, clear quarantine attributes, or pass `-allowUntrusted`. macOS's normal
unknown-publisher behavior remains visible; see
[Apple's explanation](https://support.apple.com/en-us/102445).
