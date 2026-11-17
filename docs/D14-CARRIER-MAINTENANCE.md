# Packaging revision maintenance

The initial beta contains one native release of each component. Packaging
revision 1 adds an explicit maintenance contract to each opaque carrier:
Conda owns its carrier files, native owners retain runtime selection and effects,
rollback selects a retained exact archive, and automatic activation and live
native removal are unsupported. Every native payload archive, receipt, version,
dependency relationship and SDK export remains identical to revision 0.

`qualification/d14_carrier_journeys.py` creates and independently audits this
metadata revision with the existing Conda archive writer. Its transaction
campaign installs the entire selected cohort, upgrades and rolls back each
component independently, swaps the SSH and stdio **carriers**, reverses that
swap, restores the original carrier selection, and removes each package by
name. The transport swap does not change Maestro or start either adapter.

The campaign uses the existing bounded Conda transaction engine in a private
module instance. Its original Go-carrier parser remains unchanged. A closed
adapter admits only the exact hashes, full file inventories and metadata already
verified by the current inert-carrier auditor. The engine still validates the
complete solver LINK/UNLINK plan and prepared actions, executes that same
transaction object once, prohibits hooks, prefix rewrites and forced dependency
removal, checks unrelated files, and preserves uncertain outcomes without retry.

Original archives, user and outside sentinels, helper bytes and pinned solver
identity are checked throughout. Normal cache cleanup is limited to the
campaign's private cache. No native executable, native installer, service,
provider or runtime selector is invoked.

The manual `d14-carrier-journeys.yml` workflow admits an exact committed beta
artifact selection, retrieves only successful pinned outputs, revalidates the
original native/source/SDK evidence, and runs on the matching primary platform.
Its completed artifact contains revision-one carriers and portable observations.
Local opaque-package exercises record their executing architecture and do not
substitute for that matching-host result.

This proves packaging-revision upgrade, swap and rollback when the campaign
actually passes. It does not establish compatibility between two native
releases. Such a transition remains unsupported until a real second release is
available and independently qualified. Live native removal and managed
shared-root effects retain their existing owner refusals and preservation rules;
an inert carrier transaction does not grant those authorities.
