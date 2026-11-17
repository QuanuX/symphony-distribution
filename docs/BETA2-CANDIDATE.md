# Beta2 maintenance candidate

The new candidate uses core commit
`bae2e817120467561ae051c1b08cf61be3436bac` and the unchanged client source
`572627e939250763756167a9dc05d8cb37ab4e30`. It must be rebuilt and qualified on
all four primary profiles before any new candidate result is reported as passed.
The published `0.2.0-beta.1` artifacts, publisher decision, signatures and retained
selectors remain historical evidence for their original bytes.

The core revision includes the three maintenance repairs: dependent replacement
ordering, completed scoped-close replay, and installed SSIAG/Accordare self-repair.
It also closes qxctl's Accordare module selection over the repaired source.
This work keeps the feature freeze in place.

The [source preparation record](../evidence/beta2-source-preparation.json)
binds the reviewed export and manifest digests to that source and verifies that
all three repair commits are ancestors. It records source preparation only;
primary build and qualification results must come from the new hosted runs.
The [dispatch record](../evidence/beta2-dispatches.json) links all four requested
primary runs; their recorded state is pending, not passed. The
[local validation record](../evidence/beta2-local-validation.json) covers 350
focused preparation and refusal checks.

## Review authority

`evidence/beta2-candidate.json` authorizes assembly and qualification of
`0.2.0-beta.2` as an unsigned review candidate. It does not authorize publication,
record legal acceptance, grant publisher trust, or change an operating system's
trust store. The assembly selects the exact committed authorization document and
binds its digest into the installers and result record.

Beta2 review installers use `SymphonyReview`, the separate default prefix
`~/symphony-beta2-review`, and the non-publishing review channel identifier. They
retain independently maintainable carriers and the explicit first-run retention
helper. Installation does not start services, configure credentials, enroll a
host, or select application modules.

The public-beta signing and publication tools remain bound to beta1. A review
candidate cannot be converted to a released beta by changing its version, result
state, or publication flag. A later publication step must select and authorize the
exact completed candidate and its signing scope separately.

## Candidate qualification sequence

1. Reproduce the independently selected source-export and manifest digests, then
   dispatch `d09-platform.yml` once for each primary profile with `fresh_user=true`.
   D09 performs two clean builds, SDK checks, notice/source closure, and retains
   native payloads plus evidence. The ordinary D06 workflow retains reports only;
   its artifact cannot substitute for native bytes.
2. Verify each completed D09 run and exact artifact metadata. Create new
   candidate-specific files under `evidence/native-selections/`; do not overwrite
   the beta1 selections. Dispatch `d12-native-rewrap.yml`,
   `d13-primary-client.yml`, and `d13-native-maintenance.yml` with the selected
   file and SHA256. These gates reuse the exact native bytes and preserve the
   original native/SDK provenance.
3. After package and client qualification succeeds, select their exact completed
   outputs in a new `evidence/beta-selections/` file. Dispatch
   `d14-beta-assembly.yml` with that selection, its SHA256, and
   `authorization=evidence/beta2-candidate.json`. Assembly includes the final 59
   carriers, the optional source/SDK package, revision upgrade/swap/rollback and
   removal, shell installer checks, and private first-run client preparation.
4. Select the completed macOS beta2 assembly and dispatch `d14-native-pkg.yml`.
   The actual native installer runs only in a disposable hosted runner's home.
   Retain each exact native maintenance, client, consumer and installer result
   beside the final candidate inventory.

Every handoff requires the exact run attempt, workflow commit and path, artifact
ID, size and digest, and the selected result digest. A queued run is pending;
failed, cancelled, expired, mismatched or incomplete evidence is not a passing
candidate. No workflow in this sequence uploads to Anaconda, Cloudflare or a
GitHub release.

## Qualification boundaries

D12 exercises baseline carriers on a separate disposable consumer runner.
D14's final shell qualification uses a new private home and prefix on its
assembly runner; its result explicitly does not claim a separate fresh machine.
Native macOS installation is a separate hosted run. Codex qualification covers
the actual selected client executable and the recorded engineering scenarios;
it does not imply unobserved provider login or live-model behavior.

Carrier revision upgrade and rollback keep native payloads unchanged. The native
maintenance campaign tests the owners' supported safety boundaries and
same-candidate recovery. Those results do not establish a distinct-native-version
upgrade or rollback from published beta1 to beta2. Unsupported operations must
continue to refuse without changing user state.

Unsigned macOS packages remain unsigned and unnotarized. A future self-signed
detached manifest would prove integrity only under its separately selected key
pin; it would not establish Apple Developer ID or notarization.
