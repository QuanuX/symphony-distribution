# Selected Mac shell-installer gate

The user selected the retained local Mac build for the next bounded gate. The
route in `qualification/d10_mac.py` uses that exact supplemental Intel macOS
cohort. It leaves the existing primary-platform and independent acceptance gates
unchanged.

The helper requires an explicit selected-Mac option, the previously selected D09
staging-plan digest, and the pinned review-certificate hash. It verifies the
76-artifact detached-signature set, exact source bindings, all 60 staged Conda
carriers, the signed default59 cohort and the signed shell-wrapper audit. The
optional corresponding-source carrier is verified but is not added to the
59-package shell installer. The shell wrapper and its embedded bootstrap retain
their original bytes.

The actual installer runs as the current unprivileged user, using a newly created
private HOME, cache, configuration and absent prefix. Its environment excludes
account credentials, inherited shell configuration and loader overrides. No
Apple system installer, native owner, Maestro selection, service, provider,
credential enrollment or trust-store command is invoked.

The campaign verifies all 177 installed carrier files and exact Conda package
identities, then checks that existing-prefix, forced replacement, upgrade and
dangling-link requests refuse without changing installed or caller bytes. It
uses the exact embedded maintenance bootstrap to remove only the 59 named inert
carriers offline. Private-home sentinels, unrelated prefix state, an outside
sentinel, bootstrap bytes and wrapper notices must survive. Finally, signed
inputs, selected records and executing helper hashes are checked again.

Raw logs and disposable state remain in the new private output. The portable
result records only source/artifact/helper hashes, observed OS/architecture,
command-log hashes, outcomes and explicit gate boundaries. Failure or interruption
produces incomplete evidence; the helper does not retry an uncertain install.

A passing result establishes this selected wrapper's local inert-carrier
installation, refusal and removal behavior. It does not establish native payload
installation, true two-release upgrade/rollback, primary ARM/Linux qualification,
a fresh physical host, independent reviewer approval, legal approval or beta
publication. The separate human review record owns legal-role assignments and
decisions. The detached review signature does not become Apple Developer ID or
notarization.

The retained `.pkg` remains inspected but unexecuted. Its privileged native
installation path requires an explicit isolated destination and user-state
preservation contract before execution; the shell gate never invokes it.

## Preserved startup defect and separate repair

The first actual test refused before installing any package: the original
wrapper's global plugin setting disabled the pinned standalone bootstrap's
required `constructor` command. That failed attempt and the original signed
76-artifact set remain unchanged. No passing gate is inferred from the failed
startup.

`qualification/d10_mac_overlay.py` supports a separate local repair overlay. It
reconstructs an audit layout from the existing signed carriers and hash-identical
recipe metadata, then assembles new wrappers around those same 59 archives. The
new wrapper audit, original-delivery binding and strictly scanned committed
wrapper-toolkit source receive a separate detached review signature. The original
carrier source, Anaconda staging plan, public package bytes and legal-review
records are not replaced. The new source is supplementary wrapper-build source;
it is not a claim that the carrier cohort was rebuilt.

The Mac gate can admit this overlay only with its separately selected manifest
hash and the original certificate pin. Both original delivery and overlay are
verified, and their carrier rows must agree exactly. It copies the selected signed
shell bytes through a bounded no-follow read to a read-only private snapshot,
rechecks its size/hash, audits it, and executes only that snapshot. Original
inputs, overlay source, helper closure and execution snapshot are verified again
before success. Reassembly and actual execution remain distinct evidence states.

## Reproduce the selected check

Select the retained original delivery, the repaired wrapper supplement and the
existing exact publisher interpreter/OpenSSL. The output must be a new private
directory. Obtain the certificate pin through the separately selected review
trust process; this command does not establish publisher trust.

```sh
"$PUBLISHER_PYTHON" -B qualification/d10_mac.py \
  --plan evidence/d09-anaconda-stage-plan.json \
  --stage-record evidence/d09-anaconda-staging.json \
  --plan-sha256 30cbed74ccfa9e42eeedb664356cd37ecb01a5629480010d628ab468a42bae15 \
  --delivery "$ORIGINAL_REVIEW_DELIVERY" \
  --wrapper-overlay "$REPAIRED_WRAPPER_SUPPLEMENT" \
  --wrapper-manifest-sha256 97152020349962e044f4e89971da3cecd7deba89babee1be001b3c7aeda9c8b7 \
  --certificate-sha256 "$SELECTED_REVIEW_CERTIFICATE_SHA256" \
  --openssl "$EXACT_OPENSSL" \
  --output "$NEW_PRIVATE_OUTPUT" \
  --allow-selected-mac
```

Installation uses the shipped solver-default path. Only the separately named
offline removal requests the pinned bootstrap's builtin classic solver.
