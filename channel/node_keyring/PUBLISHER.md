# Ubuntu node keyring supplement for beta 2.1

The handoff contains twelve files. Its SHA-256 is `eed4337e49ec8c7f770a9bd03d0a877a90b17dfb797a7f4d2faad33c2b936784`. The signed supplementary inventory path is `supplements/linux-node-keyring/index.json`, SHA-256 `deb6dd8ac42ef446ec4962d3cc93c06ec796401181a7128f48e12c7e61158bef`. Both package architectures require Ubuntu 26.04. Conda owns the delivery under the prefix. The host package manager owns the runtime and both SDKs. The sealed bundle contains no publication tooling or private privacy policy. Its source archive supplies the build and installed qualification scripts.

Use `build.py`, `audit_handoff.py`, `prepare_release.py`, and `publish_optional.py` from the same tool directory. Set `dist` to the qualified distribution checkout, `primary` to its unsigned four-profile beta 2.1 bundle, and `base_sha` to the SHA-256 returned after its ordinary admission. The selected publisher Python environment must support the existing distribution helpers. The hosted runner needs `ar` and `zstd` available to the audit, together with its existing private `symphony.source-privacy-policy.v1` policy.

```sh
python audit_handoff.py unpack --distribution "$dist" --privacy-policy "$policy" \
  --archive "$asset" --sha256 eed4337e49ec8c7f770a9bd03d0a877a90b17dfb797a7f4d2faad33c2b936784 \
  --directory "$new_supplement"
python prepare_release.py attach --distribution "$dist" --primary "$primary" \
  --primary-sha256 "$base_sha" --supplement "$new_supplement" \
  --supplement-sha256 deb6dd8ac42ef446ec4962d3cc93c06ec796401181a7128f48e12c7e61158bef \
  --output "$combined"
```

Choose a fresh `combined` directory outside the input bundles. The attachment checks the primary source binding and rehashes the inventory, retains all 240 original package rows and four profiles, and adds the 12 independently verified downloads. For the ordinary `installer_assembly/beta_signing.py sign`, select `combined/release-index.json` plus every file listed in its `artifacts`, with `publisher-decision.json` as the decision. Use the existing beta 2.1 publisher identity and independently pinned certificate. The normal `channel/beta_downloads.py` plan includes all 12 new downloads. Publish the downloads before the optional Conda packages so their exact source and AGPL text can be retrieved anonymously. `channel/beta_publish.py` serves the primary 240-package set.

```sh
python publish_optional.py prepare --distribution "$dist" --artifacts-root "$combined" \
  --signature-root "$signatures" --openssl "$openssl" --output "$plan"
python publish_optional.py publish --distribution "$dist" --artifacts-root "$combined" \
  --signature-root "$signatures" --openssl "$openssl" --plan "$plan" --output "$new_attempt" \
  --allow-public-beta-publication
```

The optional publisher requires the exact separately prepared plan and the release's pinned certificate. It retrieves source and license first, preserves immutable builds, journals any writes, and fetches each of the two package builds through `beta` and the release-specific label without account credentials. If an attempt stops, reconcile its journal against remote state before a new attempt. Retain `publication.json` and both primary-channel and download-publisher receipts. The public `supplements/linux-node-keyring/README.md` describes independent pinned verification, install, enrollment, SDK usage, and removal. Physical TPM2 and FIDO2 remain separate qualification work.
