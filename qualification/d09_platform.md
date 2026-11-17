# Primary-platform and disposable-user preparation

`d09-platform.yml` creates an engineering review cohort on one explicitly selected primary platform, then optionally exercises inert installer behavior on a **separate disposable GitHub-hosted runner**. Pushes run only the focused contract tests. A manual dispatch starts the native work; it does not publish or promote anything on Anaconda or Cloudflare.

The four choices are `macos15-arm64`, `ubuntu24.04-amd64`, `ubuntu24.04-arm64`, and `ubuntu26.04-amd64`. The retained local Intel package is supplemental and is refused by this route. A matching Conda subdirectory alone is insufficient: the actual OS release and architecture must also match.

## Required source selection

The dispatch requires the previously reviewed derived-export digest and exact `SOURCE-EXPORT.json` SHA256. The private repository secret `SYMPHONY_SOURCE_PRIVACY_POLICY` supplies the existing privacy policy; it is written with mode 0600 in temporary storage and never uploaded. The workflow regenerates the export from the frozen core Git commit using the existing source exporter, then checks both supplied pins and the full original/derived source relationship. Missing policy, mismatched source, and raw-Git fallback are refusals. Entering a digest does not approve new source or grant release authority.

This deliberately requires a review outside the producing job. Do not set either input from the output of that same job, substitute an empty scan policy, or put the private policy into dispatch text, source control, logs, or artifacts.

## Executable route

1. Select the exact core commit and native compiler from the existing D06 contract. Prepare pinned curl/zstd source and the verified Go module cache in private temporary directories.
2. Build two full 51-native/six-Go cohorts and require final payload equality. qxctl uses its original-Git reproducible recipe and separately proves equivalence to the reviewed compiled source. Run the existing installed SDK/owner/loader checks plus supplemental SNV API, Go SDK consumer, and disposable native removal checks.
3. Produce the full reviewed source/dependency/notices inventory, then pass the actual final reports and bytes through unchanged D08 cohort and carrier validators. Assemble 58 independent baseline carriers: 51 native, six Go, and the external dependency closure. The separately built primary client is still required; the Intel client is never relabeled as ARM or Linux.
4. Assemble matching native `.sh` wrappers and, on Apple Silicon, an unsigned `.pkg`. Exact inner carriers and bootstrap bytes are inspected. Source/export/raw build directories, user state, private scan policy, and raw process logs are excluded from uploaded review artifacts. The selected cohort, wrapper reports, public dependency records, and tool closure hashes remain bound to exact bytes.
5. When `fresh_user` is explicitly enabled, a separate hosted runner downloads this run's exact artifact. It verifies the selected result digest, re-audits the carriers and shell wrapper, and uses new private home/cache/prefix directories. It runs offline Conda link/removal and a shell-wrapper install into an absent prefix, verifies every carrier byte and mode, and checks existing-prefix, force, upgrade, and dangling-link refusals. Home sentinels and installed bytes must remain unchanged. There is no runtime owner setup, service start, provider operation, shell initialization, credential enrollment, or application selection.

The compiler executable spelling is preserved; resolving `clang++` to `clang` would change its linker behavior. The publisher tool helper preserves the existing exact top-level tool versions and bootstrap archive pins, records the resolved transitive environment, and does not claim that a newly resolved transitive tool set has independent release approval.

## Acceptance boundaries

`fresh-host-requirements.json` copies the frozen acceptance plan's four profiles and nine scenarios into 36 pending cells, with CLI and standalone routes distinguished. The automated inert-carrier exercise completes none of those broad independent acceptance cells by itself. A successful run establishes the checks actually observed on disposable hosted runners, not physical hardware, final signed-download acceptance, independent reviewer approval, live provider behavior, native runtime lifecycle, or the complete D10 campaign.

The Apple `.pkg` is assembled and inspected but not installed by this workflow. Native Apple trust/notarization and the final installation path remain separate. Native owner upgrades, rollback, runtime removal, primary-client actual Codex qualification, independent operators, and final retrieval/signature policies remain explicit gates. No current user's installed system is used as a test destination.

The workflow retains review artifacts for 14 days; these are CI evidence, not a durable published channel. D09 staging/retrieval and the legal/signing registry are separate from this preparation route. Reuse the same immutable final artifacts only after the relevant approval and trust gates are satisfied.
