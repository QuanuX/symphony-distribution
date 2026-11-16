# D06 construction and qualification evidence

This increment implements the frozen 51-native/six-Go build cohort and its
source/SDK delivery checks at core commit
`5fd6cee1bae477048bf0045b691ee8bdf334e216`. It is not release acceptance.

## PR errors addressed first

[Selective CI triage](d06-pr-ci-triage.json) records the original jobs and exact
heads. PR #200 exhausted its CodeQL job time budget; the corresponding #202
CodeQL job completed. PR #202 encountered Go dependency download timeouts after
its preceding ownership groups passed. Only the two affected jobs were retried.
No source defect was established and no speculative core patch was pushed.
Retry results were not awaited. The focused local foundation lifecycle race test
passed with Go 1.26.5 and the verified offline module cache.

## Completed preparation checks

- The source-derived four-profile inventory reconciles 51 native units, six core
  Go commands, eight optional native units, the separate administrator and all
  73 source-root dispositions.
- 57 focused build/selection/finalization/SDK/owner contract tests passed.
- 32 focused source delivery, SDK closure and diagnostic tests passed.
- Workflow validation and whitespace checks passed.
- The exact curl 8.7.1 and zstd 1.5.7 clean dependency build passed, retaining
  pinned notices, explicit SecureTransport selection and no optional dependency
  autodiscovery. A detached relocated consumer linked and ran both libraries.
- A real Mach-O relocation test executed after its original dependency prefix
  was removed. This is harness evidence, not full-cohort acceptance.

The first full native build was deliberately interrupted after an archive check
found local numeric ownership and timestamps in a foundation static library.
The builder now supplies deterministic archive settings and rejects nonneutral
static-archive member metadata. Its repaired foundation build passed that check.
The interrupted stage remains incomplete; none of its bytes are accepted here.

## Full cohort status at this increment

The repaired two-round local build is in progress. Full final SDK, six installed
owner fixtures, repeated-byte comparison, corresponding-source collection and
disposable native removal are implemented but not yet claimed as completed for
this cohort. Their exact results will be attached in a subsequent evidence commit.
The local Intel macOS host is supplemental and cannot qualify any of the four
required native targets. Hosted builds are requested by pushing this branch;
no hosted result is inferred or awaited.

## Remaining release gates

External runtime carrier ownership, privacy-reviewed final bytes on every target,
actual-manager/privilege/fresh-host lifecycle behavior, genuine second-release
upgrade and selection journeys, publisher signing/trust, final Anaconda and
Cloudflare retrieval, and independent/backup acceptance remain open. Optional
native SDKs and physical/provider-specific claims retain their separate gates.
The feature freeze and core main remain unchanged.
