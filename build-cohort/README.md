# D06 clean native and SDK cohort

`cohort.json` derives the frozen selection from six exact core source documents.
Every required profile contains the same 51 complete native receipt units and
six core Go commands in the recorded dependency order. Eight optional native
units and the protected transport administrator remain separate. The Linux-only
observer is not offered in the macOS optional selection. All 73 source roots keep
their recorded source, documentation, optional or unimplemented disposition.

The selected cohort contains 20 of the catalog's 24 SDK producers and 12 ordinary
copied-consumer records. The other SDK producers remain with optional packages;
their qualification is not inferred from the core build. SBV ABI consumers,
owner regressions, Go source consumers and independent native SDK consumers keep
their separate evidence requirements.

```sh
python3 build-cohort/plan.py verify --core /absolute/exact-core-checkout
python3 -m unittest discover -s build-cohort -p 'test_*.py' -v
```

`plan.py generate` deliberately refreshes the manifest only after checking the
exact source commit, tree and bytes of each source document. Validation refuses
selection drift, missing dependency closure, duplicate units, stale W12 records,
unclassified SDK exports, Go workspace replacements and changed exact external
dependency pins. A plan is never evidence that its builds or acceptance gates ran.

The native runner uses a fresh source export, private home and state directories,
the mapped installed SDK options and every default build target. Final loader
paths must use package-relative locations or explicit platform runtimes. The
existing MVP qualification harness uses absolute private-prefix loader paths and
cannot substitute for this final stage. Loader edits, stripping and any selected
Apple signing occur before immutable receipts. Native-owned final bytes are
receipt-covered; external libraries have a separate exact inventory, and their
final distribution carrier ownership remains an open delivery gate. Development build paths, user stores and source-tree build
artifacts are excluded from distribution inputs.

The workflow selects the four recorded native profiles and toolchains, downloads
only checksum-pinned curl 8.7.1 and zstd 1.5.7 source archives, and records the exact
TLS input closure. Go dependencies are prepared separately with exact Go 1.26.5;
component builds use the verified cache with workspace replacements disabled.
Two serial clean rounds compare final outputs. Build directories may be reclaimed
only when owned by that invocation and after their evidence is retained.

The workflow runs only for this cohort's files or source binding. It retains the
bounded results, SDK/owner reports and portable dependency record, not raw local logs or publisher
state. A tracked Git archive in hosted CI is explicit source provenance; it is
not automatically the privacy-reviewed S08 derived source export. That distinction
remains in the result. Local supplemental Intel builds cannot qualify any of the
four required targets.

`owner_audit.py` selects six existing installed Go fixtures from the core
qualification manifest: SNV receipt tampering, consumer and adversarial transport,
the SBV installed boundary, SQAV installed requests, and the Cloudflare installed
receipt/process contract. Each selected test and every subtest must pass without
skips. The SNV tamper fixture receives a fresh projection of its complete seven
native receipt units and runtime dependencies, with every original byte and mode
verified. This preserves its strict regular-file copy guard while unrelated
external libraries retain legitimate symlinks in the full candidate. The other
five tests use the complete relocated prefix. Both the original prefix and the
projection, together with Go manifests, must remain unchanged. Optional observer
and SRRAPIV tests are explicitly unrun in this
core-only cohort; the broader native CTest and direct-process campaigns are also
reported separately as unrun by this focused audit.

D06 prepares and checks candidates. Publisher signing, public trust, Anaconda
upload/retrieval, Cloudflare installers and the final fresh-host acceptance
campaign remain separate. This work grants no publication or feature expansion.

## Run a reviewed cohort

Use the exact bound core checkout, the verified S08 export and its separately held
private scan policy. Prepare the pinned Go module cache first; the build has no
network fallback. Supply the exact selected compiler, CMake and Go executables.
The workflow shows the four native platform selections and explicit Linux TLS
inputs; local Apple builds may also supply `--developer-dir`.

```sh
python3 build-cohort/external.py --source /work/core \
  --work /work/new-external \
  --curl-archive /inputs/curl-8.7.1.tar.xz \
  --zstd-archive /inputs/zstd-1.5.7.tar.gz \
  --cmake /tools/cmake --cc /tools/clang --cxx /tools/clang++

python3 build-cohort/build.py --repository /work/core \
  --output /work/new-cohort --profile macos15-arm64 \
  --cmake /tools/cmake --cc /tools/clang --cxx /tools/clang++ \
  --go /tools/go --gomodcache /inputs/verified-go-modules \
  --external-prefix /work/new-external/prefix \
  --export /inputs/reviewed-export --privacy-policy /private/source-policy.json \
  --repeat --prune-builds
```

These are placeholders for explicitly selected local inputs, not paths to create
on an end user's machine. Every output directory must be new and disjoint from
inputs. An interrupted or failed output is retained as incomplete and cannot be
adopted by a retry. `--supplemental` is an explicit local engineering mode; it
cannot convert a different host into a supported target.

After the aggregate build passes, run `qualification/d06_delivery_record.py` and
`qualification/d06_sdk_closure.py` as described in the qualification README.
The delivery collector rechecks the exact built source, receipts, Go modules,
notices and payload inventory. Its optional source archive has neutral tar owner
metadata and contains the complete build/install toolkit snapshot. The native
builder also refuses static archives whose member metadata retains builder IDs
or timestamps; outer archive normalization alone cannot repair those inner bytes.


## Stable archive and link metadata

The native link uses its stable install RPATH and install-name policy from the
initial link. Removing private search paths afterward would leave Apple linker
UUIDs dependent on those paths. A regression builds and executes the same
consumer under two independent private prefixes and compares the finalized bytes.

On Darwin, `archive_padding.py` validates the complete BSD32 symbol index and
member offsets, then clears only its fully unreferenced string-table alignment
tail. Object bytes, names, headers and offsets are preserved. Unknown layouts
refuse. This happens in the existing finalizer before native receipt sealing;
external archives are finalized and inventoried separately after native installs.
Neutral inner member ownership and timestamps are still required.

`qualification/d06_repair_cohort.py` is a bounded recovery tool for the two exact
recorded local D06 origins. It creates a new candidate, uses source-generated
owners to remove and rebuild the eight affected dependency units, and verifies
the other 43 native units and six Go commands byte for byte. Its reports explicitly
distinguish inherited artifacts from fresh compilation. Only the external zstd
archive may change outside those eight owners. Original evidence and stages are
retained; the ordinary clean builder never resumes an incomplete output.
