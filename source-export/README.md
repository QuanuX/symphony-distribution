# Reviewed corresponding-source preparation

The published **0.2.0-beta.2** supplies corresponding source as a separate Conda
package and per-platform source archive. See the
[installation guide](../docs/BETA-INSTALL.md) and
[publication evidence](../evidence/beta2-publication.json). This page documents the
source-preparation tool and its earlier selected proof; release acceptance is
established by the separately bound final artifact records.

This S08 exporter updates the earlier D03 source preparation to the exact core
commit/tree in `source-binding.json`. It reads original Git blobs, never copies
developer build directories, caches, runtime state or Git history. It leaves
core unchanged. The derived archive is preparation material, not an approved
SDK, signed installer or accepted Public Beta release.

```sh
python3 source-export/export_source.py build \
  --repository /absolute/reviewed-core \
  --privacy-policy /absolute/private-source-privacy-policy.json \
  --output /absolute/new-source-export
python3 source-export/export_source.py verify \
  --repository /absolute/reviewed-core \
  --privacy-policy /absolute/private-source-privacy-policy.json \
  --output /absolute/new-source-export
python3 -m unittest discover -s source-export -p test_export_source.py -v
```

The private policy contains `schema: symphony.source-privacy-policy.v1`, a
nonempty `markers` list and `document_attributions` mapping. Only the fixed role
replacements admitted by the tool are allowed. Store it outside the repository
and distribution inputs. Its digest is recorded; the identities themselves
are never bundled. Recipients building the exported source do not need this
publisher policy. A policy is a scoped known-marker scan, not proof that every
possible private identifier or secret has been discovered.

The reviewed transformations preserve operational source and original legal
material. Six historical SHV fixtures receive synthetic paths; one SCNV test
user becomes synthetic; personal narrative attribution becomes role-based.
Recognized copyright/license-attribution paragraphs and license/notice files refuse
rewriting and require separate review. Historical publisher dossiers and their
dedicated tests, CI/security records and one development ledger are explicitly
omitted. The derived dependency map rebinds changed input hashes and removes
only the omitted private publisher test inputs. Versions, component roots,
dependencies and owner contracts remain unchanged. The updated external
[dossier](../dossier/README.md) preserves the acceptance requirements.

The v2 manifest binds the original commit/tree, every original blob/hash/mode,
exported bytes, reviewed omissions, transformations, privacy-policy digest and
transformer hash. Verification with `--repository` recomputes the complete
original-to-export relationship. Verification also reconstructs and compares
the entire deterministic tar stream, including end padding: hidden trailers,
extra PAX/global metadata, duplicate entries, links and changed modes cannot
pass. Unknown manifest fields, altered implementation provenance and invented
release/publication acceptance are refused. Source paths, owner names and
timestamps in the archive are neutral. Failed work remains marked incomplete.

## Selected public-source build proof

`check_go_source.py` compiles the six non-qxctl Go commands from the verified
derived tree with Go 1.26.5, a fresh build cache, empty build home, disabled Go
workspace/configuration and offline checksummed module inputs. It uses the
catalog's exact trimpath/version flags, refuses module replacements, checks
compiled versions and personal build-path leakage, and compares every output
byte with the already reviewed candidate. Its process cleanup reuses the S07
bounded runner; no host service or module selection occurs.

```sh
python3 source-export/check_go_source.py \
  --export /absolute/new-source-export --repository /absolute/reviewed-core \
  --privacy-policy /absolute/private-source-privacy-policy.json \
  --candidates /absolute/verified-go-candidates \
  --go /absolute/go1.26.5/bin/go --gomodcache /absolute/verified-module-cache \
  --output /absolute/new-source-build-proof
```

This proof does not replace qxctl's original two-build identity recipe or stamp
the original Git tree onto a transformed source archive. It does not qualify
all C++/Swift/native roots, installed SDK consumers, other platforms or final
downloaded bytes. Those checks require their separate D06/D10 and final release
evidence; this earlier source-build proof does not establish them. Source fixtures
must never seed a recipient's runtime knowledge,
credentials, hardware identity or application profiles.

Portable results: [source/export binding](../evidence/s08-source-export.json)
and [selected Go source builds](../evidence/s08-derived-go-source-build.json).
Actual archives, private policies, extracted source and build outputs remain
outside this source repository.
