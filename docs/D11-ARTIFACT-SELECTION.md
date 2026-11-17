# Preparing primary artifact selections

`qualification/primary_selection.py` prepares the exact committed selection
needed by the wrapper-only workflow. It runs offline against one downloaded
carrier capsule and saved GitHub metadata. It does not start builds, install
packages, dispatch workflows, sign artifacts, or authorize publication.

Use a completed `d10-carrier-capsule-<profile>-<attempt>` artifact. A completed
native recovery capsule is an earlier checkpoint and cannot be selected as a
finished carrier capsule. Queued or running jobs, report-only artifacts and a
successful dispatch are insufficient. A later wrapper failure is acceptable
only when the original native build, supplemental SDK closure and carrier
retention steps all completed successfully and the retained bytes pass the
complete capsule audit.

## Explicit review inputs

Create a request with protocol
`symphony.distribution.primary-selection-request.v1`. Its exact top-level
fields are:

| Field | Required selection |
| --- | --- |
| `protocol` | The request protocol above |
| `repository` | `QuanuX/symphony-distribution` |
| `profile` | One of the four existing primary profiles |
| `run_id`, `run_attempt` | Positive decimal strings for one completed producer attempt |
| `workflow_commit` | The exact producer commit, 40 lowercase hexadecimal characters |
| `artifact` | Object containing `id` (integer), `name`, `sha256` (64 lowercase hexadecimal characters), and `size` (integer bytes) from the independently selected GitHub artifact |
| `source` | Object containing independently selected `source_commit`, `source_tree`, `source_export_digest`, and `source_manifest_sha256` |

The core commit and tree must also match this repository's frozen
`source-binding.json`. The reviewed export digest and source-manifest digest
must be selected independently of the ZIP being evaluated. Do not populate
missing intent by adopting whatever values an archive contains.

Save these three complete GitHub REST response objects separately:

- The exact workflow run attempt, including repository, commit, event, state,
  and `head_commit.id` / `head_commit.tree_id` for the original toolkit tree.
- The exact artifact object, including ID, name, digest, size, expiry and producer.
- The complete jobs collection for that attempt, with `total_count`, `jobs`,
  attempt numbers and full step outcomes. Merge paginated responses before use;
  the declared count must equal the collected jobs. Summaries that omit attempt
  numbers are insufficient.

The offline helper cannot authenticate these saved API responses. It records
their hashes and checks their consistency with the explicit request. The
existing hosted transport retrieves authoritative metadata and the selected ZIP
again before wrapper assembly. Local preparation never substitutes for that
fresh check, publisher trust, or independent acceptance.

## Prepare and review

Use the existing isolated publisher Python, which includes the selected Conda
archive reader and codecs. The private scan policy must remain a separate
regular file with mode `0600`.

```sh
PINNED_PUBLISHER_PYTHON -B -m qualification.primary_selection \
  --request EXPLICIT_REQUEST.json --request-sha256 REQUEST_SHA256 \
  --archive DOWNLOADED_CAPSULE.zip \
  --run-metadata RUN_ATTEMPT.json --artifact-metadata ARTIFACT.json \
  --jobs-metadata COMPLETE_JOBS.json --privacy-policy PRIVATE_POLICY \
  --output NEW_PRIVATE_REVIEW_DIRECTORY
```

The request and every input must be independent regular files with nonlinked
paths. Existing output directories, hardlink aliases and changed input bytes
are refused. ZIP traversal, case collisions, special files, links and oversized
entries use the existing bounded extraction rules. The helper retains its new
private extraction in `capsule/` for review; original inputs remain unchanged.
An interrupted or failed review may leave that private extraction, but emits no
actionable selection before all qualification checks pass.

The original toolkit tree must also match the saved producer commit observation.
The complete capsule audit verifies all 58 actual carrier archives and their
native payload assignment, both original build-round inventories, receipt and
qxctl bindings, delivery and supplemental SDK evidence, the reviewed source
manifest, and the original Git toolkit tree with its executing helper closure.
It preserves the 36 pending independent acceptance cells. It neither executes
old toolkit source nor demands that original build helpers equal a later
wrapper repair's helpers.

After successful validation, the helper writes:

- `review.json`: input and helper hashes, source/producer bindings, complete
  capsule audit scope and explicit pending authority and acceptance gates.
- `selection.json`: the existing
  `symphony.distribution.primary-rewrap-selection.v1` record, including all
  required result, cohort, build, round, SDK, delivery, source and acceptance
  pins. This actionable file is written last.

Only these two reviewed records are candidates for the evidence repository.
Keep raw API responses, private policy, downloaded ZIP and extracted custody
outside the repository. After review, copy the selection to a descriptive
`evidence/primary-selections/*.json` path, commit it on the distribution feature
branch, and provide that exact path and file SHA-256 to the existing wrapper-only
workflow. The helper itself performs none of those mutations or dispatches.

## Validation scope

Focused tests exercise a source-bound fixture through the actual complete
capsule verifier, using the existing test adapter only for Conda encoding.
They check independent request/source pins, immutable inputs, unchanged
original Git/helper provenance, full job snapshots, failed or unfinished
producers, alias and path refusal, and privacy of the emitted records. These
fixtures do not create a real primary selection or satisfy hosted installation,
matching-primary-client, trust, human-review or Public Beta acceptance gates.
