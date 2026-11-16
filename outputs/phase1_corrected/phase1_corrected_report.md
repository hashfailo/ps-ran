# Phase 1 Corrected Reliability Report

## Scope

The corrected implementation was validated on exactly the 20 reports from the
Phase 0C selection manifest: 10 benign and 10 ransomware. It did not process
the full dataset and did not modify raw reports or Phase 0 artifacts.

The original Phase 1 outputs under `outputs/phase1/` were preserved. Corrected
outputs are under this directory.

## Corrections implemented

### API-specific file-handle classification

File identity tracking now uses an explicit API/argument role map:

- `NtCreateFile.FileHandle`: `create_attempt`
- `NtOpenFile.FileHandle`: `open_attempt`
- `NtWriteFile.FileHandle`, `WriteFile.FileHandle`, `NtReadFile.FileHandle`,
  `ReadFile.FileHandle`, `NtSetInformationFile.FileHandle`,
  `NtQueryInformationFile.FileHandle`, `NtFlushBuffersFile.FileHandle`,
  `NtQueryEaFile.FileHandle`, and `NtSetEaFile.FileHandle`: `operation`
- `NtClose.Handle`: `close`

Generic arguments such as `ProcessHandle`, registry `Handle`, service handles,
thread handles, and network handles remain in the raw event record but are
marked `non_file_or_unknown` and do not receive file identity candidates.
Uncertain APIs including `NtDuplicateObject`, `NtDeviceIoControlFile`, and
`NtQueryObject` are marked `uncertain` and excluded from file identity
tracking.

An `NtClose.Handle` observation without an established file generation is
marked uncertain rather than creating a new file identity.

### Lifecycle corrections

- Repeated closes now increment `repeated_close_observations`.
- Post-close operations remain candidate observations and explicitly carry
  `confirmed_invalid: false`.
- Reuse after close creates a new generation and does not merge generations.
- Candidate keys remain scoped to sample, process, normalized handle, and
  generation.
- Create/open observations remain attempts; no status or return success
  semantics are fabricated.

### Ambiguity corrections

The corrected unresolved stream records:

- path-only observations;
- file-handle-only observations;
- multiple handles associated with one raw path;
- one handle associated with multiple raw paths;
- operations after candidate close.

Every ambiguity record includes sample ID, class, report path, process ID,
process-call position, and API where applicable.

### Ordering and storage corrections

The original stored process-call order remains the only serialized event
stream. The corrected metadata explicitly states that a merged timestamp view
is not serialized because timestamp ordering is not ground truth and a
memory-safe sorted stream would require a separate implementation.

Metadata, failures, unresolved records, and completion manifests use temporary
files, `fsync`, and atomic replacement. Per-sample event files are written
before their completion manifest entry.

## Test results

The expanded unit suite passed **11/11** tests. It covers:

- event order preservation;
- nested argument serialization;
- file handle creation and closure;
- handle reuse and generation separation;
- repeated closes;
- post-close references;
- multiple handles for one path;
- one handle for conflicting paths;
- missing close events;
- repeated writes;
- cross-process collisions;
- non-file handles;
- missing arguments and malformed records.

The corrected validation also round-tripped all 20 event JSONL files and
verified that stored process-call positions were monotonic within each
process. Overwrite protection was verified: a second run without `--resume`
fails instead of replacing corrected outputs.

## Old versus corrected measurements

| Metric | Original Phase 1 | Corrected Phase 1 |
|---|---:|---:|
| Events | 1,474,631 | 1,474,631 |
| Ambiguity/unresolved records | 408,946 | 346,827 |
| File-handle observations | broad generic count | 223,031 |
| Non-file/unknown handle observations | not separated | 1,117,763 |
| Failed samples | 0 | 0 |

The event total is unchanged because extraction still preserves every parsed
call. The handle counts are not directly comparable as file counts: the old
implementation classified generic handle-like arguments as file candidates,
while the corrected implementation separates explicit file-handle roles from
non-file/unknown observations.

Corrected per-class statistics:

| Class | Events | File handles | Non-file/unknown handles | Generations | Reuse-after-close | Repeated closes | Post-close references |
|---|---:|---:|---:|---:|---:|---:|---:|
| Benign | 438,977 | 51,568 | 392,563 | 3,882 | 2,293 | 8,989 | 28 |
| Ransomware | 1,035,654 | 171,463 | 725,200 | 40,910 | 34,302 | 16,627 | 235 |

Corrected ambiguity/unresolved reasons:

| Reason | Count |
|---|---:|
| Path-only observation | 133,873 |
| File-handle-only observation | 146,499 |
| Multiple handles for one raw path | 5,978 |
| One handle associated with multiple paths | 60,214 |
| Operation after candidate close | 263 |
| Total | 346,827 |

These are evidence categories, not confirmed physical-file or invalid-handle
counts. A single event can contribute to more than one conceptual ambiguity
over its lifetime, although each emitted record has one reason.

## Representative corrected observations

Both benign and ransomware event files retain records such as:

- `NtProtectVirtualMemory.ProcessHandle` or
  `NtAllocateVirtualMemory.ProcessHandle`: raw handle preserved,
  `object_type=non_file_or_unknown`, no file identity candidate.
- `NtCreateFile.FileHandle` with a path: explicit file candidate generation
  attached to the event.
- `NtClose.Handle` after a tracked file generation: candidate close attached
  to that generation.
- `NtClose.Handle` without a preceding tracked file create/open: uncertain
  close, no new file generation.

Raw API names, raw argument structures, values, pretty values, status, return,
timestamps, call IDs, process metadata, and source positions remain present in
the canonical event JSONL.

## Remaining limitations

1. A file-handle role is still an observational convention, not proof that
   CAPE's `FileHandle` value is a successful output handle.
2. Status and return semantics remain unvalidated.
3. Candidate generations do not prove physical kernel-object identity.
4. Different paths may be aliases; equal paths may refer to different
   generations or objects.
5. Path-only APIs cannot currently be joined confidently to handle-based
   candidates.
6. The merged timestamp-based stream is intentionally not serialized.
7. No damage, success, deletion completion, rename completion, or detector
   alert timing is calculated.
8. The corrected runner still uses JSONL because PyArrow and fastparquet are
   unavailable; Parquet was not silently substituted.

## Reproduction

```bash
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m scripts.phase1.run_phase1_corrected \
  /path/to/EN2025
```

Use `--resume` only for an interrupted corrected run. The default corrected
output directory is `outputs/phase1_corrected/`.

## Recommendation

The corrected pipeline is suitable for another controlled validation review.
It is **not yet sufficient for Phase 2 damage measurement or guaranteed
distinct-file counting**. Before full-dataset processing, the explicit file
API map and outcome semantics should be reviewed against additional CAPE
argument examples, and the storage capacity for raw JSONL should be planned.
