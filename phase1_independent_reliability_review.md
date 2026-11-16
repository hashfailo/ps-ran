# Phase 1E Independent Reliability Review

## 1. Executive summary

This was a read-only review of the success-aware Phase 1 implementation and
the persisted validation outputs under `outputs/phase1_success_aware/`. The
existing test suite was executed; no pipeline was rerun and no research
output was regenerated.

The implementation correctly enforces the central success-aware rule:
`status_raw is True` is required before a create/open observation establishes
a successful-create/open generation. Failed and unknown observations remain in
the event stream and do not receive candidate keys. Operation-first
observations are represented separately.

The persisted outputs are internally consistent. They contain 20 unique
reports, 20 event files, 1,474,631 events, no duplicate stored positions, no
per-process order violations, and summary totals that exactly match metadata
and event records.

However, material bounded issues remain:

1. A failed or unknown create/open observation on a handle that already has a
   current generation is ignored for lifecycle state, so a later operation may
   attach to the older generation without an explicit conflict marker.
2. Repeated successful create/open observations on an unclosed generation are
   counted as `repeated_create_observations` but are silently retained in the
   same generation rather than being represented as a lifecycle ambiguity.
3. Missing process identifiers are converted to the literal string `"None"` by
   `cape_parser.py`, which can merge otherwise unrelated processes if such
   reports occur.
4. Resume persistence is not fully crash-consistent: metadata can be committed
   before unresolved records, allowing a resumed run to skip a completed event
   file while losing unresolved records from the regenerated summary.

**Final verdict: CONDITIONAL PASS.** The pipeline is suitable for bounded
candidate-evidence validation, but it is not ready to freeze the methodology
or use for distinct-file damage measurement until the lifecycle-conflict,
missing-process-ID, and resume-consistency conditions are addressed and
revalidated.

## 2. Files and components inspected

- `scripts/phase1/cape_parser.py`: streaming event extraction and process
  identifier handling.
- `scripts/phase1/event_normalizer.py`: API-specific file-handle roles,
  raw argument preservation, and handle/path observations.
- `scripts/phase1/handle_tracker.py`: process-scoped generations, success
  gating, operation-first handling, closes, reuse, and ambiguities.
- `scripts/phase1/run_phase1_corrected.py`: selection, event persistence,
  metadata, unresolved records, summary aggregation, resume, and overwrite
  protection.
- `scripts/phase1/run_phase1_success_aware.py`: success-aware entry point.
- `scripts/phase1/storage.py`: atomic JSON/JSONL persistence.
- `scripts/phase1/models.py`: canonical event serialization.
- `tests/phase1/test_pipeline.py`: 16 lifecycle and serialization tests.
- `outputs/phase1_success_aware/phase1_corrected_summary.json`.
- `outputs/phase1_success_aware/metadata.jsonl`.
- `outputs/phase1_success_aware/unresolved_identities.jsonl`.
- `outputs/phase1_success_aware/completion_manifest.jsonl`.
- all 20 files under `outputs/phase1_success_aware/events/`.

The public CAPE instrumentation findings from
`outputs/phase1_corrected/phase1_cape_instrumentation_audit.md` were also
considered: `status=True` is the documented public-monitor success predicate,
but the exact deployed monitor revision remains unavailable.

## 3. Lifecycle invariant verification

| Invariant | Implementation evidence | Test evidence | Persisted-output evidence | Verdict |
|---|---|---|---|---|
| Only `status_raw is True` establishes successful-create/open generations | `handle_tracker.py:52-60, 90-103` records status and continues unless status is exactly `True`; successful generation creation is at `:96-103` | `test_failed_create_does_not_seed_following_operation`, `test_successful_open_and_failed_open_are_status_aware`, `test_missing_status_and_return_are_unknown_not_success` | 65,082 successful create/open observations and 44,004 successful-established generations | **PASS** |
| Failed/unknown create/open observations never seed successful generations | `:93` exits before generation creation and labels failed/unknown output observations | Failed, high-value-looking create/open and missing-status tests | 11,504 failed observations; no persisted failed/unknown create/open observation had a candidate key | **PASS** |
| Failed/unknown observations remain preserved | Event serialization writes the full event after `tracker.observe`; raw status/return/arguments are not removed | Serialization tests cover raw nested arguments; failed-observation test checks no candidate rather than deletion | All 1,474,631 events are present; failed observations are represented in event JSONL | **PASS** |
| Operation-first generations remain separate from later successful generations | `:63-77` creates provisional generations; `:96-103` creates a new generation when current origin is `operation_first` | `test_operation_first_then_successful_create_stays_separate` | 646 operation-first and 44,004 successful-established generations | **PASS** |
| Cross-process collisions cannot create incorrect associations | `_key()` uses `(event.process_id, handle)` at `:33-35`; candidate key includes sample and process | `test_cross_process_collision_is_separate` | No persisted candidate-key/process mismatch found | **PASS, subject to valid process IDs** |
| Handle reuse after close is separated | Successful create after closed current generation creates a new generation; operation after close also creates a new provisional generation | Existing reuse and post-close tests | 36,720 reuse-after-close observations; 44,650 total generations | **PASS** |
| Repeated closes cannot create false generations | Close with no current generation is marked uncertain and continued; repeated close increments a counter only | `test_close_without_established_file_generation_is_uncertain`, repeated-close test | 25,494 repeated closes; no close-only false generations were found in persisted candidate references | **PASS** |
| Post-close operations remain distinguishable | `:116-133` emits `operation_after_candidate_close` before creating a new provisional generation | `test_repeated_close_and_post_close_reference_are_distinct_observations` | 167 post-close references and 167 corresponding ambiguity records | **PASS** |
| `NtClose` is not automatically file-specific | Close requires an existing candidate; otherwise it becomes `uncertain` at `:75-87` | Close-without-generation test | Close-without-create observations are retained separately; no close-only candidate generation was found | **PASS** |
| Ambiguous observations cannot silently contaminate subsequent generations | Most transitions are explicit, but failed/unknown create/open observations do not emit a conflict when an older current generation exists; repeated successful creates reuse the current generation | No test covers failed create/open over an existing generation or repeated successful create without close | Persisted totals cannot prove absence of these unseen conflict cases | **FAIL / bounded gap** |

## 4. Edge-case review

### Successful create -> write -> close

Works as intended. A successful create establishes a generation; the write
and close receive the same candidate key in stored order. This is covered by
`test_successful_create_write_close_establishes_candidate`.

### Successful open -> read -> close

The same role logic applies to `NtOpenFile` and read operations. The test
suite covers successful open followed by close, but does not include the full
open -> read -> close transition. The behavior is **UNVERIFIED by a direct
test**.

### Failed create/open -> operation using the same numerical handle

With no prior current generation, the failed output receives no candidate and
the operation creates an `operation_first` candidate. This is covered.

If a prior current generation already exists for the same process-scoped
handle, the failed/unknown create/open is skipped and the later operation
continues using the prior current generation. The code has no
`failed_create_conflicts_with_current_generation` ambiguity. This is a
**High** reliability gap because raw equality does not establish that the
failed output and later operation refer to the same object.

### Operation-first -> successful create

The implementation deliberately creates separate generations. This is
covered by `test_operation_first_then_successful_create_stays_separate`.
The operation-first generation remains a candidate, not a confirmed file
identity.

### Create -> close -> operation

The closed generation is retained for the ambiguity record; the later
operation receives a new operation-first generation. This prevents direct
merging and is covered indirectly by the post-close test.

### Create -> close -> handle reuse

A successful create/open after close creates a new generation and increments
reuse. This is covered by the existing reuse test and persisted reuse counts.

### Repeated closes

Repeated closes increment `repeated_close_observations` and do not create
generations. This is covered.

### Multiple successful creates using the same handle

When the current generation is open, a second successful create/open increments
`repeated_create_observations` but appends another create position to the same
generation. The implementation does not emit a dedicated ambiguity or create
a new generation. This may be correct for duplicate logging, but it may also
represent an unobserved replacement or invalid trace. It is **Medium risk**
and currently **UNVERIFIED** for the dataset.

### Cross-process handle collisions

The key is process-scoped and the test passes. The implementation does not
include `source_process_index` in the tracker key, but process IDs are
normally sufficient. If the same process ID appears in multiple process
records within one report, the records intentionally share a handle table;
if process IDs are absent, the parser converts `None` to `"None"` and can
merge unrelated processes. No missing process IDs were found in the persisted
20-report outputs, but the missing-ID behavior is not safely represented.

### Multiple paths and multiple generations

The tracker retains path sets per candidate generation and emits
`one_handle_multiple_paths`. It also maintains a global
`path_to_candidates` map for multiple candidate keys per raw path. Persisted
records contain 49,969 one-handle/multiple-path and 5,702
multiple-handle/one-path ambiguity records.

The path map is per sample tracker, not global across samples. It is not
included in the serialized summary, so its internal set cannot be independently
reconstructed beyond the emitted ambiguity records.

### Missing or malformed arguments and status

Malformed arguments are skipped safely by the parser and missing arguments
produce no handle observation. Missing status is explicitly unknown in the
tracker. The tests cover these cases. There is no direct persisted sample
with missing status to validate the production path; this portion is
**UNVERIFIED on real data**.

### Duplicate or out-of-order events

The pipeline preserves input stored order and does not deduplicate events.
The persisted outputs contain no duplicate `(process_id,
source_process_index, process_call_position)` positions and no monotonicity
violations within those keys. The tests cover primary order versus a
timestamp-merged view, but do not test duplicate positions or tracker
behavior on deliberately out-of-order records. Those cases are **UNVERIFIED
by tests**.

## 5. API semantics assessment

The explicit API mapping remains directionally appropriate:

- create/open `FileHandle` observations are post-call output values under the
  public capemon implementation;
- write/read/information APIs use input `HANDLE` values;
- `NtClose.Handle` is an input handle for any object type.

The success-aware change correctly uses the preserved status boolean without
claiming that a successful write changed file contents. It also retains raw
return values and does not use numeric magnitude to classify handles.

The remaining semantic limitation is object identity: successful status and
exact value equality support candidate associations, not guaranteed kernel
file-object identity. The persisted event records do not contain a kernel
object identifier or independently validated file ID.

## 6. Unit-test coverage assessment

The existing suite was independently executed:

```text
Ran 16 tests ... OK
```

Covered behaviors include:

- successful create/write/close;
- failed create followed by operation;
- successful and failed open;
- missing status and return;
- operation-first separation;
- handle reuse;
- repeated closes;
- process separation;
- non-file handle exclusion;
- path ambiguity;
- missing/malformed arguments;
- nested argument serialization;
- primary ordering.

Missing or weak coverage:

1. successful open -> read -> close as one transition;
2. failed/unknown create/open over an already active generation;
3. repeated successful create/open without close;
4. missing process ID and process-ID collision behavior;
5. duplicate process-call positions;
6. out-of-order tracker input;
7. multiple handle observations in one event with mixed statuses;
8. resume crash points between each atomic write;
9. duplicate metadata rows or duplicate completion-manifest rows;
10. deterministic equality of two independently processed reports.

The tests are meaningful lifecycle tests, but the suite does not cover the
highest-risk persistence and conflict cases identified above.

## 7. Independent persisted-output consistency audit

The review read all persisted event files without regenerating them.

| Check | Result |
|---|---:|
| Selected reports | 20 |
| Metadata rows | 20 |
| Completion-manifest rows | 20 |
| Unique report paths | 20 |
| Event files | 20 |
| Events in summary | 1,474,631 |
| Events counted from JSONL | 1,474,631 |
| Benign events | 438,977 |
| Ransomware events | 1,035,654 |
| Event-file/metadata count mismatches | 0 |
| Per-process stored-order violations | 0 |
| Duplicate stored positions | 0 |
| Failed samples | 0 |
| Temporary files left behind | 0 |

The summary exactly matches metadata aggregation:

- file-handle observations: 223,008;
- non-file/unknown handle observations: 1,117,786;
- total generations: 44,650;
- successful-create/open-established generations: 44,004;
- operation-first generations: 646;
- failed create/open observations: 11,504;
- ambiguity/unresolved records: 347,691.

Class-separated values also reconcile:

| Class | Events | Successful create/open observations | Failed create/open observations | Successful-established generations | Operation-first generations | Total generations |
|---|---:|---:|---:|---:|---:|---:|
| Benign | 438,977 | 9,863 | 2,872 | 3,632 | 97 | 3,729 |
| Ransomware | 1,035,654 | 55,219 | 8,632 | 40,372 | 549 | 40,921 |

Every persisted failed or unknown create/open observation inspected had no
candidate key. Candidate references were unique by candidate key and each
reference had a generation number. These checks support the reported summary,
but cannot prove that the tracker handled unobserved input patterns correctly.

## 8. Resume and reproducibility assessment

### Verified behavior

- Existing output files cause a non-resume invocation to exit with an
  overwrite error.
- Resume found all 20 completed reports and skipped them.
- The completion manifest contains 20 unique reports and 20 unique event
  files.
- Event files are written through a temporary file followed by replacement.
- Metadata, failures, unresolved records, and summaries use atomic JSON/JSONL
  replacement.
- No temporary files remain in the persisted output directory.

### Risks

1. `completed` checks `Path(row["event_file"]).is_file()` directly. The stored
   event paths are relative, so resuming from a different working directory
   can fail to recognize completed files and may reprocess them. This is
   **Medium** and not tested.
2. The runner writes the event file, then the manifest, then metadata, then
   unresolved records. A crash after metadata is committed but before
   unresolved records are committed leaves a completed metadata row and event
   file but an incomplete unresolved stream. Resume skips that report, so the
   final summary undercounts unresolved records. This is **High**.
3. A crash after an event file replacement but before metadata persistence
   causes resume to reprocess that report. The event file is replaced
   deterministically, but this is extra work rather than a duplicate metadata
   row under normal operation.
4. A crash during a process before its metadata row is committed leaves the
   old metadata state and should reprocess the report. This is acceptable, but
   no crash-injection test proves it.
5. Summary regeneration on resume aggregates persisted metadata and unresolved
   records, but it does not independently verify that metadata report paths
   remain unique.

Independent byte-for-byte reproducibility of two fresh runs was not tested
because the task prohibits rerunning the pipeline. It is therefore
**UNVERIFIED**. The deterministic stored traversal, JSON separators, sorted
summary keys, and fixed selection support reproducibility, subject to input
files and working-directory path handling.

## 9. Findings by severity

### High

**H-1: Failed/unknown create/open conflicts are not explicitly represented.**
When a current generation already exists, a failed or unknown create/open
observation exits without creating a generation or ambiguity. A later
operation using the same handle can continue on the older generation. This
violates the requirement that ambiguous observations cannot silently
contaminate subsequent generations.

Evidence: `handle_tracker.py:90-94`; no test covers a failed create/open over
an active generation.

**H-2: Resume can commit metadata without unresolved records.**
The runner commits `metadata.jsonl` before `unresolved_identities.jsonl`.
Resume derives `completed` from metadata and event-file existence, so a crash
between those writes can permanently omit unresolved records for a skipped
sample.

Evidence: `run_phase1_corrected.py:216-224, 271-274`; no crash-injection test.

### Medium

**M-1: Missing process IDs collapse to `"None"`.**
`cape_parser.py:69` uses `str(first(...))`; missing values become `"None"`.
The tracker key is process ID plus handle, so multiple missing-ID process
records can collide.

Evidence: `cape_parser.py:69`; no missing-process-ID test; no missing IDs were
found in the persisted 20-report subset.

**M-2: Repeated successful creates reuse an open generation without an
ambiguity record.**
The tracker increments `repeated_create_observations` but leaves the same
generation active. This may be duplicate instrumentation or a real lifecycle
conflict and cannot be distinguished from the output.

Evidence: `handle_tracker.py:95-103`; no repeated-successful-create test.

**M-3: Resume path detection depends on the current working directory.**
Relative `event_file` paths are tested directly during resume.

Evidence: `run_phase1_corrected.py:111-115`; no alternate-working-directory
resume test.

### Low

**L-1: Summary schema uses the inherited filename
`phase1_corrected_summary.json` inside the success-aware directory.**
This is not a measurement error, but it weakens artifact clarity and can
confuse automation comparing phases.

Evidence: `run_phase1_corrected.py:84-86`.

**L-2: Real-report missing-status behavior is not exercised.**
The synthetic unit test proves the branch, but all 20 selected reports had
status values for the create/open observations inspected.

Evidence: persisted class counts show 11,504 false and 65,082 true, with no
unknown count; no production missing-status example exists in this subset.

## 10. Recommended corrections and additional tests

Recommended implementation changes, not performed in this review:

1. Emit a conflict ambiguity for failed/unknown create/open observations when
   a current generation exists; do not let the next operation silently inherit
   the older generation without an explicit uncertainty state.
2. Make process identity explicit when missing: use a per-process-record
   fallback key and mark it unresolved rather than converting missing IDs to a
   shared string.
3. Decide and document whether repeated successful creates on an open handle
   are duplicate observations or a new ambiguous generation; preserve both
   possibilities in the evidence.
4. Persist a single crash-consistent transaction state, or commit metadata and
   unresolved records together with a manifest/checksum that resume validates.
5. Resolve event paths relative to the output directory or store absolute
   paths with explicit provenance.
6. Use a distinct success-aware summary filename.

Additional tests:

- failed/unknown create over an active generation followed by operation;
- successful open -> read -> close;
- repeated successful create without close;
- missing process ID with two process records sharing a handle;
- duplicate positions and deliberately out-of-order tracker events;
- crash injection after each persistence step;
- resume from a different working directory;
- fresh-run deterministic event and metadata comparison.

## 11. Final verdict

**CONDITIONAL PASS: Bounded issues remain.**

The success-aware rule itself is implemented and persisted correctly for the
validated 20-report subset. The output statistics reconcile exactly, and the
candidate lifecycle model preserves important uncertainty categories.

The pipeline should not yet be frozen as the final Phase 1 methodology or
used for distinct-file damage measurement. Freeze should be conditional on
resolving H-1 and H-2, adding the recommended edge-case tests, and rerunning
the fixed 20-report validation into a new output directory. Full-dataset
processing should remain blocked until that revalidation succeeds.
