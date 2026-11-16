# Phase 1 Success-Aware Validation Report

## Scope

This validation corrected create/open generation seeding without modifying
prior Phase 1 or Phase 1 corrected outputs. It used exactly the 20 reports
selected in `outputs/phase0c/phase0c_summary.json`: 10 benign and 10
ransomware. No full-dataset processing or Phase 2 work was performed.

The public capemon semantics used here are: `status=True` represents
`NT_SUCCESS(ret)` for the documented monitor behavior, while the exact
deployed capemon revision remains unavailable.

## Changes implemented

### Success-aware create/open handling

- `NtCreateFile.FileHandle` and `NtOpenFile.FileHandle` establish a
  successful-create/open generation only when `status_raw is True`.
- `status_raw is False` is retained as an
  `unsuccessful_output_observation` and cannot seed a generation.
- Missing status is treated as unknown, not success, and is retained as an
  `unknown_output_observation`.
- Raw arguments, status, return, paths, and provenance remain in the event
  stream.

### Operation-first handling

File operations without a preceding successful create/open observation create
an explicitly provisional `operation_first` candidate generation. They retain
process scoping and raw input handles but are not confirmed file identities.

If a successful create/open later appears for the same process-scoped handle,
it receives a new generation rather than silently merging with the
operation-first generation. Operations after a close are separately recorded
as post-close references and receive a new provisional generation.

### Lifecycle and ambiguity

Process boundaries, generation separation, repeated closes, post-close
references, path-only evidence, handle-only evidence, multiple paths, and
multiple handles remain represented. `NtClose` remains conditional on an
established candidate and is not treated as inherently file-specific.

## Test results

The complete unit suite passed **16/16 tests**. New tests cover:

1. successful create -> write -> close;
2. failed create followed by an unrelated operation;
3. successful open -> close;
4. failed open with a high/pointer-like-looking raw value;
5. operation-first handles;
6. handle reuse after close;
7. repeated closes;
8. cross-process handle collisions;
9. missing status;
10. missing return values.

The tests also continue to cover raw nested arguments, malformed arguments,
non-file handles, path ambiguity, repeated writes, and event ordering.

## Validation results

The exact fixed subset processed successfully:

- Selected: 20 reports
- Processed: 20 reports
- Failed: 0 reports
- Events: 1,474,631
- Serialized event files: 20
- Event-order violations: 0

The event total is unchanged from the corrected Phase 1 output, confirming
that failed create/open observations were preserved rather than discarded.

### Overall comparison

| Metric | Phase 1 corrected | Success-aware |
|---|---:|---:|
| Events | 1,474,631 | 1,474,631 |
| File-handle observations | 223,031 | 223,008 |
| Non-file/unknown handle observations | 1,117,763 | 1,117,786 |
| Ambiguity/unresolved records | 346,827 | 347,691 |
| Handle generations | 44,792 | 44,650 |
| Successful create/open-established generations | not separated | 44,004 |
| Operation-first generations | not separated | 646 |
| Failed create/open observations | not separated | 11,504 |

The small file/non-file observation difference reflects close observations
that are no longer assigned candidate generations when no established
generation exists. The ambiguity increase reflects explicit unsuccessful and
operation-first evidence.

### Class-separated lifecycle metrics

| Class | Events | Successful create/open observations | Failed create/open observations | Successful-established generations | Operation-first generations | Total generations | Reuse after close | Repeated closes | Post-close references |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Benign | 438,977 | 9,863 | 2,872 | 3,632 | 97 | 3,729 | 2,281 | 9,005 | 15 |
| Ransomware | 1,035,654 | 55,219 | 8,632 | 40,372 | 549 | 40,921 | 34,439 | 16,489 | 152 |

Create/open observations by class are:

| Class | Total create/open observations | Status true | Status false | Status unknown |
|---|---:|---:|---:|---:|
| Benign | 12,735 | 9,863 | 2,872 | 0 |
| Ransomware | 63,851 | 55,219 | 8,632 | 0 |

The unit tests confirm that missing status would be counted separately as
unknown and would not establish a generation, even though no missing-status
create/open observations occurred in this 20-report run.

## Resume and overwrite validation

The new output directory is `outputs/phase1_success_aware/`. A second
invocation without `--resume` is rejected by overwrite protection. Resume
metadata identifies all completed event files and skips already completed
reports; the summary is regenerated from the persisted metadata without
reprocessing those reports.

## Interpretation and limitations

The success-aware change addresses a specific false-generation mechanism: a
failed or unknown create/open output observation no longer seeds a candidate
generation. It does not prove physical file identity.

In particular:

1. `status=True` is the documented public-monitor success predicate, but the
   exact EN2025 monitor revision is unavailable.
2. A successful native create/open call establishes a candidate returned
   handle observation, not guaranteed kernel-object identity.
3. Operation-first candidates are useful evidence but have no preceding
   successful create/open anchor.
4. Equal values can be reused by the operating system and are separated only
   by the stored process-call sequence and candidate lifecycle evidence.
5. `NtClose` accepts handles to any object type.
6. Successful writes or information calls do not prove changed file contents,
   damage, deletion, or rename completion.
7. Path strings remain unnormalized and may be aliases or incomplete names.

## Recommendation

The success-aware pipeline is suitable for the next reliability review and
for producing candidate event evidence on the fixed subset. It is not yet a
confirmed distinct-file or damage-measurement pipeline. Any later damage
phase must keep successful-create/open-established generations,
operation-first candidates, failed output observations, and unresolved path
evidence separate.

No full-dataset processing should begin until these categories and the
remaining file-identity limitations are reviewed.
