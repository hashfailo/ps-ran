# Phase 1.1 Reliability Audit

## Scope and method

This audit examined the existing Phase 1 implementation, the 20-report
validation outputs, representative event JSONL records from both classes, and
the unit-test suite. It did not process the full dataset, modify raw reports,
or modify Phase 0 artifacts. Existing Phase 1 validation outputs were read
only.

The audit added focused tests to
`tests/phase1/test_pipeline.py`; it did not regenerate the Phase 1 outputs.

## Executive findings

1. The primary stored process-call order is preserved in each event record.
2. Raw `arguments_raw` values are preserved in the canonical JSONL records and
   nested JSON values round-trip successfully.
3. Handle generations are deterministic and process-scoped, but the current
   tracker is not file-specific: it treats many non-file handles as candidate
   file identities.
4. The reported post-close and reuse counts are candidate observations, not
   confirmed lifetime events.
5. All 54,127 unresolved records are path-only observations. This is expected
   for APIs such as `NtQueryAttributesFile`, but the unresolved stream does not
   include other ambiguity classes when a candidate handle association exists.
6. Repeated operations reuse a candidate generation; they do not create new
   generations. However, Phase 1 does not yet emit a distinct-identity count,
   so it cannot by itself measure repeated-operation inflation.

## Existing validation statistics

| Class | Reports | Events | Candidate generations | Post-close references | Reuse-after-close observations |
|---|---:|---:|---:|---:|---:|
| Benign | 10 | 438,977 | 10,401 | 158,316 | 2,861 |
| Ransomware | 10 | 1,035,654 | 72,798 | 250,630 | 36,860 |
| Total | 20 | 1,474,631 | 83,199 | 408,946 | 39,721 |

Other tracker counters:

| Counter | Benign | Ransomware |
|---|---:|---:|
| Repeated create observations | 9,321 | 24,258 |
| Operations without candidate create | 4,854 | 29,699 |
| Closes without candidate create | 2,133 | 3,506 |

These counts are based on stored process-call order and the current argument
heuristics. They must not be interpreted as physical file lifetimes.

## Post-close reference audit

### Counting rule

For each normalized handle key `(process_id, normalized_handle)`, the tracker
keeps the latest candidate generation. When an observation is classified as a
close, its position is appended to that generation's `closed_positions`.
Later non-create, non-close observations for the same current generation
increment `post_close_reference` and append an ambiguity record.

The rule is implemented in
`handle_tracker.py` and is based only on stored process-call order. It does
not verify that:

- the close succeeded;
- the handle was a file handle;
- the preceding create succeeded;
- the handle was not already closed;
- the later operation actually reached the same kernel object.

### Representative examples

The first observed examples are not file operations:

- Benign `regopenkeyexw` followed by `regqueryvalueexw` using a `Handle`.
- Ransomware `regopenkeyexw` followed by `regqueryvalueexw` using a `Handle`.

These records received candidate file identity keys because the generic
`HANDLE_RE` matches `Handle`. This demonstrates that a substantial portion of
the post-close count can concern registry or other object handles rather than
files.

The validation artifact contains 158,316 benign and 250,630 ransomware
post-close observations under the current broad rule. A separate scan found
27,777 benign and 50,621 ransomware repeated-close observations for a key
already marked closed. Those repeated closes are not included in
`post_close_reference`, because the close branch handles them separately.

### Interpretation

The current counter conflates at least these cases:

1. A genuine operation after a successful file close.
2. A repeated close of the same handle.
3. A handle value reused without a recognized create.
4. A non-file object handle matched by the generic heuristic.
5. A close or operation whose CAPE argument does not provide enough evidence
   to establish the object type or outcome.

Therefore, the 408,946 value is a count of **candidate post-close references
under the tracker rule**, not a count of genuine post-close file operations.

## Reuse-after-close audit

### Counting and generation assignment

`candidate_reuse_after_close` increments when a create/open-like API uses
`FileHandle` or `FileObject` for a handle whose current generation already has
at least one stored close position. A new generation is then created with an
integer suffix starting at zero:

`sample_id:process_id:normalized_handle:generation`

The key includes the sample and process ID, so identical handle values in
different processes receive different candidate keys. Tests confirm that a
cross-process collision does not share a key.

### Observed counts

The existing output reports 2,861 benign and 36,860 ransomware reuse-after-
close observations. A direct scan of the event files found 4,003 benign and
39,502 ransomware create events with a prior generation, because the stored
counter reflects the implementation's current-generation transitions rather
than a complete independent lifetime reconstruction.

The discrepancy is a reliability warning: reuse counts should be recomputed
from an explicit generation-transition audit rather than inferred from the
aggregate counter alone.

### False reuse risks

Possible false classifications include:

- `FileHandle` may be an observed argument rather than a confirmed output
  handle.
- A create/open call may have failed; status and return are not interpreted.
- A prior close may have failed or referred to a different object.
- Missing calls or incomplete arguments can hide an intervening transition.
- Handle values are normalized text, so formatting aliases are grouped.
- Generic handle arguments allow non-file object reuse to enter the same
  tracker.

The generation mechanism is deterministic and process-scoped, but it does not
establish kernel-object identity.

## Unresolved identity audit

There are 54,127 unresolved records:

| Class | Path-only unresolved records |
|---|---:|
| Benign | 22,721 |
| Ransomware | 31,406 |
| Total | 54,127 |

All unresolved records are path-only: they have usable or classified path
observations but no handle observations and therefore no candidate generation.
The most frequent APIs are:

- `NtQueryAttributesFile`: 22,599
- `NtQueryFullAttributesFile`: 17,264
- `FindFirstFileExW`: 4,560
- `LdrLoadDll`: 4,505
- `LoadLibraryExW`: 1,718

These are not necessarily ambiguity errors; many path-based APIs naturally
lack a handle. They are unresolved because the current identity model requires
an observed handle candidate.

The unresolved stream does **not** capture:

- handles associated with multiple distinct raw paths;
- one raw path associated with multiple handles;
- conflicting path observations on one generation;
- candidate identities whose object type is unknown;
- operations with a candidate handle but no usable path;
- repeated operations mapped to the same candidate generation.

Those cases remain in event records and prior Phase 0D evidence, but are not
materialized as unresolved identity records. This is a coverage gap.

## Candidate identity and repeated operations

Candidate keys are attached to handle observations and are explicitly labeled
`candidate_process_handle_generation`; they are not marked as confirmed.
Repeated writes using the same process-scoped handle reuse the same candidate
key and do not create a new generation. The tests verify this behavior.

However, the current Phase 1 output does not provide a canonical distinct
identity table or a distinct-identity count. Consequently, it cannot yet
demonstrate from its own outputs that repeated operations are excluded from a
future file count. A later identity table must count candidate generations,
not event rows, and must preserve unresolved/path-only records separately.

## Expanded tests

The test suite now passes **9/9** tests, covering:

- stored event order versus deterministic timestamp ordering;
- nested argument serialization;
- handle creation, closure, reuse, and process separation;
- multiple handles associated with one raw path;
- one handle associated with conflicting raw paths;
- missing close events;
- repeated writes without new identities;
- cross-process handle collisions;
- missing arguments and unresolved observations;
- repeated close plus post-close operation behavior;
- malformed call records.

## Newly discovered bugs and required corrections

### 1. Generic handles are treated as file handles

`HANDLE_RE` matches any argument containing `handle`, including
`ProcessHandle`, registry `Handle`, service handles, and network handles.
Representative event records show registry APIs receiving candidate file
identity keys.

**Required correction:** restrict file-handle tracking to an explicit API and
argument allowlist established by Phase 0C.1, initially:

- `NtCreateFile.FileHandle`
- `NtOpenFile.FileHandle`
- `NtWriteFile.FileHandle`
- `NtSetInformationFile.FileHandle`
- `NtClose.Handle`

Other handle-like arguments should remain raw observations but be labeled
non-file or unknown-object evidence.

### 2. Create/open observations are treated as lifetime creation without outcome validation

The tracker creates or advances generations from API and argument names alone.
It preserves status and return values but does not use them to distinguish
attempted from outcome-supported creation.

**Required correction:** retain separate `attempted_create`, `outcome_present`,
and `outcome_unresolved` states. Do not let a failed or ambiguous create
automatically establish a new file-handle generation.

### 3. Repeated closes are not separately reported

The tracker appends repeated close positions but has no
`repeated_close_observations` counter. This obscures an important cause of
post-close and lifetime ambiguity.

**Required correction:** count repeated closes explicitly and preserve their
source events.

### 4. Unresolved identity coverage is incomplete

Only events with path/handle observations and no candidate key are emitted.
Ambiguous candidate identities are not emitted to the unresolved audit.

**Required correction:** create an ambiguity record for multiple paths per
generation, multiple handles per raw path, unknown object type, missing close,
unresolved outcome, and path-only observations.

### 5. Resume writes are not crash-atomic

The runner rewrites metadata, failures, and unresolved JSONL files at the end.
An interruption during this rewrite can leave an inconsistent manifest even
though per-sample event files are separate.

**Required correction:** use temporary files plus atomic rename, and record a
per-sample completion manifest before considering a sample resumable.

### 6. The merged view is not serialized

The runner records the merged event count but writes only primary event JSONL.
The deterministic merged ordering recipe is metadata, not a replayable merged
stream.

**Required correction:** either serialize a separate merged view or remove the
claim that the output contains both event views.

## Event-schema information-loss review

The schema currently preserves raw call arguments, API/status/return fields,
process provenance, and path/handle observations. Future feature extraction
could still lose:

- argument multiplicity when duplicate argument names occur;
- the distinction between raw `value` and `pretty_value` if only normalized
  values are retained;
- exact source ordering across processes;
- timestamp parse failures and timezone/format metadata;
- process-level metadata not copied into every derived feature;
- operation outcome uncertainty;
- multiple path aliases and path argument names;
- non-file object type evidence;
- the distinction between handle generations and confirmed kernel objects.

Feature extraction must retain a source event key consisting of sample ID,
report path, process index, process ID, process-call position, and call ID.
No feature should replace candidate identity with a confirmed-file label.

## Recommendation

The pipeline is **not ready for full-dataset processing for file identity or
damage measurement**. The streaming parser and provenance design are usable,
and the 20-report experiment is reproducible, but the generic handle
classification and incomplete ambiguity accounting must be corrected first.
No Phase 2 implementation should begin until those corrections and a
file-specific reliability rerun are complete.
