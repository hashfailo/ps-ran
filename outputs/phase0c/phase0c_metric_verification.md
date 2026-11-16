# Phase 0C Metric Verification

This report verifies the implementation and generated outputs only. It does
not validate CAPE semantics and does not infer damage or a global event order.

## 1. Call IDs

### Confirmed implementation

- For each process, `ids` contains every call's first matching ID field from
  `id`, `call_id`, or `callid`. `ids_numeric` is computed separately using
  numeric conversion.
- `unique_ids` is the number of distinct `compact(raw_id)` strings.
  `duplicate_ids = len(ids) - len(unique_ids)`. Thus duplicate IDs are
  counted as repeated raw representations after string compaction, not as
  duplicate numeric values after normalization.
- `ids_increase_monotonically` checks only numeric IDs in stored call order.
  Non-numeric IDs are skipped for decreases. `id_decreases` counts numeric
  decreases; equal adjacent numeric IDs are reported separately.
- `minimum_id` and `maximum_id` are calculated only from numeric IDs.

### What the generated CSV shows

- All 278 process rows have `ids_numeric=True`, `ids_non_numeric=0`,
  `duplicate_ids=0`, `ids_increase_monotonically=True`, and `id_decreases=0`.
- Therefore, in these selected reports, IDs were unique and monotonically
  increasing **within each process's stored call list**.
- This does not establish that IDs are chronological or globally unique.

### Cross-process comparisons

Two different metrics are present:

1. `cross_process_id_overlap_count` compares individual numeric ID values.
   The implementation groups each numeric ID by the set of process IDs that
   used it and counts distinct ID values used by more than one process.
   It is not a count of all cross-process call pairs.
2. `cross_process_id_range_overlap_pairs` compares each pair of process
   `[minimum_id, maximum_id]` ranges. It counts overlapping process ranges,
   not individual overlapping IDs.

`cross_process_id_restart_candidates_in_stored_process_order` is also a range
heuristic: for each later process in the report's stored process iteration,
it counts the pair if the later process's minimum is no greater than the
earlier process's maximum. It is not proof of an ID restart or chronology.

The summary reports 33,967 exact cross-process ID overlaps for benign reports
and 125,121 for ransomware reports. These observations are compatible with a
process-local-ID hypothesis, but do not prove it: process-local allocation,
reused/global IDs, report serialization behavior, and the CAPE schema would
need separate validation.

## 2. Timestamps

### Confirmed implementation

- The first matching timestamp field from `timestamp`, `time`, or `ts` is
  parsed as a number or ISO timestamp.
- Within each process, timestamp gaps are differences between adjacent
  successfully parsed timestamps in stored call order.
- `timestamp_resolution_min_gap` / `minimum_positive_gap` is the smallest
  positive adjacent gap observed. It is a metric name, not a demonstrated
  physical clock resolution.
- Cross-process ties are formed by exact equality of parsed floating-point
  timestamp values. A timestamp is written to `ambiguous_events.csv` when its
  distinct process-ID set has more than one process.

The generated `ambiguous_events.csv` contains one row per distinct
cross-process tied timestamp, with `calls_at_timestamp` and the participating
process IDs. It does **not** retain one row per event or event ID. Events are
not ordered within a tie. Ties occurring only within one process are captured
in process-level adjacent-duplicate counts, but are not emitted as ambiguous
cross-process rows.

All selected process rows have zero timestamp parse failures and zero
within-process timestamp decreases. The CSVs show frequent minimum positive
gaps near 0.015 seconds, while many adjacent timestamp gaps are exactly zero.
This supports millisecond-scale timestamp quantization in these observations,
but does not establish the underlying clock precision.

Events from different processes cannot currently be merged into a reliable
chronological sequence using these outputs alone. Exact timestamp ties lose
the relative order of the tied calls; `ambiguous_events.csv` also loses their
individual API names, IDs, arguments, and call positions. Non-tied timestamps
still do not resolve traversal-order and clock/serialization assumptions.

## 3. Handle reuse

The 6,105 benign and 27,680 ransomware values are **not confirmed
close-and-reuse counts**.

The exact increment is:

```text
if api == "NtCreateFile" and handle is present:
    record = handles.setdefault(handle, empty_handle())
    if record["created"] or record["operations"]:
        record["reuse_count"] += 1
    record["created"] += 1
```

Therefore `reuse_count` increments when a second or later `NtCreateFile`
observation uses a handle key that already has either a prior
`NtCreateFile` observation or a prior operation observation. It can increment
without any `NtClose`, without a new lifetime, and without a new path.

The metrics mean different things:

- **Handle observed repeatedly:** represented by multiple calls referring to
  the same extracted handle key. This is not itself `reuse_count`.
- **Multiple paths:** `path_count` is the number of distinct extracted path
  strings associated with the handle. It can be greater than one even without
  a proven lifetime transition.
- **Closed then reused:** not established by this audit. `reuse_count` does
  not require closure.
- **New file after prior lifetime:** not established. The audit has no
  lifetime segmentation and does not prove that a new `NtCreateFile` refers
  to a new kernel object.

Five concrete CSV examples:

1. Benign `6d14916c...`, process `2228`, handle `0x000001e4`: `created_count=3`,
   `reuse_count=2`, `path_count=2`, `closed_count=0`.
2. Benign `6d14916c...`, process `2228`, handle `0x1fa8bc40000`:
   `created_count=2`, `reuse_count=1`, `path_count=1`, `closed_count=0`.
3. Benign `6d14916c...`, process `2228`, handle `0x000001d8`:
   `created_count=2`, `reuse_count=1`, `path_count=2`, `closed_count=0`.
4. Benign `8130d906...`, process `2212`, handle `0x000001e4`:
   `created_count=3`, `reuse_count=2`, `path_count=2`, `closed_count=0`.
5. Benign `cc0d4c85...`, process `3472`, handle `0x000001cc`:
   `created_count=4`, `reuse_count=3`, `path_count=3`, `closed_count=0`.

The CSV does not provide a usable aggregate for “same path associated with
multiple handles”: the script builds `path_to_handles` but never exports it.

## 4. Post-close references

- `NtClose` is listed in `FILE_APIS`, but the script extracts only the
  `FileHandle` argument for all file APIs.
- A handle is added to `closed_handles` only when `api == "NtClose"` and a
  `FileHandle` value is present.
- A later file operation increments `referenced_after_close` only if its
  extracted `FileHandle` is already in that set.
- Handle dictionaries, closed-handle sets, and counters are recreated inside
  each process loop. The mapping is therefore process-scoped, as intended.
- The test is only against stored call-list order. It does not reorder by ID
  or timestamp.

Every generated handle row has `closed_count=0`, and the aggregate reports
zero post-close references. This is not evidence that no handles were closed.
It is consistent with the implementation failing to recognize the actual
`NtClose` argument shape when it is not named `FileHandle`, and with missing
or incomplete handle arguments. The script also cannot determine whether a
given `NtClose` targets a file handle; its own CSV note correctly warns about
non-file handles.

## 5. Overall validity and implementation issues

Confirmed limitations affecting conclusions:

1. The “handle reuse” label is misleading. It measures repeated
   `NtCreateFile` use of an already-known handle key, not handle lifetime
   reuse.
2. `NtClose` detection is likely incomplete because only `FileHandle` is
   inspected. No alternate close-handle field is checked.
3. Handle mappings are built only from file APIs carrying `FileHandle`;
   operations with other argument conventions are omitted.
4. `path_to_handles` and `operations_by_handle` are built but not exported,
   so same-path/multiple-handle conclusions cannot be reconstructed fully from
   the CSV.
5. Cross-process range “restart” counts depend on stored process iteration
   order and are heuristics, not event-order findings.
6. ID uniqueness uses compacted raw representations while monotonicity uses
   numeric conversion; mixed representations could produce inconsistent
   results, although all generated rows here were numeric.
7. Timestamp ties are exact parsed-float ties and the ambiguous CSV is a
   timestamp-group summary, not an event-level preservation of all tied calls.
8. Timestamp gap statistics are within-process only and should not be called
   a global timestamp resolution.

The outputs support the narrower statement that selected process call lists
have numeric, unique, increasing IDs and monotonic within-process timestamps,
while cross-process IDs and timestamps overlap or tie substantially. They do
not support a reliable global order, confirmed handle lifetimes, or damage
extraction.
