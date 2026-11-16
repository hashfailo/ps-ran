# Phase 0C2 Handle Lifecycle Audit

Exactly the 20 report paths from Phase 0C were analyzed. Sequences use stored process-call positions only; timestamps were retained but never used to break ties. These are candidate sequences, not confirmed kernel handle lifetimes.

## Benign

- Reports: 10
- Processes: 60
- Calls: 438977
- `create_close`: 9133
- `close_create`: 1507
- `create_close_create`: 1004
- `multiple_closes`: 29049
- `operations_between_create_close`: 872
- `NtCreateFile` with `status=false` and `FileHandle` present: 2720

## Ransomware

- Reports: 10
- Processes: 218
- Calls: 1035654
- `create_close`: 32744
- `close_create`: 14476
- `create_close_create`: 12463
- `multiple_closes`: 72831
- `operations_between_create_close`: 14905
- `NtCreateFile` with `status=false` and `FileHandle` present: 7325

## Interpretation and limitations

- `create_close` means the same normalized `(process_id, handle)` key was observed in a create and a later close in stored process-call order.
- `close_create` means a close preceded a later create for that key; it does not prove reuse because an earlier lifetime may be outside the selected call sequence or the fields may not identify the same object.
- `create_close_create` is a subset of `close_create` where the same stored process sequence also has a preceding create.
- `multiple_closes` counts a close after another close without an intervening create in stored order.
- `operations_between_create_close` records `NtWriteFile` and `NtSetInformationFile` events between the latest create and close.
- Different paths are reported as observations only. They do not prove different file objects because aliases and normalization are unresolved.
- `status`, `return`, `FileHandle`, `CreateDisposition`, and `ExistedBefore` combinations are descriptive; no success rule is applied.
- No damage extraction or damaging-API classification was performed.
