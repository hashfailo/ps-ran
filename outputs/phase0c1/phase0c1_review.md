# Phase 0C1 Handle Argument Audit

This audit uses exactly the 20 paths recorded by `outputs/phase0c/phase0c_summary.json`. It observes argument shapes only; it does not infer handle lifetimes, reuse, chronology, or damage.

## Coverage

- `NtClose` calls recorded: 134724
- `NtCreateFile` calls recorded: 38064
- Reports with parser errors: 0

## `NtClose`

Observed calls: 134724 across 18 reports. Argument occurrences:

- `Handle`: 134724

No `FileHandle` argument was observed for `NtClose`; the close-handle field
in these outputs is named `Handle`. The bounded examples also preserve the
process ID, call ID, timestamp, status, return value, and call position.

## `NtCreateFile`

Observed calls: 38064 across 15 reports. Argument occurrences:

- `CreateDisposition`: 38064
- `DesiredAccess`: 38064
- `ExistedBefore`: 38064
- `FileAttributes`: 38064
- `FileHandle`: 38064
- `FileName`: 38064
- `ShareAccess`: 38064
- `StackPivoted`: 38064

`FileHandle` is present in every observed `NtCreateFile` call. The bounded
examples show it as a hexadecimal argument value, while `return` is a
separate NTSTATUS-like value (for example `0xffffffffc0000034`) and `status`
is a separate Boolean field. This audit does not establish from the argument
shape alone whether `FileHandle` is an output handle, an input/placeholder,
or a monitor-reported result.

## `NtWriteFile`

Observed calls: 13315. Argument occurrences:

- `Buffer`: 13315
- `FileHandle`: 13315
- `HandleName`: 13315
- `Length`: 13315
- `Status`: 54

## `NtSetInformationFile`

Observed calls: 13842. Argument occurrences:

- `FileHandle`: 13842
- `FileInformation`: 13842
- `FileInformationClass`: 13842
- `HandleName`: 13842

## Observed handle representation

The JSON outputs contain bounded per-call arguments, including all argument names, status, return, process ID, call ID, and timestamp. Compare `NtClose` argument names with `NtCreateFile` fields directly; this audit intentionally does not assume that `FileHandle` is the closed or newly created object.

For comparison, `NtWriteFile` and `NtSetInformationFile` use `FileHandle`;
`NtWriteFile` also uses `HandleName`, while `NtSetInformationFile` uses
`HandleName` and `FileInformationClass`. In the selected calls,
`NtClose` uses `Handle`, not `FileHandle`.

An offline comparison of the bounded output records found exact values shared
between `NtCreateFile.FileHandle` and `NtClose.Handle` in multiple reports,
including create-before-close stored-call-position matches. This is evidence
that the fields can be compared as candidate identifiers, not proof that they
represent the same kernel lifetime. The audit outputs do not establish close
and later reassignment sequences.

## Lifetime-tracking implications

- A candidate tracker should first identify the actual close-handle field from the `NtClose` examples.
- It should separately identify whether `NtCreateFile` exposes an output handle, an input/placeholder handle, or only related metadata.
- Any lifetime or reuse claim requires a process-scoped sequence with a resolved create/output handle, a close event, and a later assignment to the same handle key. Repeated observations alone are insufficient.
- Missing, differently named, or non-file handle arguments remain unresolved until the bounded examples are reviewed.

The next tracker can conservatively use process-scoped `(process_id, handle)`
keys, read `NtCreateFile.FileHandle` and `NtClose.Handle` separately, preserve
stored call positions, and require an observed create → close → later create
sequence before labeling reuse. It should retain status, return, path/name,
and timestamp context and should not infer success or damage from them.
