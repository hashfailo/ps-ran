# Phase 1 CAPE Instrumentation and Argument Semantics Audit

## Scope and method

This was a read-only investigation. It did not rerun the Phase 1 pipeline,
process the full dataset, or modify source code, existing outputs, Phase 0
artifacts, or raw reports.

The investigation used:

- all 20 reports in `outputs/phase0c/phase0c_summary.json`;
- the corresponding original reports under
  `/path/to/EN2025`;
- preserved corrected Phase 1 JSONL event records; and
- public capemon source code for the CAPE monitor and its logging formatter.

The raw reports were inspected independently of the project parser. Counts
below are observations from this fixed 20-report selection, not full-dataset
statistics.

## CAPE provenance

Every selected report contains:

```text
info.version = "2.4-CAPE"
info.package = "exe"
info.machine.platform = "windows"
info.machine.name = "cuckoo1"
```

The report top-level structure consistently includes `behavior`, `debug`,
`CAPE`, and `info`. The `CAPE` object contains `payloads` and/or `configs`;
the `debug` object contains `log` and `errors`. No selected report exposes a
capemon DLL build identifier, Git commit, monitor configuration, hook table,
argument formatter version, or analyzer source revision.

Therefore:

- the dataset identifies its report format as `2.4-CAPE`;
- it does not identify the exact capemon build or CAPE repository commit;
- it does not expose the selected API hook implementation directly; and
- source-based conclusions below are based on the public capemon source
  currently available from `kevoreilly/capemon`, not a cryptographically
  proven exact match to the dataset's deployed monitor binary.

Relevant public source:

- [capemon README](https://github.com/kevoreilly/capemon)
- [hook_file.c](https://github.com/kevoreilly/capemon/blob/capemon/hook_file.c)
- [hook_misc.c](https://github.com/kevoreilly/capemon/blob/capemon/hook_misc.c)
- [log.h](https://github.com/kevoreilly/capemon/blob/capemon/log.h)
- [log.c](https://github.com/kevoreilly/capemon/blob/capemon/log.c)

The README identifies capemon as the monitor DLL for CAPEv2 and states that
API hooks are declared in `hooks.h`, implemented in hook-category source
files, and logged through the monitor. This is relevant provenance, but not
proof that EN2025 used the current branch revision.

## Instrumentation and serialization findings

### Capture timing

The public hook implementations call the original Windows API first and call
`LOQ_ntstatus(...)` afterward:

- `NtCreateFile`: `Old_NtCreateFile(...)`, then `LOQ_ntstatus`;
- `NtOpenFile`: `Old_NtOpenFile(...)`, then `LOQ_ntstatus`;
- `NtReadFile`: `Old_NtReadFile(...)`, then buffer/path logging;
- `NtWriteFile`: `Old_NtWriteFile(...)`, then logging;
- `NtQueryInformationFile`: original call, then logging;
- `NtSetInformationFile`: original call, then logging;
- `NtClose`: `Old_NtClose(Handle)`, then logging.

For the public source, the argument record is therefore a post-call hook
record, not a pure pre-call snapshot. This is an important distinction for
output parameters and for status/return fields.

### Output-pointer handling

The monitor logging format defines:

```text
p -> void* pointer value
P -> void**; dereference once, then log the pointed-to value
```

In `log.c`, the `P` implementation reads `*ptr` inside an exception guard and
serializes the dereferenced pointer-sized value. The `p` implementation logs
the pointer-sized value itself.

The public file hooks use these formats as follows:

```text
NtCreateFile:         "PhOiihss", FileHandle passed with P
NtOpenFile:           "PhOi",     FileHandle passed with P
NtReadFile:           "pFbl",     FileHandle passed with p
NtWriteFile:          "pFbl",     FileHandle passed with p
NtQueryInformationFile:
                       "puib",     FileHandle passed with p
NtSetInformationFile: "puiu" or "puib", FileHandle passed with p
NtClose:              "p",        Handle passed with p
```

Consequently, in the public implementation:

1. `NtCreateFile.FileHandle` and `NtOpenFile.FileHandle` are logged as the
   value stored in the `HANDLE` variable after the call, not as the address of
   the `PHANDLE` variable.
2. `NtWriteFile`, `NtReadFile`, `NtSetInformationFile`, and
   `NtQueryInformationFile` log the input `HANDLE` value directly.
3. `NtClose.Handle` logs the input object-handle value directly.
4. The CAPE JSON string representation such as `"0x000001e8"` is a
   serialization of a pointer-sized numeric value; it is not evidence that
   the value was a pointer to the output variable.

This source finding supersedes the earlier numerical-only concern that high
`NtCreateFile.FileHandle` values must be pointers. A high value in a failed
call can instead be the value read from the output variable after failure,
including an unchanged, stale, or otherwise non-handle value. The raw report
alone cannot distinguish those cases, but the public formatter explains why
the field is not necessarily the address of `FileHandle`.

### Return and status fields

The public logging function receives both:

```text
is_success
return_value
```

The `LOQ_ntstatus` macro sets `is_success` to `NT_SUCCESS(ret)` and passes
`ret` as the return value. The serialized log argument convention places:

```text
args[0] = is_success
args[1] = retval
```

The report renderer exposes these as the observed `status` boolean and
`return` string. Thus, for the public implementation:

- `status=True` means the hook classified the native return status with
  `NT_SUCCESS(ret)`;
- `return="0x00000000"` is the observed native return value for success in
  the inspected records; and
- a failed native status is recorded with `status=False` and its raw
  NTSTATUS-like hexadecimal return.

This establishes the monitor's success predicate for the public source. It
does not establish that every report was generated by that exact revision,
nor does it prove that a successful write changed file contents.

## Fixed-subset raw report evidence

All counts in this section were obtained from the original reports in the
fixed 20-report manifest. The argument entries were lists containing `name`
and `value`; the inspected handle entries had no `pretty_value`. The corrected
JSONL preserves the same raw values and normalized string values.

### API counts by class

| API | Benign calls | Benign success | Benign failure | Ransomware calls | Ransomware success | Ransomware failure |
|---|---:|---:|---:|---:|---:|---:|
| `NtCreateFile` | 7,278 | 4,558 | 2,720 | 30,786 | 23,461 | 7,325 |
| `NtOpenFile` | 5,457 | 5,305 | 152 | 33,065 | 31,758 | 1,307 |
| `NtWriteFile` | 3,241 | 3,241 | 0 | 10,074 | 10,074 | 0 |
| `NtReadFile` | 8,308 | 6,501 | 1,807 | 7,154 | 6,889 | 265 |
| `NtSetInformationFile` | 3,436 | 3,428 | 8 | 10,406 | 10,406 | 0 |
| `NtQueryInformationFile` | 12,038 | 11,148 | 890 | 25,531 | 20,292 | 5,239 |
| `NtClose` | 34,020 | 34,020 | 0 | 100,704 | 100,678 | 26 |

`NtClose` is a generic object close API. Its successful status does not
identify the closed object as a file.

### Benign example

From:

`benign/6d14916cc273aba32bffcc115c2ec71614e61a6b95d5c3f8cde7c64a9e4481ac/report.json`

```text
process=2228 position=39
NtOpenFile
  FileHandle = "0x000001e8"
  FileName   = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\"
  status=True return="0x00000000"

process=2228 position=40
NtClose
  Handle = "0x000001e8"
  status=True return="0x00000000"
```

The same value is observed after a successful open and in a subsequent close
in the same process. This is strong report-level evidence for a candidate
association and is exactly the type of association supported by the public
capemon logging code.

The same report also contains:

```text
process=2228 position=66
NtCreateFile
  FileHandle = "0x1fa8bc84fd0"
  FileName   = "C:\Windows\Microsoft.NET\Framework64\v2.0.50727\clr.dll"
  status=False return="0xffffffffc0000034"
```

The source finding changes the interpretation of this value: it should be
treated as a post-call dereferenced output-variable value from a failed call,
not declared a pointer merely because it is large. It is not evidence of a
successfully returned file handle.

### Ransomware example

From:

`ransomware/a245bb21af350757ae0eebbd3e8a13332f48a02393cf508e2668835cc98e6dc6/report.json`

```text
process=4768 position=37
NtOpenFile
  FileHandle = "0x000001e4"
  FileName   = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\"
  status=True return="0x00000000"

process=4768 position=38
NtClose
  Handle = "0x000001e4"
  status=True return="0x00000000"

process=4768 position=83
NtCreateFile
  FileHandle = "0x000001cc"
  FileName   = "C:\Users\security\AppData\Local\Temp\a245bb21af350757ae0e.exe"
  status=True return="0x00000000"

process=4768 position=84
NtQueryInformationFile
  FileHandle = "0x000001cc"
  status=True return="0x00000000"
```

This gives a strong same-process candidate association from create to query
and close. It remains a candidate association because the report does not
include a kernel object identifier or a monitor-side proof of physical file
identity.

## Create/open associations and operation evidence

From the corrected event records and the same fixed selection, exact-value
associations by stored process order were observed at these scales:

| Class | Create/open observations | Create/open status true | Create/open status false | Any later operation or close | Failed create/open with later operation or close |
|---|---:|---:|---:|---:|---:|
| Benign | 12,735 | 9,863 | 2,872 | 7,911 | 27 |
| Ransomware | 63,851 | 55,219 | 8,632 | 50,882 | 110 |

These are not proof that each value was a valid handle. They show that:

- successful output values often match later input-handle values or close
  values;
- failed output observations can also be equal to later observations, so
  raw equality must not override status evidence; and
- process-scoped matching and generation separation remain useful as
  candidate reconstruction, but not as confirmed object identity.

The public source strengthens the interpretation of successful create/open
values: after a successful native return, the output `PHANDLE` is
dereferenced, and the resulting value is logged. It also strengthens the
interpretation of operation and close values: those hooks log input handles
after calling the original APIs.

## Evidence classification

### Confirmed by public instrumentation source

1. The public capemon `NtCreateFile` and `NtOpenFile` hooks call the original
   API before logging.
2. Their `FileHandle` arguments use the `P` formatter, which dereferences a
   `PHANDLE` once before serialization.
3. The public operation hooks use the `p` formatter for input `HANDLE`
   values.
4. The public `NtClose` hook uses the `p` formatter and accepts any object
   handle.
5. `LOQ_ntstatus` derives the status boolean with `NT_SUCCESS(ret)` and
   records the native return value separately.

### Strongly supported by report observations

1. The EN2025 records contain ordinary-looking same-process handle values
   such as `0x000001e8`, which match later close observations.
2. Successful create/open output values and later operation input values
   repeatedly share exact strings within a process.
3. Benign and ransomware reports exhibit the same serialization pattern and
   the same classes of lifecycle association.
4. The fixed reports support process-scoped candidate reuse: a value can be
   closed and later observed again under a new stored-order generation.

### Candidate only

1. A create/open value matched to an operation or close is a candidate
   handle-lifetime association.
2. A path attached to a handle is candidate path evidence.
3. A successful `NtWriteFile` or `NtSetInformationFile` is a successful API
   call observation, not proof of changed file contents or damage.
4. A successful `NtClose` is a successful close of an object handle, not proof
   that the object was a file.

### Unresolved

1. The exact capemon commit and monitor binary used for EN2025 are not
   present in the reports.
2. The report renderer's exact version and any dataset-specific modifications
   are not available locally.
3. Failed create/open output values are not guaranteed to be initialized,
   valid handles, or reusable handle-table values.
4. The report does not expose a kernel file-object identifier, file ID, or
   monitor-side handle-type proof.
5. Equal handle values across separate generations do not prove equal physical
   file identity.

## Implications for the corrected handle tracker

The tracker’s API-specific mapping is substantially supported by the public
instrumentation:

- `NtWriteFile.FileHandle`, `NtReadFile.FileHandle`,
  `NtSetInformationFile.FileHandle`, and
  `NtQueryInformationFile.FileHandle` are input-handle observations.
- `NtClose.Handle` is an input object-handle observation and must remain
  conditional on an established file candidate.
- `NtCreateFile.FileHandle` and `NtOpenFile.FileHandle` are post-call
  dereferenced output values in the public monitor, not output-variable
  addresses.

However, the tracker currently creates candidate generations from
create/open observations without requiring the observed status to be true.
That means failed output values can still seed candidate generations. The
public source does not support treating those failed values as returned file
handles. Existing generation totals must therefore remain labeled
**candidate generations**, not confirmed file-handle lifetimes.

The existing process scoping and generation separation remain appropriate
for an observational candidate layer. They do not establish physical file
identity, object type, or successful file modification.

## Recommendation for the research objective

EN2025 remains **suitable for the research objective as an observational
candidate-evidence dataset**, because:

- reports identify `2.4-CAPE`;
- public capemon source explains post-call argument capture and
  `PHANDLE` dereferencing;
- successful create/open values can be associated with later input-handle and
  close observations; and
- status and raw return values are preserved.

EN2025 is **not yet sufficient for confirmed distinct-file damage
measurement** using the current tracker. Before Phase 2, the pipeline should
at minimum separate successful from failed create/open output observations
and preserve failed observations as unresolved evidence rather than allowing
them to seed file generations. It should also retain the explicit
candidate/uncertain labels and avoid interpreting `NtClose` as file-specific.

No implementation change is made by this audit. The recommended correction is
an implementation task for a later approved change, not a conclusion that the
existing outputs are invalid. The existing outputs should be retained and
reinterpreted as candidate observations.
