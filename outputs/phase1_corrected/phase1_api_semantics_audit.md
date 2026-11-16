# Phase 1 Corrected API Argument Semantics Audit

## Scope and method

This was a read-only audit. It did not rerun the pipeline or modify source
code, existing outputs, Phase 0 artifacts, or raw reports. The audit inspected
the already selected 20-report Phase 0C subset and its preserved canonical
event JSONL, and independently streamed the corresponding original CAPE
`report.json` files to inspect raw arguments.

The corrected summary reports:

- 1,474,631 events;
- 223,031 observations classified by the pipeline as file-handle
  observations; and
- 44,792 handle generations (`3,882` benign and `40,910` ransomware).

The event records preserve `arguments_raw`, `arguments_normalized`, raw
`value`, optional `pretty_value`, status, return, process ID, process-call
position, and API provenance. In the inspected file-handle examples,
arguments were CAPE argument-list entries with string values and no
`pretty_value`; no nested handle value or alternate metadata form was found.

## Documented Windows semantics

The relevant Windows Native API declarations distinguish pointers from
handles:

| API | Documented parameter | Documented role |
|---|---|---|
| `NtCreateFile` | `[out] PHANDLE FileHandle` | Pointer to a `HANDLE` variable that receives a file handle. The call returns an `NTSTATUS`; the parameter is not itself declared as an input handle. |
| `NtOpenFile` | `[out] PHANDLE FileHandle` | Pointer to a `HANDLE` variable that receives a handle to the opened file, directory, device, or volume. |
| `NtWriteFile` | `[in] HANDLE FileHandle` | Input handle to the file. |
| `NtReadFile` | `[in] HANDLE FileHandle` | Input handle to the file. |
| `NtSetInformationFile` | `[in] HANDLE FileHandle` | Input handle to the file object whose information is changed. |
| `NtQueryInformationFile` | `[in] HANDLE FileHandle` | Input handle to a file object. |
| `NtFlushBuffersFile` | `[in] HANDLE FileHandle` | Input handle to the file. |
| `NtQueryEaFile` | `[in] HANDLE FileHandle` | Input handle to the file whose extended attributes are queried. |
| `NtSetEaFile` | `[in] HANDLE FileHandle` | Input handle to the file whose extended attributes are set. |
| `NtClose` | `[in] HANDLE Handle` | Input handle to an object of any type, not specifically a file. |

Primary Microsoft documentation consulted:

- [NtCreateFile](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntcreatefile)
- [NtOpenFile](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntopenfile)
- [NtWriteFile](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntwritefile)
- [NtReadFile](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntreadfile)
- [NtSetInformationFile](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntsetinformationfile)
- [NtQueryInformationFile](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryinformationfile)
- [NtClose](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntclose)

The key distinction is that `NtCreateFile` and `NtOpenFile` receive a
`PHANDLE`, while later file operations receive a `HANDLE`. A tracer may
choose to record a dereferenced output value, the address of the output
variable, or another instrumentation representation. The CAPE field name
`FileHandle` alone does not establish which representation was captured.

## Raw CAPE observations

### Successful handle-like values

Representative benign raw calls from
`benign/6d14916cc273aba32bffcc115c2ec71614e61a6b95d5c3f8cde7c64a9e4481ac/report.json`:

```text
process_id=2228 position=39
NtOpenFile FileHandle="0x000001e8"
status=True return="0x00000000"
FileName="C:\Windows\Microsoft.NET\Framework64\v4.0.30319\"

process_id=2228 position=40
NtClose Handle="0x000001e8"
status=True return="0x00000000"

process_id=2228 position=67
NtCreateFile FileHandle="0x000001e4"
status=True return="0x00000000"
FileName="C:\Windows\Microsoft.NET\Framework64\v2.0.50727\mscorwks.dll"

process_id=2228 position=68
NtClose Handle="0x000001e4"
status=True return="0x00000000"
```

These are strong candidate matches. The same raw string is observed in the
same process in a successful open/create and a later close. This supports
candidate handle tracking, but it does not prove that CAPE captured the
kernel-returned value rather than a value produced by its instrumentation.

Representative operation observations use the same representation:

```text
NtQueryInformationFile FileHandle="0x000001dc"
NtReadFile             FileHandle="0x000001d8"
NtWriteFile            FileHandle="0x000003c8"
NtSetInformationFile   FileHandle="0x00000358"
```

The operation calls also carry `HandleName` strings in the inspected reports.
The documented signatures make these operation parameters input handles, so
their semantics are materially stronger than the create/open output
parameters, subject to CAPE capture fidelity.

### Pointer-like and failed create/open values

The same benign report contains:

```text
process_id=2228 position=66
NtCreateFile FileHandle="0x1fa8bc84fd0"
status=False return="0xffffffffc0000034"
FileName="C:\Windows\Microsoft.NET\Framework64\v2.0.50727\clr.dll"

process_id=2228 position=78
NtCreateFile FileHandle="0x1fa8bc40000"
status=False return="0xffffffffc0000034"
FileName="C:\Users\security\AppData\Local\Temp\1784.exe.config"
```

The high values are consistent with addresses or pointers rather than ordinary
user-mode handle-table values, and the calls failed. This is not proof of the
exact CAPE instrumentation rule, but it is direct evidence that the field
cannot safely be treated as an actual returned file handle solely because its
argument name is `FileHandle`.

The ransomware subset contains the same pattern, for example:

```text
report=ransomware/a245bb21af350757ae0eebbd3e8a13332f48a02393cf508e2668835cc98e6dc6/report.json
process_id=2708 position=67
NtCreateFile FileHandle="0x14c373f49f0"
status=False return="0xffffffffc0000034"

process_id=3416 position=13
NtOpenFile FileHandle="0x7ffe0000003d"
status=False return="0xffffffffc000003a"
```

The audit therefore classifies create/open `FileHandle` values as:

- **confirmed documented role:** an output parameter whose pointed-to
  variable receives a handle;
- **observed CAPE value:** candidate handle-like or pointer-like string;
- **actual returned handle:** not confirmed from the report field alone;
- **safe generation input:** only after independent evidence establishes that
  the value is the returned handle and the operation succeeded.

## API mapping validation

| Mapped API | CAPE evidence in 20 reports | Actual/pointer classification | Safe for current generation tracking? |
|---|---:|---|---|
| `NtCreateFile.FileHandle` | 38,064 calls | Documented output pointer (`PHANDLE`); CAPE values include successful small values and failed high/pointer-like values | **No, not unconditionally.** Treat as an attempted output observation; require success-aware interpretation and representation validation. |
| `NtOpenFile.FileHandle` | 38,522 calls | Documented output pointer (`PHANDLE`); successful values commonly match later closes, but failed calls also contain high values | **No, not unconditionally.** Same qualification as `NtCreateFile`. |
| `NtWriteFile.FileHandle` | 13,315 calls | Documented input `HANDLE`; CAPE values are handle-like strings and repeatedly match close/create values in some processes | **Candidate use only.** Safe as an observed input-handle association, not proof of physical identity or successful write. |
| `WriteFile.FileHandle` | 0 calls in this subset | Documented Win32 input `HANDLE` if present | **Not validated by this subset.** Mapping remains untested evidence. |
| `NtReadFile.FileHandle` | 15,462 calls | Documented input `HANDLE`; examples match repeated reads and candidate closes | **Candidate use only.** |
| `ReadFile.FileHandle` | 0 calls in this subset | Documented Win32 input `HANDLE` if present | **Not validated by this subset.** |
| `NtSetInformationFile.FileHandle` | 13,842 calls | Documented input `HANDLE`; examples include `HandleName` | **Candidate use only.** |
| `NtQueryInformationFile.FileHandle` | 37,569 calls | Documented input `HANDLE` to a file object | **Candidate use only.** |
| `NtFlushBuffersFile.FileHandle` | 0 calls in this subset | Documented input `HANDLE` | **Not validated by this subset.** |
| `NtQueryEaFile.FileHandle` | 0 calls in this subset | Documented input `HANDLE` | **Not validated by this subset.** |
| `NtSetEaFile.FileHandle` | 0 calls in this subset | Documented input `HANDLE` | **Not validated by this subset.** |
| `NtClose.Handle` | 134,724 calls | Documented input `HANDLE` to any object type | **Only conditionally.** It is suitable as a close observation after object type and generation are independently established; it is not file-specific by signature. |

The explicit mapping is directionally correct for operation APIs, but it
currently gives `NtCreateFile.FileHandle` and `NtOpenFile.FileHandle` the same
generation-creating treatment as if they were confirmed returned handles.
That is not justified by the documented parameter declaration.

## Matching and lifecycle evidence

Across the corrected event outputs, exact same-process, stored-position
matches were observable:

| Class | Create/open observations | Status true | Status false | Any later operation or close | False-status observations with later operation/close |
|---|---:|---:|---:|---:|---:|
| Benign | 12,735 | 9,863 | 2,872 | 7,911 | 27 |
| Ransomware | 63,851 | 55,219 | 8,632 | 50,882 | 110 |

These counts are exact-value associations in the stored process-call stream,
not proof that the create/open call returned the value or that the later call
used a valid file object. The false-status matches are especially important:
they demonstrate that raw equality can connect a failed output-parameter
observation to a later operation or close.

A benign reuse example is:

```text
NtOpenFile  position 39  FileHandle=0x000001e8  success
NtClose     position 40  Handle=0x000001e8       success
NtOpenFile  position 65  FileHandle=0x000001e8  success
NtClose     position 71  Handle=0x000001e8       success
```

The corrected tracker keeps these as generations `g0` and `g1`, scoped to
process `2228`. A ransomware example similarly shows
`0x000001cc` in process `4768` across create/query/close and a later reuse.
These support process-local handle-table reuse as a candidate explanation,
but do not validate the pointer-versus-output representation for all
create/open observations.

The audit found no evidence that process IDs were merged across reports or
that a candidate key crossed process scope. The generation separation logic
is deterministic for the stored order. However, deterministic generation
assignment does not repair semantically ambiguous input values.

For the descriptive “high/pointer-like” counts below, the audit used the
simple numeric heuristic `int(value, 16) > 0x100000` for values represented as
hexadecimal strings. This is not a Windows validity test and is not proposed
as an implementation rule; it only quantifies the visibly different CAPE
representations.

## Implications for reported measurements

The 223,031 file-handle observations include explicit operation inputs,
`NtClose` inputs, and create/open output-parameter observations. They should
not be described as 223,031 confirmed actual file handles.

The 44,792 generations include generations initiated from create/open
attempts, including failed attempts. In the event outputs, the first
create/open observation for 3,805 benign generations and 40,658 ransomware
generations was available for inspection; among those:

| Class | Generations inspected | First create/open status false | First value high/pointer-like | Both |
|---|---:|---:|---:|---:|
| Benign | 3,805 | 177 | 87 | 87 |
| Ransomware | 40,658 | 286 | 102 | 102 |

The remaining generations were initiated by operation or close observations
without a preceding create/open observation. This makes the generation totals
candidate lifecycle counts, not counts of confirmed file objects.

## Findings by confidence

### Confirmed

1. Windows documents `NtCreateFile.FileHandle` and `NtOpenFile.FileHandle` as
   `PHANDLE` output parameters.
2. Windows documents the `FileHandle` parameters of the operation APIs as
   input `HANDLE` values.
3. Windows documents `NtClose.Handle` as a generic object handle.
4. The CAPE subset contains exact same-process value matches between
   create/open, operation, and close observations.
5. The corrected tracker preserves raw evidence, process scope, and separate
   deterministic generations.

### Strongly supported but not proven

1. Successful calls with values such as `0x000001e8` and `0x000001e4`
   represent ordinary returned/user-mode handles, because they match later
   successful closes and operations in the same process.
2. Failed calls with values such as `0x1fa8bc84fd0` and `0x7ffee2e65db8`
   are pointer-like output-variable addresses or other instrumentation
   artifacts, because they are high values and accompany failure statuses.

### Unsupported

1. A `FileHandle` argument name alone does not establish that the value is
   the actual returned handle.
2. Exact equality does not prove the same kernel file object.
3. A `NtClose` match does not prove the closed object was a file.
4. A status/return combination has not been independently validated as a
   complete success rule for CAPE's instrumentation.
5. The current audit cannot establish whether CAPE records pre-call pointers,
   post-call dereferenced outputs, or a mixture for create/open.

## Recommendation

The current tracker is **not safe to use as a confirmed file-handle or
distinct-file tracker**. It is safe only as a raw, process-scoped candidate
association layer.

Before using generations for damage measurement, the implementation should
separate:

1. documented output-pointer observations from returned-handle observations;
2. successful and unsuccessful create/open outcomes, without inventing a
   success rule;
3. uncertain CAPE representations; and
4. candidate lifecycle associations from confirmed file-object identity.

Until that correction is made, retain the existing 223,031 and 44,792 values
as audit measurements, label them as candidate observations/generations, and
do not use them as confirmed file counts, damage denominators, or labels.
