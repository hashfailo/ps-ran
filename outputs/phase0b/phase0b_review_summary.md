# Phase 0B Review: Raw EN2025 Report Structure

## Scope and sample selection

The audit inspected six reports, selected as the lexicographically first three
`report.json` paths in each class:

- **Benign:** `001b7fa6.../report.json`, `00a71718.../report.json`,
  `00fb683d.../report.json`
- **Ransomware:** `0085f137.../report.json`, `01626411.../report.json`,
  `0178461a.../report.json`

The files contain 1, 2, 3, 3, 1, and 4 processes respectively. API-call totals
are 2,617, 5,159, 24,267, 21,339, 4,047, and 41,469. The per-class totals in the audit
are **32,043 benign** and **66,855 ransomware**, for **98,898 total calls**.

All six reports contained `info`, `behavior`, and `signatures`. `dropped` was
present in two reports: benign `00fb683d...` and ransomware `0178461a...`.

## Frequent APIs and categories

Aggregated over the three reports in each class, the most frequent APIs were:

- **Benign:** `NtQueryKey` (4,302), `NtQueryValueKey` (3,736), `NtClose`
  (3,704), `NtOpenKeyEx` (3,578), `RtlSetCurrentTransaction` (1,869),
  `NtQueryInformationToken` (1,546), and
  `LdrGetProcedureAddressForCaller` (1,311).
- **Ransomware:** `CryptCreateHash` (9,998), `NtReadVirtualMemory` (9,998),
  `CryptHashData` (8,570), `CryptDestroyHash` (4,999),
  `NtAllocateVirtualMemory` (4,434), `NtFreeVirtualMemory` (3,735), and
  `NtClose` (1,841).

Most frequent categories by class were:

- **Benign:** `registry` (13,711), `system` (6,718), `process` (6,122),
  `misc` (2,584), and `filesystem` (1,178).
- **Ransomware:** `crypto` (28,878), `process` (21,636), `filesystem` (6,266),
  `system` (5,430), and `registry` (2,549).

These are frequencies in the inspected sample, not class-wide estimates.

## Call fields and event ordering

All 98,898 observed calls had timestamps, IDs, `repeated`, `status`, `return`,
and `arguments` according to the structure summary. All timestamps parsed
successfully.

Call IDs were numerically increasing for almost all adjacent calls in the
stored traversal, but they were unique in only two of six reports:

- Unique IDs: benign `001b7fa6...` and ransomware `01626411...`
- Duplicate IDs: benign `00a71718...` (1,040 duplicates),
  benign `00fb683d...` (295), ransomware `0085f137...` (357), and
  ransomware `0178461a...` (7,239)

The audit recorded cross-process adjacent ID comparisons in four reports.
Every recorded cross-process comparison decreased rather than increased:
one in `00a71718...`, two in `00fb683d...`, two in `0085f137...`, and
three in `0178461a...`. No such comparison was recorded for the two reports
with one process. This is evidence against treating IDs as a reliable global
chronological order, but it does not establish what the IDs mean.

Timestamps were monotonic within each process in all six reports. When calls
from all processes were combined in the stored traversal, timestamps were
monotonic in two reports and had violations in four:

- Violations: one in `00a71718...`, two in `00fb683d...`, two in
  `0085f137...`, and two in `0178461a...`
- No violations: `001b7fa6...` and `01626411...`

Every report had calls sharing timestamps. The audit recorded 40, 45, 485,
821, 30, and 1,678 shared-timestamp groups in the six reports respectively.
Consequently, timestamps often do not provide a unique order.

Adjacent ID/timestamp comparisons mostly had equal timestamps rather than a
direction to compare. The audit recorded one disagreeing direction in
`0178461a...`; the other reports recorded no disagreeing direction. These
observations require further investigation before defining a global event
ordering rule.

## File-related APIs and arguments

The selected reports contained these target file APIs:

- `NtCreateFile`: 263 benign calls and 809 ransomware calls. Observed argument
  names include `FileHandle`, `DesiredAccess`, `FileName`,
  `CreateDisposition`, `ShareAccess`, `FileAttributes`, `ExistedBefore`, and
  `StackPivoted`.
- `NtSetInformationFile`: 24 benign calls and 959 ransomware calls. Observed
  names are `FileHandle`, `HandleName`, `FileInformationClass`, and
  `FileInformation`.
- `NtWriteFile`: 75 benign calls and 999 ransomware calls. Observed names are
  `FileHandle`, `HandleName`, `Buffer`, `Length`, and `Status`.
- `CopyFileW`: one ransomware call, with `ExistingFileName`, `NewFileName`,
  and `ExistedBefore`.

No observations for the other requested target names (`WriteFile`,
`CreateFile`, `MoveFileExW`, `MoveFileW`, `DeleteFileW`, `NtDeleteFile`,
`SetFileAttributesW`, or `CopyFileA`) appear in the generated file-API output.
This means they were not present in the selected target-API observations, not
that they are absent from EN2025.

Observed `NtSetInformationFile` values included:

- `4` — `FileBasicInformation`
- `14` — `FilePositionInformation`
- `23` — `FilePipeInformation`
- `30` — `FileCompletionInformation`
- `41` — `FileIoStatusBlockRangeInformation`
- `64` and `74` — numeric values without a recorded `pretty_value`

Bounded examples show Windows paths such as
`C:\Windows\Microsoft.NET\Framework64\v2.0.50727\clr.dll`,
`C:\Users\security\AppData\Local\Temp\232config.ini`,
`C:\KRAB-DECRYPT.txt`, and
`C:\Users\security\AppData\Roaming\explorer.exe`. Device-style values such as
`\Device\Serial0` and `\Device\NamedPipe\wkssvc` also occur.

File handles are represented as hexadecimal strings such as `0x00000270`,
`0x000004bc`, and `0x000003f4`. Examples include successful returns
`0x00000000` with `status: true`, failed creates returning
`0xffffffffc0000034` or `0xffffffffc0000033` with `status: false`, and
`CopyFileW` returning `0x00000001` with `status: true`. `repeated` was `0` in
the displayed examples. Buffers were redacted by the audit; lengths such as
`2`, `27`, `226`, and `8110` were retained.

## Errors, limitations, and follow-up

- The four generated outputs report no per-report processing errors.
- This is a six-report structural sample, not a representative estimate for
  all 919 benign and 611 ransomware reports.
- The audit records field presence and bounded examples; it does not validate
  Windows API success semantics, infer damage, or classify operations as
  damaging.
- Duplicate IDs, cross-process decreases, timestamp ties, and combined
  timestamp violations mean a global chronological sequence is not established.
- `status`, `return`, and `repeated` observations are descriptive only.
- Argument buffers were redacted/truncated, and long paths were truncated.
- Further work should compare more reports and inspect CAPE process/call
  identity semantics before implementing any event ordering or damage logic.
