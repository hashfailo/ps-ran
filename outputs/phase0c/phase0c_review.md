# Phase 0C Event and Handle Audit

This is an observational audit. It does not infer a global event order or calculate damage.

## Benign selection

- `benign/6d14916cc273aba32bffcc115c2ec71614e61a6b95d5c3f8cde7c64a9e4481ac/report.json` — 743114 bytes
- `benign/8130d90665602a085f2c1284729c891330caae568cffe08be454af20d1b0bcef/report.json` — 743884 bytes
- `benign/cc0d4c85639dd5e8d68c4b356c9dcf9c501bae0190a08376bced2bcc85e2cf79/report.json` — 747240 bytes
- `benign/5cd37ffb582d6b9366f05a3268afc86f65efea3b2ad6c6856458416919d32d33/report.json` — 757318 bytes
- `benign/896baff0131eff425f4897b19f64734302baa32386244b95cffc0ec14f122075/report.json` — 763885 bytes
- `benign/ac8eccff20d0b4df5df77c63b8cb403ceea0d54ff172459cc7046135dde6cc95/report.json` — 52134517 bytes
- `benign/6cbcd7e7544c5878c07382499440c4878b5da4c8b2c64bc9d81f1a2686330b0f/report.json` — 58132429 bytes
- `benign/85bc7bfb6ca93ce864a112849afbb090b2b4a47e1fd66caa332fecfdaf145073/report.json` — 70446550 bytes
- `benign/04785b45f5e89cf98a45f917948826b63d2f9bc155d291544626f5b8b9c01318/report.json` — 128998372 bytes
- `benign/3bc839b933d9c40a8b8d25b415c1037ba4a47009bf3c4e3a3d4c26554b7d4898/report.json` — 132397903 bytes

Inspected 10 reports, 438977 calls.

## Ransomware selection

- `ransomware/992dad791a523f2c0a0b5a74c08e5573905f301d8891db0ed6e885face9ef0e2/report.json` — 101327 bytes
- `ransomware/9704a4959ec0edb5b82732944be3665e80ed974dec17ab401545ee21069da08d/report.json` — 101355 bytes
- `ransomware/7124f6f197e503f77b3bbb136391b12d79a0e248e697506184aaf19b2df8eb7e/report.json` — 127121 bytes
- `ransomware/8575dcf7c67612b4d1fc1315bb19318f06bb5abdc6341890e251eb303e386db7/report.json` — 127182 bytes
- `ransomware/4ae6519e0d6a7aaf9b684497763257e3a752ef0b31b4ba31afb9aecd1af59d9a/report.json` — 127418 bytes
- `ransomware/a245bb21af350757ae0eebbd3e8a13332f48a02393cf508e2668835cc98e6dc6/report.json` — 161875321 bytes
- `ransomware/b2493a580153291b69ca23190d00a00b1220cd0aadf469b3974fdaa726516649/report.json` — 187176510 bytes
- `ransomware/a1d99da15a8902431ab728f50cc47294cdb18fa204d4343f42e49fc84d44bed6/report.json` — 188248346 bytes
- `ransomware/7d9380fb533f6af97982464579db90dcffe42067d07d570a9857f4b0e5d37862/report.json` — 199455153 bytes
- `ransomware/54412886df7c047a42393e1e0f509da55a27c6b953a9a80b2f18b8ae78628deb/report.json` — 315944982 bytes

Inspected 10 reports, 1035654 calls.

## Aggregate observations

### Benign

- 60 processes and 438977 calls.
- 33967 exact call-ID overlaps across processes were observed; 396 process-range overlap pairs were observed.
- 396 stored-process-order ID restart/overlap candidates were observed; this is not proof of chronological ID resets.
- 0 duplicate IDs occurred within processes. 0 processes had a decrease in stored ID order.
- 0 timestamp parse failures occurred, and 0 processes had a within-process timestamp decrease.
- 196 cross-process timestamp tie rows were retained as ambiguous.
- 6105 handle-reuse observations were recorded; 0 processes had a handle reference after an `NtClose` in stored call order.

### Ransomware

- 218 processes and 1035654 calls.
- 125121 exact call-ID overlaps across processes were observed; 6724 process-range overlap pairs were observed.
- 6724 stored-process-order ID restart/overlap candidates were observed; this is not proof of chronological ID resets.
- 0 duplicate IDs occurred within processes. 0 processes had a decrease in stored ID order.
- 0 timestamp parse failures occurred, and 0 processes had a within-process timestamp decrease.
- 3453 cross-process timestamp tie rows were retained as ambiguous.
- 27680 handle-reuse observations were recorded; 0 processes had a handle reference after an `NtClose` in stored call order.

### `NtSetInformationFile` observations

- `14 (FilePositionInformation)` — 12719 observations
- `19 (FileAllocationInformation)` — 64 observations
- `20 (FileEndOfFileInformation)` — 83 observations
- `23 (FilePipeInformation)` — 6 observations
- `30 (FileCompletionInformation)` — 27 observations
- `36 (FileTrackingInformation)` — 7 observations
- `4 (FileBasicInformation)` — 840 observations
- `41 (FileIoStatusBlockRangeInformation)` — 17 observations
- `64` — 62 observations
- `65` — 11 observations
- `74` — 6 observations

These are raw observed values only; no value is classified as damaging.

## Observations

- Process-level IDs, timestamps, gaps, duplicate timestamps, and monotonicity are in the CSV outputs.
- `ambiguous_events.csv` records timestamp ties across processes without ordering them.
- `handle_mapping_audit.csv` scopes handle/path associations to one process and reports post-`NtClose` references and reuse observations.
- `phase0c_summary.json` records all selected paths, sizes, per-report details, and `NtSetInformationFile` classes.

## Limitations and unresolved questions

- IDs and timestamps are not treated as chronological truth; ties, duplicate IDs, and traversal-order effects remain unresolved.
- `NtClose` may refer to non-file handles, so post-close observations are call-sequence evidence only.
- A handle-to-path association is based only on available argument fields; absence of a path is not evidence that no path exists.
- Handle reuse and cross-process identity require further CAPE-specific validation.
- No APIs were classified as damaging and no damage was calculated.
