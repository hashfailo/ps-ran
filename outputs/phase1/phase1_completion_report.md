# Phase 1 Completion Report

## Scope

Phase 1 was implemented and run on exactly the 20 reports recorded in
`outputs/phase0c/phase0c_summary.json`: 10 benign and 10 ransomware reports.
No full-dataset run was performed. Raw dataset files and prior Phase 0
artifacts were not modified.

## Implemented modules

- `scripts/phase1/models.py`: event record with raw and derived fields.
- `scripts/phase1/cape_parser.py`: streaming `ijson` CAPE ingestion.
- `scripts/phase1/event_normalizer.py`: API, path, handle, and operation labels.
- `scripts/phase1/handle_tracker.py`: process-scoped candidate handle generations.
- `scripts/phase1/stream_reconstructor.py`: primary and deterministic merged views.
- `scripts/phase1/storage.py`: JSONL I/O and explicit Parquet capability check.
- `scripts/phase1/run_phase1.py`: resumable validation runner and provenance.
- `tests/phase1/test_pipeline.py`: focused unit tests.

## Storage and dependencies

`ijson 3.6.0` was available and used. PyArrow, fastparquet, and NumPy were
unavailable, so canonical output is JSONL; the summary explicitly reports
Parquet as unavailable rather than silently substituting another format. NPY
was not used because event streams are variable length.

The event files contain complete `arguments_raw` values from each parsed CAPE
call. Derived representations are separate fields and may be bounded only in
future debug outputs; canonical raw event records are not truncated.

## Tests and serialization

The Phase 1 unit suite passed 4/4 tests:

- primary stored process-call ordering versus deterministic timestamp view;
- nested CAPE argument preservation and JSONL round-trip;
- handle creation, close, reuse candidates, and process separation;
- missing and malformed argument handling.

The validation run also round-tripped every event JSONL file by rereading it
and comparing the event count. All 20 reports passed this check.

## Validation statistics

| Class | Reports | Events | Candidate handle generations | Post-close references | Candidate reuse after close |
|---|---:|---:|---:|---:|---:|
| Benign | 10 | 438,977 | 10,401 | 158,316 | 2,861 |
| Ransomware | 10 | 1,035,654 | 72,798 | 250,630 | 36,860 |
| Total | 20 | 1,474,631 | 83,199 | 408,946 | 39,721 |

Other candidate observations across the subset:

- Repeated create observations: benign 9,321; ransomware 24,258.
- Operations without a preceding candidate create: benign 4,854; ransomware
  29,699.
- Close observations without a preceding candidate create: benign 2,133;
  ransomware 3,506.

These are parser observations in stored process-call order. They are not
confirmed kernel handle lifetimes, confirmed reuse, or damage measurements.

## Failures and traceability

All 20 selected reports processed successfully; `failures.jsonl` is empty.
Each event carries its sample ID, class, report path, process index, process
ID, and process-call position. Each metadata row points to its event JSONL
file. This permits every derived observation to be traced to a source sample
and event position. `unresolved_identities.jsonl` contains 54,127
path/handle observations that had no candidate identity association.

## Ordering and identity limitations

The primary event sequence is the original stored process traversal and
process-call order. The timestamp-based view is only a deterministic
reconstruction using timestamp, process index, and call position. Timestamp
ties and prior Phase 0 ordering violations mean it is not ground-truth global
chronology.

Handles are scoped to `(sample, process, normalized handle)` and split into
candidate generations after a candidate close. Paths and handles remain
candidate identity evidence. Matching handles or paths do not prove physical
file identity; multiple paths per handle, multiple handles per path, missing
paths, and incomplete arguments remain possible. Status and return fields are
preserved but no universal success semantics are inferred.

The operation labels identify observed API families only. No file damage,
successful modification, deletion, rename completion, or detector alert time
is calculated.

## Reproduction

```bash
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m scripts.phase1.run_phase1 \
  /path/to/EN2025
```

To resume an interrupted Phase 1 output directory:

```bash
.venv/bin/python -m scripts.phase1.run_phase1 \
  /path/to/EN2025 --resume
```

## Recommendation

The pipeline is suitable for a controlled review and a larger ingestion
experiment, but it is **not yet ready for damage measurement or claims of
distinct physical file counts**. Before full-dataset processing, validate
operation outcome semantics, `NtSetInformationFile` classes, path alias
handling, and detector alert-time definition. A full run should also confirm
storage capacity because the 20-report raw-preserving validation produced
approximately 2.4 GB of JSONL output.
