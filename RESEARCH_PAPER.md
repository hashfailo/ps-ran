# Damage-Aware Evaluation of Streaming Ransomware Detectors

## Abstract

This study develops a reproducible, storage-constrained evaluation pipeline
for streaming ransomware detectors using the EN2025 CAPE dataset. The dataset
contains 919 benign and 611 ransomware reports. We preserve raw CAPE evidence,
retain stored process-call order as the primary sequence, and treat paths and
handles as candidate evidence rather than guaranteed physical-file identity.
The final full-dataset experiment streamed all 1,530 reports without loading a
report into memory and produced compact sample-level aggregates.

A transparent Gaussian Naive Bayes baseline was evaluated on deterministic
10%, 25%, 50%, 75%, and 100% stream prefixes. On a fixed hash-based
train/test split, ROC AUC ranged from 0.903 to 0.928 and recall ranged from
0.611 to 0.690. Ransomware reports showed substantially higher observable
write, delete, rename, and file-information activity than benign reports.
These results support early behavioral discrimination, but they do **not**
establish physical file damage, successful encryption, or distinct-file
identity. The central result is therefore a defensible observable-activity
benchmark, not a claim that the detector measures damage directly.

## 1. Research question

The project asks whether streaming behavioral detectors can distinguish
ransomware from benign activity early enough to limit observable harmful
operations. The phrase “damage-aware” is operationalized conservatively:
before an alarm checkpoint, we measure observable write/delete/rename and
file-information calls. CAPE reports alone do not prove that bytes changed,
that encryption completed, or that a path refers to one physical file.

## 2. Dataset and provenance

The EN2025 inventory contains:

| Class | Samples | Reports | Report storage | Total parsed events |
|---|---:|---:|---:|---:|
| Benign | 919 | 919 | 3.84 GiB | 3,917,169 |
| Ransomware | 611 | 611 | 18.66 GiB | 17,225,345 |
| **Total** | **1,530** | **1,530** | **21.97 GiB** | **21,142,514** |

All reports were processed from their original locations. No report, PCAP, or
earlier phase artifact was modified. The parser used `ijson` and processed one
report at a time.

The reports identify themselves as `2.4-CAPE`. The exact deployed capemon
revision is unavailable. Public capemon source supports the following
interpretation: create/open `PHANDLE` outputs are logged after dereferencing,
operation APIs log input `HANDLE` values, `NtClose` logs a generic object
handle, and the status boolean is derived from `NT_SUCCESS(ret)`. This source
evidence still does not establish physical file identity.

## 3. Evidence-preserving pipeline

### 3.1 Phase 0 inventory

`inventory_dataset.py` discovers class/sample directories and records report
and PCAP presence and report sizes using filesystem metadata only. It never
opens `report.json`.

### 3.2 Phase 1 event reconstruction

The Phase 1 pipeline:

- preserves complete raw arguments and nested argument structure;
- uses stored process-call order as the primary sequence;
- keeps timestamp ordering separate and explicitly reconstructed;
- maps file handles only for API-specific argument roles;
- preserves non-file and uncertain handles as raw observations;
- treats successful create/open generations as candidates, not confirmed files;
- separates operation-first candidates, failed/unknown output observations,
  repeated closes, post-close references, and path ambiguity.

The full experiment intentionally did not write another canonical event archive,
because the 21.1 million events would consume substantial storage. The
20-report canonical archive from Phase 1 remains available for auditability;
the full experiment writes one compact JSONL feature row per sample.

### 3.3 Reliability hardening

The lifecycle tracker was hardened before the full experiment:

- missing process IDs receive distinct process-record fallback keys and an
  explicit warning;
- failed/unknown create/open observations do not establish generations;
- a failed/unknown create/open observation invalidates the active candidate
  for subsequent operation association and emits an ambiguity record;
- repeated successful creates on an active generation are retained and marked
  ambiguous;
- operation-first generations remain separate from later successful
  create/open generations.

The unit suite passes 18/18 tests.

## 4. Features and detector

For each sample, the streaming extractor records:

- total events and processes;
- unique API count;
- file-handle observations and usable path observations;
- create/open, successful create/open, and failed create/open counts;
- reads, writes, deletes, renames, file-information calls, and closes.

Prefix features are normalized per event at 10%, 25%, 50%, 75%, and 100% of
the stored report sequence. The baseline is Gaussian Naive Bayes, trained
without third-party machine-learning dependencies. The deterministic test
split assigns a sample to test when
`sha256(sample_id) mod 5 == 0`; all other samples are training samples.
There are 1,214 training samples and 316 test samples.

This is a baseline benchmark, not a production detector. Prefix checkpoints
are not exact alarm timestamps.

## 5. Observable activity results

| Feature | Benign mean | Benign median | Ransomware mean | Ransomware median |
|---|---:|---:|---:|---:|
| Events | 4,262 | 2,684 | 28,192 | 17,500 |
| Writes | 31 | 1 | 994 | 96 |
| Reads | 21 | 6 | 583 | 24 |
| Deletes | 2 | 0 | 347 | 0 |
| Renames | 0 | 0 | 461 | 0 |
| File-information calls | 47 | 14 | 1,894 | 92 |
| Successful create/open | 96 | 55 | 2,391 | 766 |
| File-handle observations | 674 | 276 | 9,472 | 4,470 |
| Usable paths observed | 151 | 129 | 2,706 | 482 |

The distributions are highly skewed. Means should not be interpreted as a
typical report; medians and the complete `sample_features.jsonl` artifact are
the preferred reproducibility reference.

## 6. Detection results

| Stream prefix | Accuracy | Balanced accuracy | Precision | Recall | F1 | ROC AUC |
|---:|---:|---:|---:|---:|---:|---:|
| 10% | 0.880 | 0.838 | 0.963 | 0.690 | 0.804 | 0.926 |
| 25% | 0.854 | 0.800 | 0.972 | 0.611 | 0.750 | 0.928 |
| 50% | 0.861 | 0.809 | 0.973 | 0.628 | 0.763 | 0.923 |
| 75% | 0.858 | 0.805 | 0.972 | 0.619 | 0.757 | 0.918 |
| 100% | 0.854 | 0.802 | 0.959 | 0.619 | 0.753 | 0.903 |

The 10% result is not evidence that a real detector raises an alarm after
exactly 10% of execution. It means that a classifier using features available
from that checkpoint separates the held-out samples with the listed metrics.
The apparent decline in recall at later checkpoints reflects the fixed
feature model and sample distribution; it is not interpreted as detector
degradation without repeated splits and event-level calibration.

## 7. Damage-aware interpretation

The activity table shows that ransomware reports contain much more observable
file-related activity before any hypothetical alarm checkpoint. This is
consistent with a damage-aware evaluation objective: a detector that alarms
earlier can potentially reduce exposure to these operations.

The evidence does **not** support the following stronger claims:

1. A write call changed file contents.
2. A set-information call changed encryption state.
3. A path uniquely identifies a physical file.
4. A handle uniquely identifies a physical file across reuse.
5. A successful native status proves content modification.
6. A ransomware-labeled report contains only ransomware behavior.

Accordingly, the current “damage” variables are explicitly named
`observable_activity_proxy` in the methodology. A future damage study would
need file-system snapshots, content hashes, write-byte accounting, or another
instrumented ground truth.

## 8. Reproducibility

From the repository root, with `ijson` installed:

```bash
python3 -m unittest discover -s tests -v
python3 -m scripts.final_research_pipeline \
  /path/to/EN2025 \
  --inventory ./inventory.csv \
  --output-dir ./outputs/final_research
```

The output directory contains:

- `sample_features.jsonl`: one compact, provenance-linked row per report;
- `metrics.json`: dataset totals, split definition, methodology, and metrics;
- `final_research_report.md`: generated experiment summary.

Earlier Phase 0 and Phase 1 artifacts remain under `outputs/phase0*`,
`outputs/phase1`, `outputs/phase1_corrected`, and
`outputs/phase1_success_aware`. The full-dataset feature artifact is only an
aggregate and does not replace the 20-report raw-preserving validation
archive.

## 9. Limitations and future work

- The exact deployed capemon revision is unknown.
- Report order is stored process-call order, not guaranteed wall-clock
  chronology across processes.
- File identity is candidate-level and ambiguity-aware.
- The fixed hash split is deterministic but is not repeated cross-validation.
- No confidence intervals or calibration curves are reported.
- The baseline is sample-level, not a continuously updated event classifier.
- The observable activity proxy is not physical damage.
- Class labels come from the dataset and were not independently adjudicated.
- PCAP contents were not used to establish file-system ground truth.

The next scientifically justified step is not to claim successful damage
measurement. It is to add independent temporal splits, calibrated event-level
alarms, and file-system ground truth on a controlled subset.

## 10. Conclusion

The project now has a complete, reproducible inventory, evidence-preserving
event reconstruction, reliability-hardened lifecycle tracker, and full
EN2025 streaming benchmark. The benchmark demonstrates strong separation
between the two dataset classes using early observable activity, while the
audits prevent that separation from being overstated as physical damage
measurement. This bounded conclusion is the scientifically defensible final
claim supported by the available data.
