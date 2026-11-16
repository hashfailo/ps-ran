# Final EN2025 Streaming Detector Experiment

## Scope

Processed 1530 of 1530 inventory reports in a streaming pass. The experiment writes compact sample-level aggregates and never modifies raw reports.

## Scientific safeguards

- Features are observable CAPE event activity, not claims of physical file damage.
- File handles and paths remain candidate evidence, not guaranteed identities.
- The split is deterministic by SHA-256(sample_id) modulo 5.
- The classifier is a transparent Gaussian Naive Bayes baseline; results are not a production detector.

## Dataset totals

- Benign samples: 919
- Ransomware samples: 611
- Benign events: 3917169
- Ransomware events: 17225345

## Detection metrics

| Prefix | Accuracy | Balanced accuracy | Precision | Recall | F1 | ROC AUC |
|---:|---:|---:|---:|---:|---:|---:|
| 10% | 0.880 | 0.838 | 0.963 | 0.690 | 0.804 | 0.926 |
| 25% | 0.854 | 0.800 | 0.972 | 0.611 | 0.750 | 0.928 |
| 50% | 0.861 | 0.809 | 0.973 | 0.628 | 0.763 | 0.923 |
| 75% | 0.858 | 0.805 | 0.972 | 0.619 | 0.757 | 0.918 |
| 100% | 0.854 | 0.802 | 0.959 | 0.619 | 0.753 | 0.903 |

## Limitations

The available reports do not establish changed bytes, successful content encryption, physical file identity, or alarm causality. Prefix results are checkpoint evaluations, not sub-event alarm timestamps. The final paper must report these as observational proxy results.

Artifacts: `sample_features.jsonl` and `metrics.json`.
