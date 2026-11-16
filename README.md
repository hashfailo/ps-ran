# Damage-Aware Evaluation of Streaming Ransomware Detectors

This student research project studies how quickly machine-learning detectors recognize ransomware and how much harm has occurred by the time they raise an alarm.

## Overview

The project examines recorded ransomware behavior in a sandbox. It focuses on the timing of detection and the damage that may occur before an alarm.

## Status

Early development. Structure and documentation are still being set up.

## Phase 0A: Dataset inventory

`inventory_dataset.py` inventories the `benign` and `ransomware` trees using
filesystem metadata only. It never opens `report.json`, so large reports do
not consume memory. A directory is treated as a sample when it contains
`report.json` or `dump.pcap`; this allows samples with a missing report to be
counted while avoiding unrelated directories.

Run it from the repository root:

```bash
python3 inventory_dataset.py ~/Downloads/EN2025
```

Use `--output-dir` to choose another output location:

```bash
python3 inventory_dataset.py ~/Downloads/EN2025 --output-dir ./inventory-output
```

The script writes:

- `inventory.csv`: one row per discovered sample, including class, sample
  directory/hash, relative report path, artifact presence, and report size.
- `summary.json`: per-class counts, total storage, distribution statistics
  (bytes), and counts above 10, 50, and 100 MiB.

Sizes use binary MiB (`1 MiB = 1,048,576 bytes`). Inaccessible directories are
reported as warnings and skipped; original dataset files are not modified.

## Phase 0B: Report structure audit

The Phase 0B audit uses the optional `ijson` streaming parser so reports are
processed one at a time without loading the complete dataset or creating report
copies. Set up a private environment, then run:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install ijson
.venv/bin/python scripts/report_structure_audit.py \
  /path/to/EN2025
```

By default, the script selects the first three report paths per class after
lexicographic sorting. Use `--reports-per-class N` to change this, and
`--output-dir DIR` to change the output location. Existing output files are
not overwritten unless `--overwrite` is supplied.

The audit writes `report_structure_summary.json` (section availability,
process/call counts, field presence, API/category frequencies, and selected
report metadata), `api_frequency.csv` (class/API call totals),
`file_api_arguments.json` (bounded, redacted examples for common file APIs),
and `event_ordering_audit.json` (ID uniqueness, timestamp parsing and
monotonicity observations, shared timestamps, and adjacent ID/timestamp
direction comparisons). These are observations only: the audit does not infer
chronological order, damage, or operation success from CAPE fields.

## Phase 0C: Event and handle audit

Run the size-stratified event/handle audit with the same `ijson` environment:

```bash
.venv/bin/python scripts/phase0c_event_handle_audit.py \
  /path/to/EN2025
```

It selects five smallest and five largest reports per class, excluding Phase
0B selections when the Phase 0B summary is available. Outputs include report
selection and per-process ID/timestamp details, scoped handle mappings,
ambiguous cross-process timestamp ties, and an observational Markdown review.
Use `--overwrite` only to intentionally replace existing Phase 0C outputs.

## Phase 0C2: Handle lifecycle audit

The lifecycle audit reuses the exact 20 report paths recorded by Phase 0C and
tracks `(process_id, normalized_handle)` in stored process-call order:

```bash
.venv/bin/python scripts/phase0c2_handle_lifecycle_audit.py \
  /path/to/EN2025
```

It writes candidate create/close sequence counts and examples, `NtCreateFile`
outcome combinations, and a review under `outputs/phase0c2/`. These are
observations only; timestamps are not used to break ties and no handle
lifetime, reuse, success, or damage conclusion is inferred.

## Phase 0D: File identity and path audit

Phase 0D reuses the exact 20-report selection recorded by Phase 0C and audits
raw path and handle representations without normalizing paths or inferring
file identity:

```bash
.venv/bin/python scripts/phase0d_file_identity_audit.py \
  /path/to/EN2025
```

Outputs are written under `outputs/phase0d/`:

- `file_path_argument_audit.csv`: per-API argument frequencies and usable,
  missing, empty, null, and unusable path/handle counts.
- `path_variation_examples.csv`: bounded raw path examples grouped by
  descriptive representation.
- `handle_path_consistency.csv`: process-scoped candidate handle/path
  observations with stored call context.
- `file_identity_summary.json`: separated benign/ransomware aggregates,
  methodology, and limitations.
- `phase0d_review.md`: concise observational findings and unresolved
  questions.

The audit processes one report at a time with `ijson`. Existing outputs are
not overwritten; no dataset files or previous phase outputs are modified.

## Phase 1: Event stream reconstruction and file identity tracking

Phase 1 currently validates the approved 20-report Phase 0C selection. It
preserves complete raw call arguments, emits the stored process-call order as
the primary event stream, and records a separate deterministic timestamp-based
ordering recipe without treating it as ground-truth chronology:

```bash
.venv/bin/python -m scripts.phase1.run_phase1 \
  /path/to/EN2025
```

Outputs are written under `outputs/phase1/`. Each sample has an event JSONL
file with sample, process, call, raw argument, normalized argument, path,
handle, candidate identity, and uncertainty fields. `metadata.jsonl` records
per-sample counts and provenance; `failures.jsonl` records failed samples;
`unresolved_identities.jsonl` records path/handle observations without a
candidate identity;
`phase1_summary.json` records selection, storage capability, and limitations.
Use `--resume` to continue an interrupted run. Existing outputs are otherwise
protected from overwrite.

The corrected reliability implementation is run separately and writes to
`outputs/phase1_corrected/`:

```bash
.venv/bin/python -m scripts.phase1.run_phase1_corrected \
  /path/to/EN2025
```

It uses explicit API-specific file-handle roles, separates non-file handles,
records lifecycle and identity ambiguities, and uses atomic metadata writes.
It still preserves candidate rather than guaranteed physical file identity.

The current environment has `ijson` but no PyArrow or fastparquet, so the
validation uses JSONL and explicitly reports Parquet as unavailable. NPY is
not used for variable-length event streams. This phase does not measure damage,
infer operation success, or train a detector.

## Final compact research experiment

The full-dataset experiment is storage-aware: it streams each report with
`ijson` and writes one small JSONL record per sample rather than another
multi-gigabyte canonical event archive. It extracts conservative observable
activity features, evaluates a transparent Gaussian Naive Bayes baseline at
10%, 25%, 50%, 75%, and 100% stream prefixes, and reports write/delete/rename
activity as an observable pre-alarm proxy rather than physical damage:

```bash
.venv/bin/python -m scripts.final_research_pipeline \
  /path/to/EN2025 \
  --inventory ./inventory.csv \
  --output-dir ./outputs/final_research
```

The outputs are `sample_features.jsonl`, `metrics.json`, and
`final_research_report.md`. The classifier split is deterministic by
`sha256(sample_id) mod 5`. Existing output directories are protected unless
`--overwrite` is explicitly supplied. The experiment does not modify reports,
PCAPs, or earlier phase outputs.

## Working streaming detector demo

The web demo loads the persisted Bag-of-APIs model and never retrains when
the server starts. Install the backend and frontend dependencies once:

```bash
python3 -m venv .venv-demo
.venv-demo/bin/python -m pip install -r requirements-demo.txt
cd web/frontend
npm install
npm run build
cd ../..
```

Train the dedicated 331-token model (the command is overwrite-protected):

```bash
.venv-demo/bin/python -m scripts.train_bag_of_apis \
  /path/to/EN2025 \
  --inventory ./inventory.csv \
  --output-dir ./models/bag_of_apis
```

Run an independent inference check:

```bash
.venv-demo/bin/python -m scripts.predict_api models/bag_of_apis \
  NtCreateFile NtWriteFile NtWriteFile NtClose
```

Start the FastAPI/WebSocket server and open the React/Tailwind dashboard:

```bash
EN2025_ROOT=/path/to/EN2025 \
EN2025_INVENTORY=inventory.csv \
BAG_OF_APIS_MODEL=models/bag_of_apis \
.venv-demo/bin/python -m uvicorn web.backend:app \
  --host 127.0.0.1 --port 8000
```

Open <http://127.0.0.1:8000>. The dashboard replays stored CAPE events,
updates the actual loaded model score over WebSocket, supports pause/resume/
reset and speed control, and marks the first calibrated alert. See
[`DEMO_GUIDE.md`](DEMO_GUIDE.md) and [`DEMO_STATUS.md`](DEMO_STATUS.md).

### Lightweight CNN, GRU, and causal Transformer training

The neural workflow is optional and does not change the Bag-of-APIs workflow.
Install its dependencies with:

```bash
python3 -m venv .venv-neural
.venv-neural/bin/python -m pip install -r requirements-neural.txt
```

On the validated local machine this produced Python 3.14.3, PyTorch 2.15.0,
NumPy 2.5.5, ijson 3.6.0, and JupyterLab 4.6.6. The machine is an arm64
Apple M1 with 8 GiB unified memory. `--device auto` selected MPS and a real
matrix multiplication smoke test completed successfully. The scripts fall
back to CPU if MPS is unavailable.

Recommended conservative starting configurations for an 8 GiB M1 are:

| Model | Sequence length | Batch size | Embedding | Hidden | Layers | Heads |
|---|---:|---:|---:|---:|---:|---:|
| XRan-style CNN | 512 | 16 | 32 | 64 | 1 | N/A |
| GRU | 512 | 8–16 | 32 | 64 | 1 | N/A |
| Causal Transformer | 256–512 | 4–8 | 32 | 64 | 1 | 4 |

Train models sequentially, not concurrently. Monitor `memory_pressure` and
`df -h .`; keep at least several GiB free for checkpoints and macOS swap.
The preprocessing output is fixed-width and memory-mapped, so the 22 GiB raw
EN2025 directory is never loaded into RAM.

Preprocess reports once into a compact, fixed-width memmapped dataset. Reports
are streamed one at a time; the raw dataset is never assembled in memory:

```bash
.venv-neural/bin/python scripts/preprocess_neural_dataset.py \
  /path/to/EN2025 \
  --inventory inventory.csv \
  --output-dir outputs/neural_dataset \
  --sequence-length 512
```

Train each architecture independently. `--device auto` selects CUDA, Apple
Silicon MPS, or CPU. Checkpoints are written every epoch and
`--resume` continues from an interrupted checkpoint:

```bash
.venv-neural/bin/python scripts/train_xran_style_cnn.py outputs/neural_dataset \
  --output-dir models/xran_style_cnn --device auto --batch-size 16 --epochs 8
.venv-neural/bin/python scripts/train_gru.py outputs/neural_dataset \
  --output-dir models/gru --device auto --batch-size 16 --epochs 8
.venv-neural/bin/python scripts/train_causal_transformer.py outputs/neural_dataset \
  --output-dir models/causal_transformer --device auto --batch-size 8 \
  --embedding-dim 32 --hidden-dim 64 --layers 1 --heads 4 --epochs 8
```

For example, resume with:

```bash
.venv-neural/bin/python scripts/train_gru.py outputs/neural_dataset \
  --output-dir models/gru --resume models/gru/last_checkpoint.pt --epochs 12
```

Validate a downloaded model without retraining:

```bash
.venv-neural/bin/python -m scripts.validate_neural_model models/gru \
  /path/to/EN2025 \
  --inventory inventory.csv --sample-id 7b4c442ae9ef60b2f04dd893ab0a62385a2f016d4ad82793317b50b9fcd12e1e
```

Evaluate all saved neural models on the fixed test split:

```bash
.venv-neural/bin/python -m scripts.evaluate_neural_models \
  outputs/neural_dataset --models-root models --device mps
```

This writes `evaluation.json` in each neural model directory and
`outputs/neural_model_comparison.json`.

Each artifact records the architecture, dimensions, sequence length, seed,
dependency versions, hardware/device, exact split rule, validation threshold,
and test summary. Copy the complete model directory to `models/gru`,
`models/xran_style_cnn`, or `models/causal_transformer`; the existing FastAPI
backend discovers and loads it without retraining. The optional
notebook in `notebooks/` is retained for portability, but the validated
training run and showcase deployment use only the local Apple Silicon
environment described above.

## Responsible use

This is defensive research based on previously recorded, publicly available sandbox data. No malware samples or tools for creating malware are included or will be released, and no real systems are affected.

## License

To be decided.
