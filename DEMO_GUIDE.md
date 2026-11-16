# EN2025 Streaming Detector Demo Guide

## What this demonstrates

This is a replay of recorded EN2025 CAPE reports. It is not live endpoint
monitoring and it never executes a sample. The dashboard receives one stored
API event at a time, updates the persisted Bag-of-APIs model, and marks the
first threshold crossing.

The activity counters are observable telemetry. They are not claims of
physical file damage, successful encryption, or guaranteed file identity.

## Start the demo

From the repository root:

```bash
# one-time setup
python3 -m venv .venv-demo
.venv-demo/bin/python -m pip install -r requirements-demo.txt
cd web/frontend
npm install
npm run build
cd ../..

# build the model once, if models/bag_of_apis is absent
.venv-demo/bin/python -m scripts.train_bag_of_apis \
  /path/to/EN2025 \
  --inventory ./inventory.csv \
  --output-dir ./models/bag_of_apis

# start the backend
EN2025_ROOT=/path/to/EN2025 \
.venv-demo/bin/python -m uvicorn web.backend:app --host 127.0.0.1 --port 8000
```

Open <http://127.0.0.1:8000>.

## Recommended walkthrough

1. Select model **Bag of APIs**. The neural architecture entries are visibly
   unavailable unless their optional implementations are added.
2. Select a smaller benign report first, such as sample
   `001b7fa6b0ef402d2ab4f10403d6e9867c9d9c6493b99392f2cdb63bc2631422`.
3. Use a replay speed around 20 events/sec and select **Start replay**.
4. Point out the stored event order, current score, calibrated threshold,
   file-related highlighting, and the absence/presence of an alert.
5. Reset and select ransomware sample
   `7b4c442ae9ef60b2f04dd893ab0a62385a2f016d4ad82793317b50b9fcd12e1e`.
6. Point out the first alert marker, trace fraction, score at alert, and
   observable write/read/delete/rename/file-information counters.
7. Pause, resume, and reset to show that replay controls affect the same
   independent session state.

The sample labels shown in the UI are dataset ground-truth labels. They are
not model predictions.

## What to say during review

- The model is loaded from `models/bag_of_apis/model.json`; the web server
  does not retrain on startup.
- The threshold is calibrated from validation benign traces at a fixed 1%
  validation false-alarm target.
- The test split is held out by sample hash during training.
- Paths and handles remain candidate evidence, and writes remain API
  observations rather than confirmed physical damage.
