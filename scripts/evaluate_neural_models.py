#!/usr/bin/env python3
"""Evaluate saved neural artifacts on the fixed memmapped test split."""

from __future__ import annotations

import argparse
import gc
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.detection.neural_models import load_neural_artifact, select_device, require_torch
from src.detection.neural_training import MemmapSequenceDataset


def evaluate(model_dir: Path, dataset_dir: Path, device: str) -> dict:
    torch, _ = require_torch()
    handle = load_neural_artifact(model_dir, device)
    dataset_metadata = json.loads((dataset_dir / "metadata.json").read_text(encoding="utf-8"))
    dataset = MemmapSequenceDataset(dataset_dir, "test")
    loader = torch.utils.data.DataLoader(dataset, batch_size=16, shuffle=False, num_workers=0)
    tp = tn = fp = fn = 0
    with torch.no_grad():
        for sequences, lengths, target in loader:
            scores = torch.softmax(
                handle.model(sequences.to(device), lengths.to(device)), dim=1
            )[:, 1].cpu()
            predicted = scores.ge(handle.threshold).to(torch.long)
            tp += int(((predicted == 1) & (target == 1)).sum())
            tn += int(((predicted == 0) & (target == 0)).sum())
            fp += int(((predicted == 1) & (target == 0)).sum())
            fn += int(((predicted == 0) & (target == 1)).sum())
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    f1 = 2 * precision * recall / max(1e-12, precision + recall)
    result = {
        "architecture": handle.metadata["architecture"],
        "threshold": handle.threshold,
        "split": "test",
        "split_rule": dataset_metadata["split_rule"],
        "samples": len(dataset),
        "confusion_matrix": {
            "labels": ["benign", "ransomware"],
            "rows_true": {
                "benign": {"benign": tn, "ransomware": fp},
                "ransomware": {"benign": fn, "ransomware": tp},
            },
        },
        "classification_report": {
            "benign": {
                "precision": tn / max(1, tn + fn),
                "recall": tn / max(1, tn + fp),
                "f1": 2 * (tn / max(1, tn + fn)) * (tn / max(1, tn + fp))
                / max(1e-12, (tn / max(1, tn + fn)) + (tn / max(1, tn + fp))),
                "support": tn + fp,
            },
            "ransomware": {
                "precision": precision,
                "recall": recall,
                "f1": f1,
                "support": tp + fn,
            },
            "accuracy": (tp + tn) / max(1, tp + tn + fp + fn),
            "macro_f1": (
                f1
                + 2 * (tn / max(1, tn + fn)) * (tn / max(1, tn + fp))
                / max(1e-12, (tn / max(1, tn + fn)) + (tn / max(1, tn + fp)))
            )
            / 2,
        },
        "test_recall": recall,
        "test_false_alarm_rate": fp / max(1, tn + fp),
    }
    (model_dir / "evaluation.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    del handle, dataset, loader
    gc.collect()
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset_dir", type=Path)
    parser.add_argument("--models-root", type=Path, default=Path("models"))
    parser.add_argument("--device", choices=("auto", "cpu", "mps", "cuda"), default="auto")
    args = parser.parse_args()
    device = select_device(args.device)
    results = []
    for architecture in ("xran_style_cnn", "gru", "causal_transformer"):
        results.append(evaluate(args.models_root / architecture, args.dataset_dir, device))
    comparison = {
        "dataset_format": json.loads((args.dataset_dir / "metadata.json").read_text())["format_version"],
        "split_rule": results[0]["split_rule"],
        "device": device,
        "models": results,
    }
    Path("outputs/neural_model_comparison.json").write_text(
        json.dumps(comparison, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(comparison, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
