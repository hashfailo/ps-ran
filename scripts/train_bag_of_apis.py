#!/usr/bin/env python3
"""Train and persist the group-held-out Bag-of-APIs detector."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from scripts.phase1.cape_parser import iter_report_events
from src.detection.bag_of_apis import BagOfAPIsModel, MODEL_VERSION


VOCABULARY_SIZE = 331
SPLIT_RULE = "sha256(sample_id) integer mod 100: train < 70, validation < 85, test >= 85"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset_root", type=Path)
    parser.add_argument("--inventory", type=Path, default=Path("inventory.csv"))
    parser.add_argument("--output-dir", type=Path, default=Path("models/bag_of_apis"))
    parser.add_argument("--overwrite", action="store_true")
    return parser.parse_args()


def split_for(sample_id: str) -> str:
    bucket = int(hashlib.sha256(sample_id.encode()).hexdigest()[:8], 16) % 100
    return "train" if bucket < 70 else "validation" if bucket < 85 else "test"


def load_inventory(path: Path, root: Path) -> list[dict[str, Any]]:
    with path.open(newline="", encoding="utf-8") as stream:
        rows = []
        for row in csv.DictReader(stream):
            if row.get("report_exists", "").lower() != "true":
                continue
            report = root / row["relative_report_path"]
            if report.is_file():
                rows.append(
                    {
                        "sample_id": row["sample_hash"],
                        "class_label": row["class_label"],
                        "relative_report_path": row["relative_report_path"],
                        "path": report,
                    }
                )
    return sorted(rows, key=lambda row: row["relative_report_path"])


def extract_counts(item: dict[str, Any]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for event in iter_report_events(
        item["path"],
        item["sample_id"],
        item["class_label"],
        item["relative_report_path"],
    ):
        if event.api_normalized:
            counts[event.api_normalized] += 1
    return counts


def final_score(model: BagOfAPIsModel, counts: Counter[str]) -> float:
    return model.score_counts(counts, sum(counts.values()))


def quantile(values: list[float], percentile: float) -> float:
    values = sorted(values)
    if not values:
        return 1.0
    position = (len(values) - 1) * percentile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return values[lower]
    return values[lower] + (values[upper] - values[lower]) * (position - lower)


def main() -> int:
    args = parse_args()
    root = args.dataset_root.expanduser().resolve()
    inventory = args.inventory.expanduser()
    output = args.output_dir.expanduser()
    if output.exists() and any(output.iterdir()) and not args.overwrite:
        print(f"Error: refusing to overwrite model directory: {output}", file=sys.stderr)
        return 1
    output.mkdir(parents=True, exist_ok=True)
    items = load_inventory(inventory, root)
    if not items:
        print("Error: no readable reports found in inventory", file=sys.stderr)
        return 2
    records: list[dict[str, Any]] = []
    api_totals: Counter[str] = Counter()
    for index, item in enumerate(items, 1):
        print(f"Extracting {index}/{len(items)}: {item['relative_report_path']}", file=sys.stderr)
        counts = extract_counts(item)
        records.append(
            {
                **{key: item[key] for key in ("sample_id", "class_label", "relative_report_path")},
                "split": split_for(item["sample_id"]),
                "counts": dict(counts),
                "events": sum(counts.values()),
            }
        )
        if split_for(item["sample_id"]) == "train":
            api_totals.update(counts)
    vocabulary = [api for api, _ in api_totals.most_common(VOCABULARY_SIZE)]
    while len(vocabulary) < VOCABULARY_SIZE:
        vocabulary.append(f"<reserved_{len(vocabulary)}>")
    train = [row for row in records if row["split"] == "train"]
    class_event_totals = Counter()
    for row in train:
        class_event_totals[row["class_label"]] += row["events"]
    log_probabilities: dict[str, list[float]] = {}
    alpha = 1.0
    for label in ("benign", "ransomware"):
        totals = [
            sum(row["counts"].get(api, 0) for row in train if row["class_label"] == label)
            for api in vocabulary
        ]
        denominator = sum(totals) + alpha * len(vocabulary)
        log_probabilities[label] = [math.log((value + alpha) / denominator) for value in totals]
    total_train_events = sum(class_event_totals.values())
    log_priors = {
        label: math.log((class_event_totals[label] + 1) / (total_train_events + 2))
        for label in ("benign", "ransomware")
    }
    provisional = BagOfAPIsModel(
        vocabulary,
        log_probabilities,
        log_priors,
        threshold=1.0,
        metadata={"model_version": MODEL_VERSION, "alpha": alpha},
    )
    validation_benign = [
        final_score(provisional, Counter(row["counts"]))
        for row in records
        if row["split"] == "validation" and row["class_label"] == "benign"
    ]
    threshold = quantile(validation_benign, 0.99)
    model = BagOfAPIsModel(
        vocabulary,
        log_probabilities,
        log_priors,
        threshold,
        metadata={
            "model_version": MODEL_VERSION,
            "feature_type": "API event counts",
            "vocabulary_size": VOCABULARY_SIZE,
            "alpha": alpha,
            "split_rule": SPLIT_RULE,
            "calibration": "99th percentile of validation benign final scores",
            "source_dataset": str(root),
        },
    )
    model.save(output)
    (output / "vocabulary.json").write_text(json.dumps(vocabulary, indent=2) + "\n", encoding="utf-8")
    split_manifest = {
        split: sorted(row["sample_id"] for row in records if row["split"] == split)
        for split in ("train", "validation", "test")
    }
    (output / "split_manifest.json").write_text(
        json.dumps({"rule": SPLIT_RULE, "splits": split_manifest}, indent=2) + "\n",
        encoding="utf-8",
    )
    scores = []
    for row in records:
        score = final_score(model, Counter(row["counts"]))
        scores.append((row, score))
    test = [(row, score) for row, score in scores if row["split"] == "test"]
    tp = sum(row["class_label"] == "ransomware" and score >= threshold for row, score in test)
    fp = sum(row["class_label"] == "benign" and score >= threshold for row, score in test)
    positives = sum(row["class_label"] == "ransomware" for row, _ in test)
    summary = {
        "model_version": MODEL_VERSION,
        "samples": len(records),
        "splits": {split: sum(row["split"] == split for row in records) for split in ("train", "validation", "test")},
        "vocabulary_size": len(vocabulary),
        "threshold": threshold,
        "validation_benign_count": len(validation_benign),
        "test_true_positive": tp,
        "test_false_positive": fp,
        "test_ransomware_count": positives,
        "test_recall": tp / positives if positives else None,
        "test_false_alarm_rate": fp / max(1, sum(row["class_label"] == "benign" for row, _ in test)),
        "split_rule": SPLIT_RULE,
    }
    (output / "training_summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
