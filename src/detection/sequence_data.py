"""Streaming sequence preprocessing for the neural detector models.

The raw reports are read one at a time.  The resulting fixed-width integer
matrix is memory-mapped so training never needs to hold EN2025 in RAM.
"""

from __future__ import annotations

import csv
import hashlib
import json
import platform
import random
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterator

import numpy as np

from scripts.phase1.cape_parser import iter_report_events

SPLIT_RULE = "sha256(sample_id) integer mod 100: train < 70, validation < 85, test >= 85"
SPLITS = ("train", "validation", "test")


def split_for(sample_id: str) -> str:
    bucket = int(hashlib.sha256(sample_id.encode()).hexdigest()[:8], 16) % 100
    return "train" if bucket < 70 else "validation" if bucket < 85 else "test"


def hardware_info() -> dict[str, Any]:
    info: dict[str, Any] = {
        "platform": platform.platform(),
        "python": sys.version,
        "machine": platform.machine(),
        "processor": platform.processor(),
    }
    try:
        import torch

        info["torch_version"] = torch.__version__
        info["cuda_available"] = bool(torch.cuda.is_available())
        info["mps_available"] = bool(
            hasattr(torch.backends, "mps") and torch.backends.mps.is_available()
        )
    except ImportError:
        info["torch_version"] = None
        info["cuda_available"] = False
        info["mps_available"] = False
    return info


def select_device(requested: str = "auto") -> str:
    if requested != "auto":
        return requested
    try:
        import torch

        if torch.cuda.is_available():
            return "cuda"
        if hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
            return "mps"
    except ImportError:
        pass
    return "cpu"


def load_inventory(path: Path, root: Path) -> list[dict[str, Any]]:
    with path.open(newline="", encoding="utf-8") as stream:
        rows = []
        for row in csv.DictReader(stream):
            report = root / row["relative_report_path"]
            if row.get("report_exists", "").lower() == "true" and report.is_file():
                rows.append(
                    {
                        "sample_id": row["sample_hash"],
                        "class_label": row["class_label"],
                        "relative_report_path": row["relative_report_path"],
                        "path": report,
                        "split": split_for(row["sample_hash"]),
                    }
                )
    return sorted(rows, key=lambda row: row["relative_report_path"])


def iter_token_ids(
    item: dict[str, Any], vocabulary: dict[str, int]
) -> Iterator[int]:
    for event in iter_report_events(
        item["path"],
        item["sample_id"],
        item["class_label"],
        item["relative_report_path"],
    ):
        api = event.api_normalized
        yield vocabulary.get(api, 0)


def _write_json(path: Path, value: Any) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def build_sequence_dataset(
    dataset_root: Path,
    inventory_path: Path,
    vocabulary_path: Path,
    output_dir: Path,
    sequence_length: int = 512,
    overwrite: bool = False,
) -> dict[str, Any]:
    """Create a compact, deterministic, fixed-width memmap dataset."""
    if sequence_length <= 0:
        raise ValueError("sequence_length must be positive")
    if output_dir.exists() and any(output_dir.iterdir()) and not overwrite:
        raise FileExistsError(f"refusing to overwrite non-empty directory: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    vocabulary = {
        api: index + 1
        for index, api in enumerate(json.loads(vocabulary_path.read_text(encoding="utf-8")))
    }
    items = load_inventory(inventory_path, dataset_root)
    if not items:
        raise ValueError("no readable reports found in inventory")

    labels = {"benign": 0, "ransomware": 1}
    matrix_path = output_dir / "sequences.int16"
    lengths_path = output_dir / "lengths.uint32"
    labels_path = output_dir / "labels.uint8"
    matrix = np.memmap(matrix_path, mode="w+", dtype=np.int16, shape=(len(items), sequence_length))
    lengths = np.memmap(lengths_path, mode="w+", dtype=np.uint32, shape=(len(items),))
    target_labels = np.memmap(labels_path, mode="w+", dtype=np.uint8, shape=(len(items),))
    manifest: list[dict[str, Any]] = []
    split_counts = {split: 0 for split in SPLITS}

    try:
        for index, item in enumerate(items):
            event_count = 0
            for token in iter_token_ids(item, vocabulary):
                if event_count < sequence_length:
                    matrix[index, event_count] = token
                event_count += 1
            count = min(event_count, sequence_length)
            if count < sequence_length:
                matrix[index, count:] = 0
            lengths[index] = count
            target_labels[index] = labels[item["class_label"]]
            split_counts[item["split"]] += 1
            manifest.append(
                {
                    "index": index,
                    "sample_id": item["sample_id"],
                    "class_label": item["class_label"],
                    "split": item["split"],
                    "events": event_count,
                    "stored_events": count,
                    "relative_report_path": item["relative_report_path"],
                }
            )
            if (index + 1) % 25 == 0 or index + 1 == len(items):
                print(f"Preprocessed {index + 1}/{len(items)}", file=sys.stderr)
        matrix.flush()
        lengths.flush()
        target_labels.flush()
    finally:
        del matrix, lengths, target_labels

    metadata = {
        "format_version": "sequence-memmap-v1",
        "sequence_length": sequence_length,
        "vocabulary_size": len(vocabulary),
        "padding_id": 0,
        "dtype": "int16",
        "samples": len(items),
        "splits": split_counts,
        "split_rule": SPLIT_RULE,
        "source_dataset": str(dataset_root.resolve()),
        "source_inventory": str(inventory_path.resolve()),
        "vocabulary_file": str(vocabulary_path.resolve()),
        "random_seed": None,
        "python_version": sys.version,
        "hardware": hardware_info(),
    }
    _write_json(output_dir / "metadata.json", metadata)
    _write_json(output_dir / "manifest.json", {"records": manifest})
    return metadata
