#!/usr/bin/env python3
"""Build a compact memmapped sequence dataset without loading EN2025 into RAM."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.detection.sequence_data import build_sequence_dataset


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset_root", type=Path)
    parser.add_argument("--inventory", type=Path, default=Path("inventory.csv"))
    parser.add_argument("--vocabulary", type=Path, default=Path("models/bag_of_apis/vocabulary.json"))
    parser.add_argument("--output-dir", type=Path, default=Path("outputs/neural_dataset"))
    parser.add_argument("--sequence-length", type=int, default=512)
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args()
    build_sequence_dataset(
        args.dataset_root.expanduser().resolve(),
        args.inventory.expanduser(),
        args.vocabulary.expanduser(),
        args.output_dir.expanduser(),
        sequence_length=args.sequence_length,
        overwrite=args.overwrite,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
