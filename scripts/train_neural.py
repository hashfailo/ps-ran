#!/usr/bin/env python3
"""Shared command implementation for the causal neural detector trainers."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.detection.neural_training import train_neural


def run(architecture: str) -> int:
    parser = argparse.ArgumentParser(description=f"Train the {architecture} EN2025 detector.")
    parser.add_argument("dataset_dir", type=Path, help="directory made by preprocess_neural_dataset.py")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--epochs", type=int, default=8)
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--learning-rate", type=float, default=1e-3)
    parser.add_argument("--embedding-dim", type=int, default=32)
    parser.add_argument("--hidden-dim", type=int, default=64)
    parser.add_argument("--layers", type=int, default=1)
    parser.add_argument("--heads", type=int, default=4)
    parser.add_argument("--dropout", type=float, default=0.1)
    parser.add_argument("--device", choices=("auto", "cpu", "mps", "cuda"), default="auto")
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--checkpoint-every", type=int, default=1)
    parser.add_argument("--resume", type=Path)
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args()
    train_neural(
        architecture,
        args.dataset_dir.expanduser(),
        args.output_dir.expanduser(),
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.learning_rate,
        embedding_dim=args.embedding_dim,
        hidden_dim=args.hidden_dim,
        layers=args.layers,
        heads=args.heads,
        dropout=args.dropout,
        device=args.device,
        seed=args.seed,
        checkpoint_every=args.checkpoint_every,
        resume=args.resume.expanduser() if args.resume else None,
        overwrite=args.overwrite,
    )
    return 0
