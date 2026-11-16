#!/usr/bin/env python3
"""Load a saved neural artifact and validate prefix inference on one report."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.detection.neural_models import load_neural_artifact
from src.detection.neural_models import select_device
from src.detection.sequence_data import iter_token_ids, load_inventory


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("model_dir", type=Path)
    parser.add_argument("dataset_root", type=Path)
    parser.add_argument("--inventory", type=Path, default=Path("inventory.csv"))
    parser.add_argument("--sample-id", required=True)
    parser.add_argument("--device", choices=("auto", "cpu", "mps", "cuda"), default="auto")
    args = parser.parse_args()
    device = select_device(args.device)
    handle = load_neural_artifact(args.model_dir, device)
    model = handle.model
    metadata = handle.metadata
    vocabulary = {
        api: index + 1
        for index, api in enumerate(
            json.loads((args.model_dir / "vocabulary.json").read_text(encoding="utf-8"))
        )
    } if (args.model_dir / "vocabulary.json").exists() else {}
    items = [item for item in load_inventory(args.inventory, args.dataset_root) if item["sample_id"] == args.sample_id]
    if not items:
        raise SystemExit(f"sample not found: {args.sample_id}")
    tokens = []
    for token in iter_token_ids(items[0], vocabulary):
        tokens.append(token)
        if len(tokens) >= int(metadata["config"]["sequence_length"]):
            break
    import torch

    with torch.no_grad():
        sequence = torch.tensor([tokens], dtype=torch.long, device=device)
        lengths = torch.tensor([len(tokens)], dtype=torch.long, device=device)
        score = float(torch.softmax(model(sequence, lengths), dim=1)[0, 1].cpu())
    print(json.dumps({
        "sample_id": args.sample_id,
        "architecture": metadata["architecture"],
        "events_scored": len(tokens),
        "score": score,
        "threshold": metadata["threshold"],
        "alert": score >= metadata["threshold"],
        "device": device,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
