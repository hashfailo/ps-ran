"""Shared low-memory training loop for the three causal neural detectors."""

from __future__ import annotations

import json
import importlib.metadata
import os
import random
import resource
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import numpy as np

from .neural_models import build_model, require_torch, select_device
from .sequence_data import hardware_info


class MemmapSequenceDataset:
    def __init__(self, dataset_dir: Path, split: str):
        metadata = json.loads((dataset_dir / "metadata.json").read_text(encoding="utf-8"))
        manifest = json.loads((dataset_dir / "manifest.json").read_text(encoding="utf-8"))["records"]
        rows = [row for row in manifest if row["split"] == split]
        self.indices = np.asarray([row["index"] for row in rows], dtype=np.int64)
        self.sequences = np.memmap(
            dataset_dir / "sequences.int16",
            mode="r",
            dtype=np.int16,
            shape=(metadata["samples"], metadata["sequence_length"]),
        )
        self.lengths = np.memmap(
            dataset_dir / "lengths.uint32",
            mode="r",
            dtype=np.uint32,
            shape=(metadata["samples"],),
        )
        self.labels = np.memmap(
            dataset_dir / "labels.uint8",
            mode="r",
            dtype=np.uint8,
            shape=(metadata["samples"],),
        )

    def __len__(self) -> int:
        return len(self.indices)

    def __getitem__(self, position: int):
        torch, _ = require_torch()
        index = int(self.indices[position])
        return (
            torch.from_numpy(np.array(self.sequences[index], dtype=np.int64, copy=True)),
            torch.tensor(int(self.lengths[index]), dtype=torch.long),
            torch.tensor(int(self.labels[index]), dtype=torch.long),
        )


def _quantile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.5
    return float(np.quantile(np.asarray(values, dtype=np.float64), percentile))


def _version(command: list[str]) -> str | None:
    try:
        return subprocess.check_output(command, text=True, stderr=subprocess.DEVNULL).strip()
    except (OSError, subprocess.SubprocessError):
        return None


def _set_seed(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch, _ = require_torch()
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


def _scores(model, loader, device: str, criterion=None) -> tuple[list[float], list[int], float]:
    torch, _ = require_torch()
    scores: list[float] = []
    labels: list[int] = []
    total_loss = 0.0
    batches = 0
    with torch.no_grad():
        for sequences, lengths, target in loader:
            logits = model(sequences.to(device), lengths.to(device))
            if criterion is not None:
                total_loss += float(criterion(logits, target.to(device)).cpu())
                batches += 1
            scores.extend(torch.softmax(logits, dim=1)[:, 1].detach().cpu().tolist())
            labels.extend(target.tolist())
    return scores, labels, total_loss / max(1, batches)


def train_neural(
    architecture: str,
    dataset_dir: Path,
    output_dir: Path,
    *,
    epochs: int = 8,
    batch_size: int = 16,
    learning_rate: float = 1e-3,
    embedding_dim: int = 32,
    hidden_dim: int = 64,
    layers: int = 1,
    heads: int = 4,
    dropout: float = 0.1,
    device: str = "auto",
    seed: int = 1337,
    checkpoint_every: int = 1,
    resume: Path | None = None,
    overwrite: bool = False,
) -> dict[str, Any]:
    torch, _ = require_torch()
    _set_seed(seed)
    selected_device = select_device(device)
    if output_dir.exists() and any(output_dir.iterdir()) and not overwrite and resume is None:
        raise FileExistsError(f"refusing to overwrite non-empty directory: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    dataset_metadata = json.loads((dataset_dir / "metadata.json").read_text(encoding="utf-8"))
    config = {
        "architecture": architecture,
        "vocabulary_size": dataset_metadata["vocabulary_size"],
        "sequence_length": dataset_metadata["sequence_length"],
        "embedding_dim": embedding_dim,
        "hidden_dim": hidden_dim,
        "layers": layers,
        "heads": heads,
        "dropout": dropout,
        "batch_size": batch_size,
        "learning_rate": learning_rate,
        "epochs": epochs,
        "seed": seed,
    }
    model = build_model(architecture, config).to(selected_device)
    train_set = MemmapSequenceDataset(dataset_dir, "train")
    validation_set = MemmapSequenceDataset(dataset_dir, "validation")
    test_set = MemmapSequenceDataset(dataset_dir, "test")
    train_loader = torch.utils.data.DataLoader(train_set, batch_size=batch_size, shuffle=True, num_workers=0)
    validation_loader = torch.utils.data.DataLoader(validation_set, batch_size=batch_size, shuffle=False, num_workers=0)
    test_loader = torch.utils.data.DataLoader(test_set, batch_size=batch_size, shuffle=False, num_workers=0)
    optimizer = torch.optim.AdamW(model.parameters(), lr=learning_rate)
    criterion = torch.nn.CrossEntropyLoss()
    start_epoch = 0
    best_validation_loss = float("inf")
    history: list[dict[str, Any]] = []
    if resume:
        checkpoint = torch.load(resume, map_location=selected_device, weights_only=False)
        model.load_state_dict(checkpoint["model_state"])
        optimizer.load_state_dict(checkpoint["optimizer_state"])
        start_epoch = int(checkpoint["epoch"])
        best_validation_loss = float(checkpoint.get("best_validation_loss", float("inf")))
        history = list(checkpoint.get("history", []))
        if checkpoint.get("seed") is not None:
            _set_seed(int(checkpoint["seed"]))

    for epoch in range(start_epoch, epochs):
        started = time.monotonic()
        model.train()
        total_loss = 0.0
        for sequences, lengths, target in train_loader:
            optimizer.zero_grad(set_to_none=True)
            logits = model(sequences.to(selected_device), lengths.to(selected_device))
            loss = criterion(logits, target.to(selected_device))
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            total_loss += float(loss.detach().cpu())
        model.eval()
        _, _, validation_loss = _scores(model, validation_loader, selected_device, criterion)
        epoch_record = {
            "epoch": epoch + 1,
            "train_loss": total_loss / max(1, len(train_loader)),
            "validation_loss": validation_loss,
            "duration_seconds": time.monotonic() - started,
            "max_rss": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        }
        history.append(epoch_record)
        checkpoint_data = {
            "epoch": epoch + 1,
            "model_state": model.state_dict(),
            "optimizer_state": optimizer.state_dict(),
            "seed": seed,
            "best_validation_loss": min(best_validation_loss, validation_loss),
            "history": history,
        }
        torch.save(checkpoint_data, output_dir / "last_checkpoint.pt")
        if validation_loss < best_validation_loss:
            best_validation_loss = validation_loss
            torch.save(checkpoint_data, output_dir / "best_checkpoint.pt")
        if (epoch + 1) % checkpoint_every == 0:
            torch.save(checkpoint_data, output_dir / f"checkpoint_epoch_{epoch + 1:04d}.pt")
        print(
            f"epoch {epoch + 1}/{epochs} train_loss={epoch_record['train_loss']:.4f} "
            f"val_loss={validation_loss:.4f} duration={epoch_record['duration_seconds']:.1f}s",
            file=sys.stderr,
        )

    best_checkpoint = torch.load(output_dir / "best_checkpoint.pt", map_location=selected_device, weights_only=False)
    model.load_state_dict(best_checkpoint["model_state"])
    model.eval()
    validation_scores, validation_labels, _ = _scores(model, validation_loader, selected_device)
    benign_scores = [score for score, label in zip(validation_scores, validation_labels) if label == 0]
    threshold = _quantile(benign_scores, 0.99)
    test_scores, test_labels, _ = _scores(model, test_loader, selected_device)
    positives = sum(label == 1 for label in test_labels)
    benign = sum(label == 0 for label in test_labels)
    true_positive = sum(label == 1 and score >= threshold for score, label in zip(test_scores, test_labels))
    false_positive = sum(label == 0 and score >= threshold for score, label in zip(test_scores, test_labels))
    final_checkpoint = {
        "model_state": model.state_dict(),
        "architecture": architecture,
        "config": config,
        "threshold": threshold,
    }
    torch.save(final_checkpoint, output_dir / "model.pt")
    vocabulary_source = Path(dataset_metadata["vocabulary_file"])
    if vocabulary_source.is_file():
        shutil.copy2(vocabulary_source, output_dir / "vocabulary.json")
    summary = {
        "architecture": architecture,
        "threshold": threshold,
        "samples": dataset_metadata["samples"],
        "splits": dataset_metadata["splits"],
        "validation_benign_count": len(benign_scores),
        "test_true_positive": true_positive,
        "test_false_positive": false_positive,
        "test_recall": true_positive / positives if positives else None,
        "test_false_alarm_rate": false_positive / max(1, benign),
    }
    metadata = {
        "artifact_version": "neural-detector-v1",
        "architecture": architecture,
        "config": config,
        "threshold": threshold,
        "calibration": "99th percentile of validation benign final scores",
        "split_rule": dataset_metadata["split_rule"],
        "dataset_format": dataset_metadata["format_version"],
        "hardware": hardware_info(),
        "selected_device": selected_device,
        "python": sys.version,
        "numpy": np.__version__,
        "dependencies": {
            package: _package_version(package)
            for package in ("torch", "numpy", "ijson")
        },
        "git_revision": _version(["git", "rev-parse", "HEAD"]),
        "training_summary": summary,
        "history": history,
        "best_epoch": int(best_checkpoint["epoch"]),
    }
    (output_dir / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    (output_dir / "training_summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    (output_dir / "training_history.json").write_text(json.dumps(history, indent=2) + "\n", encoding="utf-8")
    shutil.copy2(dataset_dir / "manifest.json", output_dir / "split_manifest.json")
    print(json.dumps(summary, indent=2))
    return summary


def _package_version(package: str) -> str | None:
    try:
        return importlib.metadata.version(package)
    except importlib.metadata.PackageNotFoundError:
        return None
