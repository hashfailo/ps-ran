"""Small causal PyTorch architectures and persisted artifact loading."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def require_torch():
    try:
        import torch
        from torch import nn
    except ImportError as exc:
        raise RuntimeError(
            "PyTorch is required for neural models. Install requirements-neural.txt."
        ) from exc
    return torch, nn


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


def build_model(architecture: str, config: dict[str, Any]):
    torch, nn = require_torch()
    vocab_size = int(config["vocabulary_size"]) + 1
    embedding_dim = int(config["embedding_dim"])
    hidden_dim = int(config["hidden_dim"])
    num_classes = 2

    class CausalCNN(nn.Module):
        def __init__(self):
            super().__init__()
            self.embedding = nn.Embedding(vocab_size, embedding_dim, padding_idx=0)
            self.conv1 = nn.Conv1d(embedding_dim, hidden_dim, 5)
            self.conv2 = nn.Conv1d(hidden_dim, hidden_dim, 5)
            self.dropout = nn.Dropout(float(config["dropout"]))
            self.head = nn.Linear(hidden_dim, num_classes)

        def forward(self, x, lengths=None):
            z = self.embedding(x).transpose(1, 2)
            z = nn.functional.pad(z, (4, 0))
            z = nn.functional.gelu(self.conv1(z))
            z = nn.functional.pad(z, (4, 0))
            z = nn.functional.gelu(self.conv2(z))
            if lengths is None:
                pooled = z[:, :, -1]
            else:
                positions = (lengths.clamp_min(1) - 1).view(-1, 1, 1).expand(-1, z.size(1), 1)
                pooled = z.gather(2, positions).squeeze(2)
            return self.head(self.dropout(pooled))

    class CausalGRU(nn.Module):
        def __init__(self):
            super().__init__()
            self.embedding = nn.Embedding(vocab_size, embedding_dim, padding_idx=0)
            self.gru = nn.GRU(
                embedding_dim,
                hidden_dim,
                num_layers=int(config["layers"]),
                batch_first=True,
                dropout=float(config["dropout"]) if int(config["layers"]) > 1 else 0.0,
            )
            self.dropout = nn.Dropout(float(config["dropout"]))
            self.head = nn.Linear(hidden_dim, num_classes)

        def forward(self, x, lengths=None):
            z, _ = self.gru(self.embedding(x))
            if lengths is None:
                pooled = z[:, -1]
            else:
                positions = (lengths.clamp_min(1) - 1).view(-1, 1, 1).expand(-1, 1, z.size(2))
                pooled = z.gather(1, positions).squeeze(1)
            return self.head(self.dropout(pooled))

    class CausalTransformer(nn.Module):
        def __init__(self):
            super().__init__()
            self.embedding = nn.Embedding(vocab_size, embedding_dim, padding_idx=0)
            self.position = nn.Embedding(int(config["sequence_length"]), embedding_dim)
            layer = nn.TransformerEncoderLayer(
                d_model=embedding_dim,
                nhead=int(config["heads"]),
                dim_feedforward=hidden_dim * 2,
                dropout=float(config["dropout"]),
                batch_first=True,
                activation="gelu",
                norm_first=True,
            )
            self.encoder = nn.TransformerEncoder(layer, num_layers=int(config["layers"]))
            self.head = nn.Linear(embedding_dim, num_classes)

        def forward(self, x, lengths=None):
            positions = self.position(
                torch.arange(x.size(1), device=x.device).clamp_max(self.position.num_embeddings - 1)
            )
            z = self.embedding(x) + positions
            steps = x.size(1)
            causal = torch.triu(torch.ones(steps, steps, device=x.device, dtype=torch.bool), diagonal=1)
            padding = x.eq(0)
            z = self.encoder(z, mask=causal, src_key_padding_mask=padding)
            if lengths is None:
                pooled = z[:, -1]
            else:
                positions = (lengths.clamp_min(1) - 1).view(-1, 1, 1).expand(-1, 1, z.size(2))
                pooled = z.gather(1, positions).squeeze(1)
            return self.head(pooled)

    classes = {
        "xran_style_cnn": CausalCNN,
        "gru": CausalGRU,
        "causal_transformer": CausalTransformer,
    }
    if architecture not in classes:
        raise ValueError(f"unsupported architecture: {architecture}")
    return classes[architecture]()


class NeuralIncremental:
    """Causal prefix scorer used by replay and local validation."""

    def __init__(self, handle: "NeuralModelHandle"):
        self.handle = handle
        self.tokens: list[int] = []
        self.events = 0
        self.first_alert: dict[str, Any] | None = None

    def update(self, api: str, event_position: int | None = None) -> dict[str, Any]:
        torch, _ = require_torch()
        normalized = str(api or "").strip().lower()
        token = self.handle.vocabulary.get(normalized, 0)
        if len(self.tokens) < self.handle.sequence_length:
            self.tokens.append(token)
        self.events += 1
        with torch.no_grad():
            sequence = torch.tensor([self.tokens], dtype=torch.long, device=self.handle.device)
            lengths = torch.tensor([len(self.tokens)], dtype=torch.long, device=self.handle.device)
            score = float(torch.softmax(self.handle.model(sequence, lengths), dim=1)[0, 1].cpu())
        alert = score >= self.handle.threshold
        if alert and self.first_alert is None:
            self.first_alert = {
                "event_position": event_position if event_position is not None else self.events - 1,
                "trace_fraction": None,
                "score": score,
            }
        return {
            "score": score,
            "threshold": self.handle.threshold,
            "alert": alert,
            "events_seen": self.events,
            "vocabulary_hit": normalized in self.handle.vocabulary,
        }


class NeuralModelHandle:
    def __init__(self, model, metadata: dict[str, Any], vocabulary: dict[str, int], device: str):
        self.model = model
        self.metadata = metadata
        self.vocabulary = vocabulary
        self.device = device
        self.threshold = float(metadata["threshold"])
        self.sequence_length = int(metadata["config"]["sequence_length"])

    def create_stream(self) -> NeuralIncremental:
        return NeuralIncremental(self)


def load_neural_artifact(model_dir: str | Path, device: str = "cpu"):
    torch, _ = require_torch()
    directory = Path(model_dir)
    metadata = json.loads((directory / "metadata.json").read_text(encoding="utf-8"))
    model = build_model(metadata["architecture"], metadata["config"])
    checkpoint = torch.load(directory / "model.pt", map_location=device, weights_only=True)
    model.load_state_dict(checkpoint["model_state"])
    model.to(device)
    model.eval()
    vocabulary = {
        api: index + 1
        for index, api in enumerate(
            json.loads((directory / "vocabulary.json").read_text(encoding="utf-8"))
        )
    }
    return NeuralModelHandle(model, metadata, vocabulary, device)
