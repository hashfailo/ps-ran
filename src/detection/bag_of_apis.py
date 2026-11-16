"""Persistence and incremental inference for the Bag-of-APIs detector."""

from __future__ import annotations

import json
import math
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Mapping


MODEL_VERSION = "bag-of-apis-v1"


def _sigmoid(value: float) -> float:
    if value >= 0:
        z = math.exp(-min(value, 60.0))
        return 1.0 / (1.0 + z)
    z = math.exp(max(value, -60.0))
    return z / (1.0 + z)


class BagOfAPIsModel:
    """Multinomial API model with a bounded incremental score."""

    def __init__(
        self,
        vocabulary: list[str],
        log_probabilities: Mapping[str, list[float]],
        log_priors: Mapping[str, float],
        threshold: float,
        metadata: Mapping[str, Any] | None = None,
    ) -> None:
        if set(log_probabilities) != {"benign", "ransomware"}:
            raise ValueError("model must contain benign and ransomware probabilities")
        if len(log_probabilities["benign"]) != len(vocabulary):
            raise ValueError("probability and vocabulary lengths differ")
        self.vocabulary = vocabulary
        self.index = {api: index for index, api in enumerate(vocabulary)}
        self.log_probabilities = {
            label: list(values) for label, values in log_probabilities.items()
        }
        self.log_priors = dict(log_priors)
        self.threshold = float(threshold)
        self.metadata = dict(metadata or {})

    def score_counts(self, counts: Mapping[str, int], events: int) -> float:
        if events <= 0:
            return 0.5
        log_odds = self.log_priors["ransomware"] - self.log_priors["benign"]
        log_odds += sum(
            count
            * (
                self.log_probabilities["ransomware"][self.index[api]]
                - self.log_probabilities["benign"][self.index[api]]
            )
            for api, count in counts.items()
            if api in self.index
        ) / events
        return _sigmoid(log_odds)

    def score_event(self, api: str, counts: Mapping[str, int], events: int) -> float:
        return self.score_counts(counts, events)

    def to_dict(self) -> dict[str, Any]:
        return {
            "model_version": MODEL_VERSION,
            "vocabulary": self.vocabulary,
            "log_probabilities": self.log_probabilities,
            "log_priors": self.log_priors,
            "threshold": self.threshold,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "BagOfAPIsModel":
        if data.get("model_version") != MODEL_VERSION:
            raise ValueError(f"unsupported model version: {data.get('model_version')}")
        return cls(
            list(data["vocabulary"]),
            data["log_probabilities"],
            data["log_priors"],
            float(data["threshold"]),
            data.get("metadata"),
        )

    def save(self, directory: Path) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "model.json"
        temporary = path.with_suffix(".json.tmp")
        temporary.write_text(
            json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.replace(path)

    @classmethod
    def load(cls, directory: Path) -> "BagOfAPIsModel":
        path = directory / "model.json"
        return cls.from_dict(json.loads(path.read_text(encoding="utf-8")))


class IncrementalBagOfAPIs:
    """Stateful, event-at-a-time inference for replay and WebSocket sessions."""

    def __init__(self, model: BagOfAPIsModel) -> None:
        self.model = model
        self.counts: Counter[str] = Counter()
        self.events = 0
        self.first_alert: dict[str, Any] | None = None

    def update(self, api: str, event_position: int | None = None) -> dict[str, Any]:
        normalized = str(api or "").strip().lower()
        self.events += 1
        if normalized in self.model.index:
            self.counts[normalized] += 1
        score = self.model.score_event(normalized, self.counts, self.events)
        alert = score >= self.model.threshold
        if alert and self.first_alert is None:
            self.first_alert = {
                "event_position": event_position if event_position is not None else self.events - 1,
                "trace_fraction": None,
                "score": score,
            }
        return {
            "score": score,
            "threshold": self.model.threshold,
            "alert": alert,
            "events_seen": self.events,
            "vocabulary_hit": normalized in self.model.index,
        }

    def reset(self) -> None:
        self.counts.clear()
        self.events = 0
        self.first_alert = None
