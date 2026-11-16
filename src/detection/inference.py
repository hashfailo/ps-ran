"""Independent model-loading and event inference API."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .bag_of_apis import BagOfAPIsModel, IncrementalBagOfAPIs


def load_saved_model(model_dir: str | Path) -> BagOfAPIsModel:
    """Load persisted parameters and calibration without fitting."""
    return BagOfAPIsModel.load(Path(model_dir))


def infer_api_event(
    model: BagOfAPIsModel,
    predictor: IncrementalBagOfAPIs,
    api: str,
    event_position: int | None = None,
) -> dict[str, Any]:
    """Update an incremental predictor with one normalized API event."""
    return predictor.update(api, event_position)
