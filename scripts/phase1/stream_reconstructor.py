"""Reconstruct one sample while preserving primary and merged views."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Iterable, List, Tuple

from .event_normalizer import enrich_event
from .handle_tracker import HandleTracker
from .models import Event


def timestamp_key(value: Any) -> Tuple[int, str]:
    if value is None:
        return (1, "")
    text = str(value)
    try:
        return (0, datetime.fromisoformat(text.replace(",", ".")).isoformat())
    except ValueError:
        return (1, text)


def reconstruct(events: Iterable[Event]) -> tuple[List[Event], List[Event], HandleTracker]:
    primary: List[Event] = []
    tracker = HandleTracker()
    for event in events:
        enrich_event(event)
        tracker.observe(event)
        primary.append(event)
    merged = sorted(
        primary,
        key=lambda e: (
            timestamp_key(e.timestamp_raw),
            e.source_process_index,
            e.process_call_position,
        ),
    )
    return primary, merged, tracker

