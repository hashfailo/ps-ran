"""Recorded-trace replay state for the web demonstration."""

from __future__ import annotations

import asyncio
import time
from collections import Counter
from pathlib import Path
from typing import Any, Awaitable, Callable

from scripts.phase1.cape_parser import iter_report_events
from scripts.phase1.event_normalizer import enrich_event
from scripts.phase1.handle_tracker import HandleTracker

from .bag_of_apis import IncrementalBagOfAPIs


EventSender = Callable[[dict[str, Any]], Awaitable[None]]


def count_events(item: dict[str, Any]) -> int:
    return sum(
        1
        for _ in iter_report_events(
            item["path"],
            item["sample_id"],
            item["class_label"],
            item["relative_report_path"],
        )
    )


class ReplaySession:
    def __init__(self, session_id: str, model: Any) -> None:
        self.session_id = session_id
        self.model = model
        self.sample: dict[str, Any] | None = None
        self.total_events = 0
        self.position = 0
        self.status = "idle"
        self.speed = 20.0
        self.pause_event = asyncio.Event()
        self.pause_event.set()
        self.stop_requested = False
        self.task: asyncio.Task[None] | None = None
        self.first_alert: dict[str, Any] | None = None
        self.activity_at_alert: dict[str, int] | None = None
        self.score = 0.5
        self.activity: Counter[str] = Counter()
        self.tracker: HandleTracker | None = None
        self.scores: list[float] = []
        self._lock = asyncio.Lock()

    async def configure(self, sample: dict[str, Any], speed: float) -> None:
        async with self._lock:
            if self.task and not self.task.done():
                raise RuntimeError("replay is already running")
            self.sample = sample
            self.speed = max(0.0, min(float(speed), 100.0))
            self.total_events = count_events(sample)
            self.position = 0
            self.status = "ready"
            self.first_alert = None
            self.activity_at_alert = None
            self.score = 0.5
            self.activity = Counter()
            self.tracker = HandleTracker()
            self.scores = []
            self.stop_requested = False
            self.pause_event.set()

    async def start(self, sender: EventSender) -> None:
        if self.sample is None:
            raise RuntimeError("select a sample before starting replay")
        if self.task and not self.task.done():
            return
        self.stop_requested = False
        self.pause_event.set()
        self.task = asyncio.create_task(self._run(sender))

    async def pause(self) -> None:
        self.pause_event.clear()
        self.status = "paused"

    async def resume(self) -> None:
        self.pause_event.set()
        if self.status == "paused":
            self.status = "running"

    async def reset(self) -> None:
        self.stop_requested = True
        if self.task and not self.task.done():
            self.task.cancel()
        if self.sample is not None:
            sample = self.sample
            speed = self.speed
            await self.configure(sample, speed)
        else:
            self.status = "idle"

    async def _run(self, sender: EventSender) -> None:
        assert self.sample is not None
        assert self.tracker is not None
        self.status = "running"
        predictor = (
            self.model.create_stream()
            if hasattr(self.model, "create_stream")
            else IncrementalBagOfAPIs(self.model)
        )
        try:
            for event in iter_report_events(
                self.sample["path"],
                self.sample["sample_id"],
                self.sample["class_label"],
                self.sample["relative_report_path"],
            ):
                await self.pause_event.wait()
                if self.stop_requested:
                    return
                enrich_event(event)
                self.tracker.observe(event)
                self.position += 1
                api = event.api_normalized
                result = predictor.update(api, event.process_call_position)
                self.score = result["score"]
                self.scores.append(self.score)
                for key in ("writes", "reads", "deletes", "renames", "file_information"):
                    if (
                        event.operation_kind == key[:-1]
                        or (key == "file_information" and event.operation_kind == "set_file_information")
                        or (key == "writes" and "writefile" in api)
                        or (key == "reads" and "readfile" in api)
                        or (key == "deletes" and "delete" in api)
                        or (key == "renames" and "movefile" in api)
                    ):
                        self.activity[key] += 1
                if result["alert"] and self.first_alert is None:
                    self.first_alert = {
                        "event_position": self.position,
                        "trace_fraction": self.position / max(1, self.total_events),
                        "score": self.score,
                    }
                    self.activity_at_alert = self.activity_snapshot()
                await sender(
                    {
                        "type": "event",
                        "event": {
                            "position": self.position,
                            "total": self.total_events,
                            "api": event.api_normalized,
                            "operation_kind": event.operation_kind,
                            "process_id": event.process_id,
                            "status": event.status_raw,
                            "file_related": bool(event.handle_observations or event.path_observations),
                            "arguments": list(event.arguments_normalized)[:8],
                        },
                        "prediction": {
                            **result,
                            "trace_fraction": self.position / max(1, self.total_events),
                        },
                        "activity": self.activity_snapshot(),
                        "lifecycle": {
                            "candidate_generations": self.tracker.counts["handle_generations"],
                            "ambiguous_observations": len(self.tracker.ambiguities),
                            "unresolved_observations": self.tracker.counts["operation_without_create"]
                            + self.tracker.counts["close_without_create"],
                        },
                    }
                )
                if self.speed:
                    await asyncio.sleep(1.0 / self.speed)
            self.status = "completed"
            await sender({"type": "complete", "result": self.result()})
        except asyncio.CancelledError:
            self.status = "idle"
            raise
        except Exception as exc:
            self.status = "error"
            await sender({"type": "error", "message": f"{type(exc).__name__}: {exc}"})

    def activity_snapshot(self) -> dict[str, int]:
        return {key: int(self.activity.get(key, 0)) for key in ("writes", "reads", "deletes", "renames", "file_information")}

    def result(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "alerted": self.first_alert is not None,
            "first_alert": self.first_alert,
            "events_seen": self.position,
            "total_events": self.total_events,
            "activity_before_alert": self.activity_at_alert or self.activity_snapshot(),
            "completed_without_alert": self.status == "completed" and self.first_alert is None,
        }
