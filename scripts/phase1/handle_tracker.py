"""Process-scoped candidate handle generations."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .models import Event


@dataclass
class HandleGeneration:
    process_id: str
    handle: str
    generation: int
    created_positions: List[int] = field(default_factory=list)
    closed_positions: List[int] = field(default_factory=list)
    paths: set[str] = field(default_factory=set)
    status: str = "unresolved"
    origin: str = "operation_first"
    established_by_successful_create_open: bool = False
    candidate_key: str = ""


class HandleTracker:
    def __init__(self) -> None:
        self.generations: Dict[Tuple[str, str], List[HandleGeneration]] = {}
        self.counts: Counter[str] = Counter()
        self.ambiguities: List[Dict[str, Any]] = []
        self.path_to_candidates: Dict[str, set[str]] = {}

    def _key(self, event: Event, handle: str) -> Tuple[str, str]:
        return event.process_id, handle

    def _current(self, event: Event, handle: str) -> Optional[HandleGeneration]:
        generations = self.generations.get(self._key(event, handle), [])
        return generations[-1] if generations else None

    def _new_generation(self, event: Event, handle: str) -> HandleGeneration:
        generations = self.generations.setdefault(self._key(event, handle), [])
        generation = HandleGeneration(
            process_id=event.process_id,
            handle=handle,
            generation=len(generations),
            candidate_key=f"{event.sample_id}:{event.process_id}:{handle}:g{len(generations)}",
        )
        generations.append(generation)
        self.counts["handle_generations"] += 1
        return generation

    def _record_create_open_observation(self, event: Event, observation: Dict[str, Any]) -> None:
        status = event.status_raw
        if status is True:
            self.counts["successful_create_open_observations"] += 1
        elif status is False:
            self.counts["failed_create_open_observations"] += 1
            observation["identity_tracking"] = "unsuccessful_output_observation"
        else:
            self.counts["unknown_create_open_observations"] += 1
            observation["identity_tracking"] = "unknown_output_observation"

    def _generation_for_operation(
        self, event: Event, handle: str
    ) -> HandleGeneration:
        generation = self._current(event, handle)
        if (
            generation is None
            or generation.closed_positions
            or generation.status == "uncertain_after_create_open_failure"
        ):
            if generation is not None and generation.closed_positions:
                self.counts["candidate_reuse_after_close"] += 1
            generation = self._new_generation(event, handle)
            generation.origin = "operation_first"
            self.counts["operation_first_generations"] += 1
        return generation

    def observe(self, event: Event) -> None:
        for observation in event.handle_observations:
            handle = observation.get("normalized_handle")
            role = observation.get("file_handle_role")
            if role == "close" and handle and self._current(event, handle) is None:
                self.counts["close_without_create"] += 1
                observation["object_type"] = "uncertain"
                observation["identity_tracking"] = "close_without_established_file_generation"
                continue
            if not handle or observation.get("object_type") != "file_candidate":
                if observation.get("object_type") != "file_candidate":
                    observation["identity_tracking"] = "excluded_non_file_or_unknown"
                continue
            is_close = role == "close"
            is_create = role in {"create_attempt", "open_attempt"}
            generation = self._current(event, handle)
            if is_create:
                self._record_create_open_observation(event, observation)
                if event.status_raw is not True:
                    if generation is not None and not generation.closed_positions:
                        generation.status = "uncertain_after_create_open_failure"
                        reason = (
                            "failed_create_open_conflicts_with_current_generation"
                            if event.status_raw is False
                            else "unknown_create_open_conflicts_with_current_generation"
                        )
                        observation["identity_tracking"] = reason
                        self.ambiguities.append(
                            {
                                "sample_id": event.sample_id,
                                "class_label": event.class_label,
                                "report_path": event.report_path,
                                "process_id": event.process_id,
                                "handle": handle,
                                "generation": generation.generation,
                                "event_position": event.process_call_position,
                                "api_normalized": event.api_normalized,
                                "reason": reason,
                                "confirmed_invalid": False,
                            }
                        )
                    continue
                if generation is not None and not generation.closed_positions:
                    self.counts["repeated_create_observations"] += 1
                    self.ambiguities.append(
                        {
                            "sample_id": event.sample_id,
                            "class_label": event.class_label,
                            "report_path": event.report_path,
                            "process_id": event.process_id,
                            "handle": handle,
                            "generation": generation.generation,
                            "event_position": event.process_call_position,
                            "api_normalized": event.api_normalized,
                            "reason": "repeated_successful_create_open_on_active_generation",
                            "confirmed_invalid": False,
                        }
                    )
                elif generation is not None and generation.closed_positions:
                    self.counts["candidate_reuse_after_close"] += 1
                if (
                    generation is None
                    or generation.closed_positions
                    or generation.origin == "operation_first"
                    or generation.status == "uncertain_after_create_open_failure"
                ):
                    generation = self._new_generation(event, handle)
                    generation.origin = "successful_create_open"
                    generation.established_by_successful_create_open = True
                    self.counts["successful_create_open_generations"] += 1
                generation.created_positions.append(event.process_call_position)
            elif is_close:
                if generation is None:
                    self.counts["close_without_create"] += 1
                    observation["identity_tracking"] = "close_without_established_file_generation"
                    observation["object_type"] = "uncertain"
                    continue
                elif generation.closed_positions:
                    self.counts["repeated_close_observations"] += 1
                generation.closed_positions.append(event.process_call_position)
                generation.status = "closed_candidate"
            else:
                was_closed = generation is not None and bool(generation.closed_positions)
                was_uncertain = (
                    generation is not None
                    and generation.status == "uncertain_after_create_open_failure"
                )
                if was_closed:
                    self.counts["post_close_reference"] += 1
                    self.ambiguities.append(
                        {
                            "sample_id": event.sample_id,
                            "class_label": event.class_label,
                            "report_path": event.report_path,
                            "process_id": event.process_id,
                            "handle": handle,
                            "generation": generation.generation,
                            "event_position": event.process_call_position,
                            "api_normalized": event.api_normalized,
                            "reason": "operation_after_candidate_close",
                            "confirmed_invalid": False,
                        }
                    )
                if generation is None or generation.closed_positions or was_uncertain:
                    if generation is None:
                        self.counts["operation_without_create"] += 1
                    generation = self._generation_for_operation(event, handle)
                    observation["identity_tracking"] = "operation_first_candidate"
                for path in event.path_observations:
                    if path["state"] == "usable":
                        generation.paths.add(str(path["raw_value"]))
            observation["candidate_key"] = generation.candidate_key
            observation["generation"] = generation.generation
        for path in event.path_observations:
            if path["state"] != "usable":
                continue
            for observation in event.handle_observations:
                key = observation.get("candidate_key")
                if not key:
                    continue
                generation = next(
                    (g for gs in self.generations.values() for g in gs if g.candidate_key == key),
                    None,
                )
                if generation is not None:
                    generation.paths.add(str(path["raw_value"]))
        event.file_identity_candidates = [
            {
                "candidate_key": o["candidate_key"],
                "generation": o["generation"],
                "resolution": "candidate_process_handle_generation",
            }
            for o in event.handle_observations
            if o.get("candidate_key")
        ]
        usable_paths = {
            str(path["raw_value"])
            for path in event.path_observations
            if path["state"] == "usable"
        }
        file_observations = [
            o for o in event.handle_observations
            if o.get("object_type") == "file_candidate"
        ]
        if len(file_observations) > 1:
            self.ambiguities.append(
                {
                    "sample_id": event.sample_id,
                    "class_label": event.class_label,
                    "report_path": event.report_path,
                    "process_id": event.process_id,
                    "event_position": event.process_call_position,
                    "api_normalized": event.api_normalized,
                    "reason": "multiple_file_handles_in_event",
                    "candidate_keys": [
                        o.get("candidate_key") for o in file_observations
                    ],
                }
            )
        if usable_paths and len(file_observations) == 0:
            self.ambiguities.append(
                {
                    "sample_id": event.sample_id,
                    "class_label": event.class_label,
                    "report_path": event.report_path,
                    "process_id": event.process_id,
                    "event_position": event.process_call_position,
                    "api_normalized": event.api_normalized,
                    "reason": "path_only_observation",
                    "paths": sorted(usable_paths),
                }
            )
        if file_observations and not usable_paths:
            self.ambiguities.append(
                {
                    "sample_id": event.sample_id,
                    "class_label": event.class_label,
                    "report_path": event.report_path,
                    "process_id": event.process_id,
                    "event_position": event.process_call_position,
                    "api_normalized": event.api_normalized,
                    "reason": "file_handle_only_observation",
                    "candidate_keys": [
                        o.get("candidate_key") for o in file_observations
                    ],
                }
            )
        for observation in file_observations:
            key = observation.get("candidate_key")
            if not key:
                continue
            generation = next(
                (g for gs in self.generations.values() for g in gs if g.candidate_key == key),
                None,
            )
            if generation is not None and len(generation.paths) > 1:
                self.ambiguities.append(
                    {
                        "sample_id": event.sample_id,
                        "class_label": event.class_label,
                        "report_path": event.report_path,
                        "process_id": event.process_id,
                        "event_position": event.process_call_position,
                        "api_normalized": event.api_normalized,
                        "reason": "one_handle_multiple_paths",
                        "candidate_key": key,
                        "paths": sorted(generation.paths),
                    }
                )
        for path in usable_paths:
            candidates = self.path_to_candidates.setdefault(path, set())
            before = len(candidates)
            candidates.update(
                o["candidate_key"]
                for o in file_observations
                if o.get("candidate_key")
            )
            if before <= 1 and len(candidates) > 1:
                self.ambiguities.append(
                    {
                        "sample_id": event.sample_id,
                        "class_label": event.class_label,
                        "report_path": event.report_path,
                        "process_id": event.process_id,
                        "event_position": event.process_call_position,
                        "api_normalized": event.api_normalized,
                        "reason": "multiple_handles_one_path",
                        "raw_path": path,
                        "candidate_keys": sorted(candidates),
                    }
                )
