"""Streaming CAPE report ingestion with raw-preserving call parsing."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterator, Optional

import ijson

from .models import Event

PID_KEYS = ("process_id", "pid", "processid", "processId")
PARENT_KEYS = ("parent_id", "parentid", "parentId")
ID_KEYS = ("id", "call_id", "callid")
TIMESTAMP_KEYS = ("timestamp", "time", "ts")


def first(mapping: Dict[str, Any], keys: tuple[str, ...]) -> Any:
    for key in keys:
        if key in mapping:
            return mapping[key]
    return None


def normalize_api(value: Any) -> str:
    return "" if value is None else str(value).strip().lower()


def argument_entries(arguments: Any) -> Iterator[tuple[str, Any, Any]]:
    if isinstance(arguments, dict):
        for name, value in arguments.items():
            yield str(name), value, None
    elif isinstance(arguments, list):
        for item in arguments:
            if not isinstance(item, dict) or "name" not in item:
                continue
            yield str(item["name"]), item.get("value"), item.get("pretty_value")


def normalize_arguments(arguments: Any) -> Dict[str, list[Dict[str, Any]]]:
    result: Dict[str, list[Dict[str, Any]]] = {}
    for name, value, pretty in argument_entries(arguments):
        item: Dict[str, Any] = {"value": value}
        if pretty is not None:
            item["pretty_value"] = pretty
        result.setdefault(name, []).append(item)
    return result


def event_arguments(event: Event) -> Dict[str, Any]:
    return {
        name: [entry.get("value") for entry in entries]
        for name, entries in event.arguments_normalized.items()
    }


def iter_report_events(
    report_path: Path,
    sample_id: str,
    class_label: str,
    relative_report_path: str,
) -> Iterator[Event]:
    with report_path.open("rb") as stream:
        for process_index, process in enumerate(
            ijson.items(stream, "behavior.processes.item")
        ):
            if not isinstance(process, dict):
                continue
            raw_process_id = first(process, PID_KEYS)
            # Do not collapse unrelated records with a shared "None" key.
            process_id = (
                str(raw_process_id)
                if raw_process_id is not None
                else f"missing-process-{process_index}"
            )
            parent_id = first(process, PARENT_KEYS)
            calls = process.get("calls")
            if not isinstance(calls, list):
                continue
            for position, call in enumerate(calls):
                if not isinstance(call, dict):
                    continue
                api_raw = call.get("api")
                api_normalized = normalize_api(api_raw)
                normalized = normalize_arguments(call.get("arguments"))
                yield Event(
                    sample_id=sample_id,
                    class_label=class_label,
                    report_path=relative_report_path,
                    source_process_index=process_index,
                    process_call_position=position,
                    process_id=process_id,
                    parent_process_id=None if parent_id is None else str(parent_id),
                    process_name=process.get("process_name"),
                    module_path=process.get("module_path"),
                    call_id_raw=first(call, ID_KEYS),
                    timestamp_raw=first(call, TIMESTAMP_KEYS),
                    api_raw=api_raw,
                    api_normalized=api_normalized,
                    category_raw=call.get("category"),
                    thread_id_raw=call.get("thread_id"),
                    status_raw=call.get("status"),
                    return_raw=call.get("return"),
                    repeated_raw=call.get("repeated"),
                    arguments_raw=call.get("arguments"),
                    arguments_normalized=normalized,
                    operation_kind="unknown",
                    warnings=["missing_process_id"] if raw_process_id is None else [],
                )

