#!/usr/bin/env python3
"""Audit call ordering and per-process file-handle observations in CAPE reports."""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import math
import os
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, DefaultDict, Dict, Iterable, List, Optional, Set, Tuple

try:
    import ijson
except ImportError as exc:
    print(
        "Error: ijson is required. Install it in the Python environment used to "
        "run this script; no dependency was installed automatically.",
        file=sys.stderr,
    )
    raise SystemExit(2) from exc


CLASS_NAMES = ("benign", "ransomware")
FILE_APIS = {
    "NtCreateFile",
    "NtWriteFile",
    "WriteFile",
    "NtSetInformationFile",
    "NtClose",
    "MoveFileExW",
    "MoveFileW",
    "DeleteFileW",
    "NtDeleteFile",
    "CopyFileW",
    "CopyFileA",
}
PID_KEYS = ("process_id", "pid", "processid", "processId")
ID_KEYS = ("id", "call_id", "callid")
TIMESTAMP_KEYS = ("timestamp", "time", "ts")
MAX_VALUE_LENGTH = 240


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Audit CAPE event IDs, timestamps, and per-process file handles."
    )
    parser.add_argument("dataset_root", type=Path)
    parser.add_argument(
        "-n",
        "--reports-per-class",
        type=int,
        default=10,
        help="Reports per class (default: 10)",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        default=Path("outputs/phase0c"),
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Allow replacing existing Phase 0C outputs",
    )
    return parser.parse_args()


def warn(message: str) -> None:
    print(f"Warning: {message}", file=sys.stderr)


def first(mapping: Dict[str, Any], keys: Iterable[str]) -> Any:
    for key in keys:
        if key in mapping:
            return mapping[key]
    return None


def process_id(process: Dict[str, Any]) -> Any:
    return first(process, PID_KEYS)


def call_id(call: Dict[str, Any]) -> Any:
    return first(call, ID_KEYS)


def timestamp_value(call: Dict[str, Any]) -> Any:
    return first(call, TIMESTAMP_KEYS)


def numeric(value: Any) -> Optional[float]:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def parse_timestamp(value: Any) -> Optional[float]:
    parsed = numeric(value)
    if parsed is not None:
        return parsed
    if isinstance(value, str):
        try:
            return dt.datetime.fromisoformat(value.strip().replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None
    return None


def compact(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        value = json.dumps(value, separators=(",", ":"), ensure_ascii=True)
    value = str(value).replace("\x00", "\\x00")
    return value if len(value) <= MAX_VALUE_LENGTH else value[:MAX_VALUE_LENGTH] + "...<truncated>"


def named_arguments(call: Dict[str, Any]) -> Dict[str, Any]:
    arguments = call.get("arguments")
    if isinstance(arguments, dict):
        return {str(k): v for k, v in arguments.items()}
    if isinstance(arguments, list):
        result: Dict[str, Any] = {}
        for item in arguments:
            if isinstance(item, dict) and "name" in item and "value" in item:
                value: Any = item["value"]
                if "pretty_value" in item:
                    value = {"value": value, "pretty_value": item["pretty_value"]}
                result[str(item["name"])] = value
        return result
    return {}


def handle_value(value: Any) -> Optional[str]:
    if value is None:
        return None
    return compact(value)


def path_values(arguments: Dict[str, Any]) -> Set[str]:
    values: Set[str] = set()
    for key in (
        "FileName",
        "HandleName",
        "ExistingFileName",
        "NewFileName",
        "FilePath",
        "Path",
    ):
        value = arguments.get(key)
        if value is not None:
            if isinstance(value, dict):
                value = value.get("value", value)
            values.add(compact(value))
    return values


def discover_reports(root: Path, class_name: str) -> List[Tuple[Path, int]]:
    reports: List[Tuple[Path, int]] = []
    class_root = root / class_name
    if not class_root.is_dir():
        warn(f"class directory not found: {class_root}")
        return reports
    for current, dirs, files in os.walk(class_root, topdown=True, followlinks=False):
        dirs.sort()
        for filename in sorted(files):
            if filename != "report.json":
                continue
            path = Path(current) / filename
            try:
                reports.append((path, path.stat().st_size))
            except OSError as exc:
                warn(f"cannot stat {path}: {exc}")
    return sorted(reports, key=lambda item: (item[1], item[0].relative_to(root).as_posix()))


def phase0b_paths(root: Path) -> Set[str]:
    summary_path = Path("outputs/phase0b/report_structure_summary.json")
    try:
        data = json.loads(summary_path.read_text(encoding="utf-8"))
        return {
            str(report["relative_report_path"])
            for report in data.get("reports", [])
            if isinstance(report, dict) and "relative_report_path" in report
        }
    except (OSError, ValueError, TypeError):
        return set()


def select_reports(
    root: Path, class_name: str, count: int
) -> Tuple[List[Tuple[Path, int]], Dict[str, Any]]:
    all_reports = discover_reports(root, class_name)
    excluded = phase0b_paths(root)
    available = [
        item for item in all_reports if item[0].relative_to(root).as_posix() not in excluded
    ]
    if len(available) < count:
        raise ValueError(f"{class_name}: only {len(available)} reports available; need {count}")
    lower_count = count // 2
    upper_count = count - lower_count
    selected = available[:lower_count] + available[-upper_count:]
    unique: List[Tuple[Path, int]] = []
    seen: Set[str] = set()
    for item in selected:
        relative = item[0].relative_to(root).as_posix()
        if relative not in seen:
            unique.append(item)
            seen.add(relative)
    if len(unique) != count:
        raise ValueError(f"{class_name}: size ranges did not yield {count} unique reports")
    return unique, {
        "available_reports_after_phase0b_exclusion": len(available),
        "excluded_phase0b_reports": sorted(excluded),
        "selection": "five smallest and five largest report sizes after Phase 0B exclusion",
    }


def empty_handle() -> Dict[str, Any]:
    return {
        "created": 0,
        "closed": 0,
        "operations": 0,
        "paths": set(),
        "created_paths": set(),
        "referenced_after_close": 0,
        "reuse_count": 0,
    }


def inspect_report(path: Path, root: Path, class_name: str) -> Dict[str, Any]:
    process_rows: List[Dict[str, Any]] = []
    timestamp_rows: List[Dict[str, Any]] = []
    handle_rows: List[Dict[str, Any]] = []
    ambiguous_rows: List[Dict[str, Any]] = []
    file_classes: Counter = Counter()
    all_timestamps: DefaultDict[float, Dict[str, Any]] = defaultdict(
        lambda: {"calls": 0, "processes": set(), "first_index": None}
    )
    report_call_index = 0
    report_ids: List[Tuple[str, Optional[float], Any]] = []
    errors: List[str] = []

    try:
        stream = path.open("rb")
    except OSError as exc:
        return {
            "class": class_name,
            "relative_report_path": path.relative_to(root).as_posix(),
            "report_size_bytes": path.stat().st_size if path.exists() else None,
            "processes": 0,
            "total_calls": 0,
            "errors": [str(exc)],
        }

    with stream:
        try:
            for process in ijson.items(stream, "behavior.processes.item"):
                if not isinstance(process, dict):
                    continue
                pid = process_id(process)
                pid_key = compact(pid)
                calls = process.get("calls", [])
                if not isinstance(calls, list):
                    calls = []
                ids: List[Any] = []
                numeric_ids: List[float] = []
                timestamps: List[float] = []
                timestamp_failures = 0
                timestamp_raw_count = 0
                duplicate_timestamps = 0
                previous_id: Optional[float] = None
                previous_timestamp: Optional[float] = None
                id_decreases = 0
                id_equals = 0
                timestamp_decreases = 0
                timestamp_equals = 0
                gaps: List[float] = []
                handles: Dict[str, Dict[str, Any]] = {}
                closed_handles: Set[str] = set()
                operations_by_handle: Counter = Counter()
                path_to_handles: DefaultDict[str, Set[str]] = defaultdict(set)
                api_counts: Counter = Counter()

                for call in calls:
                    if not isinstance(call, dict):
                        continue
                    report_call_index += 1
                    api = compact(call.get("api", "<missing>"))
                    api_counts[api] += 1
                    raw_id = call_id(call)
                    current_id = numeric(raw_id)
                    if raw_id is not None:
                        ids.append(raw_id)
                    if current_id is not None:
                        numeric_ids.append(current_id)
                        if previous_id is not None:
                            if current_id < previous_id:
                                id_decreases += 1
                            elif current_id == previous_id:
                                id_equals += 1
                        previous_id = current_id
                    raw_timestamp = timestamp_value(call)
                    current_timestamp = parse_timestamp(raw_timestamp)
                    if raw_timestamp is not None:
                        timestamp_raw_count += 1
                        if current_timestamp is None:
                            timestamp_failures += 1
                        else:
                            timestamps.append(current_timestamp)
                            if previous_timestamp is not None:
                                gap = current_timestamp - previous_timestamp
                                gaps.append(gap)
                                if gap < 0:
                                    timestamp_decreases += 1
                                elif gap == 0:
                                    timestamp_equals += 1
                            previous_timestamp = current_timestamp
                            all_timestamps[current_timestamp]["calls"] += 1
                            all_timestamps[current_timestamp]["processes"].add(pid_key)
                            if all_timestamps[current_timestamp]["first_index"] is None:
                                all_timestamps[current_timestamp]["first_index"] = report_call_index
                            elif len(all_timestamps[current_timestamp]["processes"]) > 1:
                                ambiguous_rows.append(
                                    {
                                        "relative_report_path": path.relative_to(root).as_posix(),
                                        "timestamp": current_timestamp,
                                        "process_ids": "|".join(
                                            sorted(all_timestamps[current_timestamp]["processes"])
                                        ),
                                        "calls_at_timestamp": all_timestamps[current_timestamp]["calls"],
                                        "reason": "timestamp shared across processes; no order inferred",
                                    }
                                )
                    arguments = named_arguments(call)
                    if api in FILE_APIS:
                        handle = handle_value(arguments.get("FileHandle"))
                        paths = path_values(arguments)
                        if api == "NtCreateFile" and handle:
                            record = handles.setdefault(handle, empty_handle())
                            if record["created"] or record["operations"]:
                                record["reuse_count"] += 1
                            record["created"] += 1
                            record["created_paths"].update(paths)
                            record["paths"].update(paths)
                            for path_value in paths:
                                path_to_handles[path_value].add(handle)
                        elif handle:
                            record = handles.setdefault(handle, empty_handle())
                            if handle in closed_handles:
                                record["referenced_after_close"] += 1
                            record["operations"] += 1
                            record["paths"].update(paths)
                            operations_by_handle[handle] += 1
                            for path_value in paths:
                                path_to_handles[path_value].add(handle)
                        if api == "NtClose" and handle:
                            record = handles.setdefault(handle, empty_handle())
                            record["closed"] += 1
                            closed_handles.add(handle)
                        if api == "NtSetInformationFile":
                            info_class = arguments.get("FileInformationClass")
                            if isinstance(info_class, dict):
                                value = info_class.get("value")
                                pretty = info_class.get("pretty_value")
                            else:
                                value, pretty = info_class, None
                            file_classes[(compact(value), compact(pretty))] += 1
                    report_ids.append((pid_key, current_id, raw_id))

                unique_ids = {compact(value) for value in ids}
                process_rows.append(
                    {
                        "relative_report_path": path.relative_to(root).as_posix(),
                        "class": class_name,
                        "process_id": pid_key,
                        "total_calls": len(calls),
                        "ids_present": len(ids),
                        "unique_ids": len(unique_ids),
                        "duplicate_ids": len(ids) - len(unique_ids),
                        "ids_numeric": len(numeric_ids) == len(ids),
                        "ids_non_numeric": len(ids) - len(numeric_ids),
                        "ids_increase_monotonically": id_decreases == 0,
                        "id_decreases": id_decreases,
                        "id_equal_adjacent": id_equals,
                        "minimum_id": min(numeric_ids) if numeric_ids else "",
                        "maximum_id": max(numeric_ids) if numeric_ids else "",
                        "timestamp_values_present": timestamp_raw_count,
                        "timestamp_parse_failures": timestamp_failures,
                        "timestamps_monotonic": timestamp_decreases == 0,
                        "timestamp_decreases": timestamp_decreases,
                        "duplicate_timestamp_adjacent": timestamp_equals,
                        "timestamp_unique_values": len(set(timestamps)),
                        "timestamp_resolution_min_gap": min((gap for gap in gaps if gap > 0), default=""),
                        "timestamp_gap_median": statistics.median(gaps) if gaps else "",
                        "timestamp_gap_mean": statistics.mean(gaps) if gaps else "",
                        "api_counts": dict(api_counts),
                        "handle_count": len(handles),
                        "handles_referenced_after_close": sum(
                            int(record["referenced_after_close"] > 0)
                            for record in handles.values()
                        ),
                        "handle_reuse_count": sum(
                            record["reuse_count"] for record in handles.values()
                        ),
                    }
                )
                timestamp_rows.append(
                    {
                        "relative_report_path": path.relative_to(root).as_posix(),
                        "class": class_name,
                        "process_id": pid_key,
                        "calls": len(calls),
                        "timestamps_present": timestamp_raw_count,
                        "parse_failures": timestamp_failures,
                        "timestamps_monotonic": timestamp_decreases == 0,
                        "timestamp_decreases": timestamp_decreases,
                        "duplicate_timestamp_adjacent": timestamp_equals,
                        "unique_timestamps": len(set(timestamps)),
                        "minimum_positive_gap": min((gap for gap in gaps if gap > 0), default=""),
                        "median_gap": statistics.median(gaps) if gaps else "",
                        "mean_gap": statistics.mean(gaps) if gaps else "",
                    }
                )
                for handle, record in handles.items():
                    handle_rows.append(
                        {
                            "relative_report_path": path.relative_to(root).as_posix(),
                            "class": class_name,
                            "process_id": pid_key,
                            "handle": handle,
                            "created_count": record["created"],
                            "closed_count": record["closed"],
                            "operation_count": record["operations"],
                            "created_paths": "|".join(sorted(record["created_paths"])),
                            "all_observed_paths": "|".join(sorted(record["paths"])),
                            "path_count": len(record["paths"]),
                            "referenced_after_ntclose": record["referenced_after_close"] > 0,
                            "references_after_ntclose": record["referenced_after_close"],
                            "reuse_count": record["reuse_count"],
                            "note": "NtClose may target non-file handles; this is call-sequence evidence only",
                        }
                    )
        except (ijson.common.JSONError, OSError, ValueError) as exc:
            errors.append(str(exc))

    cross_process_ids: DefaultDict[str, Set[float]] = defaultdict(set)
    for pid_key, id_value, _ in report_ids:
        if id_value is not None:
            cross_process_ids[compact(id_value)].add(pid_key)
    overlapping_ids = sum(len(processes) > 1 for processes in cross_process_ids.values())
    range_overlap_pairs = 0
    range_restart_candidates = 0
    for index, left in enumerate(process_rows):
        if left["minimum_id"] == "" or left["maximum_id"] == "":
            continue
        for right in process_rows[index + 1 :]:
            if right["minimum_id"] == "" or right["maximum_id"] == "":
                continue
            if (
                left["minimum_id"] <= right["maximum_id"]
                and right["minimum_id"] <= left["maximum_id"]
            ):
                range_overlap_pairs += 1
            if right["minimum_id"] <= left["maximum_id"]:
                range_restart_candidates += 1
    tie_rows = []
    for timestamp, data in sorted(all_timestamps.items()):
        if len(data["processes"]) > 1:
            tie_rows.append(
                {
                    "relative_report_path": path.relative_to(root).as_posix(),
                    "timestamp": timestamp,
                    "process_ids": "|".join(sorted(data["processes"])),
                    "calls_at_timestamp": data["calls"],
                    "reason": "timestamp shared across processes; no order inferred",
                }
            )
    ambiguous_rows = tie_rows
    return {
        "class": class_name,
        "sample_directory": path.parent.name,
        "relative_report_path": path.relative_to(root).as_posix(),
        "report_size_bytes": path.stat().st_size,
        "processes": process_rows,
        "timestamps": timestamp_rows,
        "handles": handle_rows,
        "ambiguous": ambiguous_rows,
        "file_information_classes": [
            {"value": value, "pretty_value": pretty, "count": count}
            for (value, pretty), count in sorted(file_classes.items())
        ],
        "cross_process_id_overlap_count": overlapping_ids,
        "cross_process_id_range_overlap_pairs": range_overlap_pairs,
        "cross_process_id_restart_candidates_in_stored_process_order": range_restart_candidates,
        "total_calls": sum(row["total_calls"] for row in process_rows),
        "errors": errors,
    }


def write_csv(path: Path, rows: List[Dict[str, Any]], fields: Tuple[str, ...]) -> None:
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def write_json(path: Path, data: Any) -> None:
    with path.open("w", encoding="utf-8") as stream:
        json.dump(data, stream, indent=2, allow_nan=False)
        stream.write("\n")


def main() -> int:
    args = parse_args()
    if args.reports_per_class < 2:
        print("Error: --reports-per-class must be at least 2", file=sys.stderr)
        return 2
    root = args.dataset_root.expanduser().resolve()
    if not root.is_dir():
        print(f"Error: dataset root is not a directory: {root}", file=sys.stderr)
        return 2
    output_dir = args.output_dir.expanduser()
    names = (
        "phase0c_summary.json",
        "process_id_audit.csv",
        "timestamp_audit.csv",
        "handle_mapping_audit.csv",
        "ambiguous_events.csv",
        "phase0c_review.md",
    )
    if not args.overwrite:
        existing = [output_dir / name for name in names if (output_dir / name).exists()]
        if existing:
            print(
                "Error: output files already exist; use --overwrite explicitly: "
                + ", ".join(map(str, existing)),
                file=sys.stderr,
            )
            return 1
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print(f"Error: cannot create output directory: {exc}", file=sys.stderr)
        return 1

    selected: Dict[str, Any] = {}
    reports: List[Dict[str, Any]] = []
    try:
        for class_name in CLASS_NAMES:
            chosen, selection = select_reports(root, class_name, args.reports_per_class)
            selected[class_name] = {
                **selection,
                "reports": [
                    {
                        "relative_report_path": path.relative_to(root).as_posix(),
                        "size_bytes": size,
                    }
                    for path, size in chosen
                ],
            }
            for index, (path, size) in enumerate(chosen, start=1):
                print(
                    f"Inspecting {class_name} {index}/{len(chosen)} "
                    f"({size} bytes): {path}",
                    file=sys.stderr,
                )
                reports.append(inspect_report(path, root, class_name))
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    process_rows = [row for report in reports for row in report["processes"]]
    timestamp_rows = [row for report in reports for row in report["timestamps"]]
    handle_rows = [row for report in reports for row in report["handles"]]
    ambiguous_rows = [row for report in reports for row in report["ambiguous"]]
    summary = {
        "dataset_root": str(root),
        "reports_per_class": args.reports_per_class,
        "selection": selected,
        "reports": reports,
        "observational_constraints": [
            "IDs and timestamps are observations, not assumed chronological order.",
            "Timestamp ties are retained as ambiguous; no order is inferred.",
            "Handle mappings are scoped to individual processes.",
            "NtClose is not assumed to close a file handle.",
            "No damage extraction or damaging-API classification was performed.",
        ],
    }
    process_fields = (
        "relative_report_path", "class", "process_id", "total_calls", "ids_present",
        "unique_ids", "duplicate_ids", "ids_numeric", "ids_non_numeric",
        "ids_increase_monotonically", "id_decreases", "id_equal_adjacent",
        "minimum_id", "maximum_id", "timestamp_values_present",
        "timestamp_parse_failures", "timestamps_monotonic", "timestamp_decreases",
        "duplicate_timestamp_adjacent", "timestamp_unique_values",
        "timestamp_resolution_min_gap", "timestamp_gap_median", "timestamp_gap_mean",
        "handle_count", "handles_referenced_after_close", "handle_reuse_count",
    )
    timestamp_fields = (
        "relative_report_path", "class", "process_id", "calls",
        "timestamps_present", "parse_failures", "timestamps_monotonic",
        "timestamp_decreases", "duplicate_timestamp_adjacent",
        "unique_timestamps", "minimum_positive_gap", "median_gap", "mean_gap",
    )
    handle_fields = (
        "relative_report_path", "class", "process_id", "handle", "created_count",
        "closed_count", "operation_count", "created_paths", "all_observed_paths",
        "path_count", "referenced_after_ntclose", "references_after_ntclose",
        "reuse_count", "note",
    )
    ambiguous_fields = (
        "relative_report_path", "timestamp", "process_ids", "calls_at_timestamp", "reason"
    )
    try:
        write_json(output_dir / "phase0c_summary.json", summary)
        write_csv(output_dir / "process_id_audit.csv", process_rows, process_fields)
        write_csv(output_dir / "timestamp_audit.csv", timestamp_rows, timestamp_fields)
        write_csv(output_dir / "handle_mapping_audit.csv", handle_rows, handle_fields)
        write_csv(output_dir / "ambiguous_events.csv", ambiguous_rows, ambiguous_fields)
        write_review(output_dir / "phase0c_review.md", reports, selected)
    except (OSError, TypeError, ValueError) as exc:
        print(f"Error: cannot write outputs: {exc}", file=sys.stderr)
        return 1

    print(f"Inspected {len(reports)} reports and {sum(r['total_calls'] for r in reports)} calls.")
    print(f"Outputs written to {output_dir}")
    return 0


def write_review(path: Path, reports: List[Dict[str, Any]], selected: Dict[str, Any]) -> None:
    with path.open("w", encoding="utf-8") as stream:
        stream.write("# Phase 0C Event and Handle Audit\n\n")
        stream.write("This is an observational audit. It does not infer a global event order or calculate damage.\n\n")
        for class_name in CLASS_NAMES:
            stream.write(f"## {class_name.title()} selection\n\n")
            for item in selected[class_name]["reports"]:
                stream.write(f"- `{item['relative_report_path']}` — {item['size_bytes']} bytes\n")
            class_reports = [r for r in reports if r["class"] == class_name]
            stream.write(
                f"\nInspected {len(class_reports)} reports, "
                f"{sum(r['total_calls'] for r in class_reports)} calls.\n\n"
            )
        stream.write("## Aggregate observations\n\n")
        for class_name in CLASS_NAMES:
            class_reports = [r for r in reports if r["class"] == class_name]
            process_rows = [p for r in class_reports for p in r["processes"]]
            stream.write(
                f"### {class_name.title()}\n\n"
                f"- {sum(len(r['processes']) for r in class_reports)} processes and "
                f"{sum(r['total_calls'] for r in class_reports)} calls.\n"
                f"- {sum(r['cross_process_id_overlap_count'] for r in class_reports)} "
                f"exact call-ID overlaps across processes were observed; "
                f"{sum(r['cross_process_id_range_overlap_pairs'] for r in class_reports)} "
                f"process-range overlap pairs were observed.\n"
                f"- {sum(r['cross_process_id_restart_candidates_in_stored_process_order'] for r in class_reports)} "
                f"stored-process-order ID restart/overlap candidates were observed; this is "
                f"not proof of chronological ID resets.\n"
                f"- {sum(p['duplicate_ids'] for p in process_rows)} duplicate IDs occurred "
                f"within processes. {sum(not p['ids_increase_monotonically'] for p in process_rows)} "
                f"processes had a decrease in stored ID order.\n"
                f"- {sum(p['timestamp_parse_failures'] for p in process_rows)} timestamp parse "
                f"failures occurred, and {sum(not p['timestamps_monotonic'] for p in process_rows)} "
                f"processes had a within-process timestamp decrease.\n"
                f"- {sum(len(r['ambiguous']) for r in class_reports)} cross-process timestamp "
                f"tie rows were retained as ambiguous.\n"
                f"- {sum(p['handle_reuse_count'] for p in process_rows)} handle-reuse observations "
                f"were recorded; {sum(p['handles_referenced_after_close'] for p in process_rows)} "
                f"processes had a handle reference after an `NtClose` in stored call order.\n\n"
            )
        classes: Dict[Tuple[str, str], int] = {}
        for report in reports:
            for item in report["file_information_classes"]:
                key = (item["value"], item["pretty_value"])
                classes[key] = classes.get(key, 0) + item["count"]
        stream.write("### `NtSetInformationFile` observations\n\n")
        for (value, pretty), count in sorted(classes.items(), key=lambda item: item[0]):
            label = f"{value} ({pretty})" if pretty else value
            stream.write(f"- `{label}` — {count} observations\n")
        stream.write(
            "\nThese are raw observed values only; no value is classified as damaging.\n\n"
        )
        stream.write("## Observations\n\n")
        stream.write("- Process-level IDs, timestamps, gaps, duplicate timestamps, and monotonicity are in the CSV outputs.\n")
        stream.write("- `ambiguous_events.csv` records timestamp ties across processes without ordering them.\n")
        stream.write("- `handle_mapping_audit.csv` scopes handle/path associations to one process and reports post-`NtClose` references and reuse observations.\n")
        stream.write("- `phase0c_summary.json` records all selected paths, sizes, per-report details, and `NtSetInformationFile` classes.\n\n")
        stream.write("## Limitations and unresolved questions\n\n")
        stream.write("- IDs and timestamps are not treated as chronological truth; ties, duplicate IDs, and traversal-order effects remain unresolved.\n")
        stream.write("- `NtClose` may refer to non-file handles, so post-close observations are call-sequence evidence only.\n")
        stream.write("- A handle-to-path association is based only on available argument fields; absence of a path is not evidence that no path exists.\n")
        stream.write("- Handle reuse and cross-process identity require further CAPE-specific validation.\n")
        stream.write("- No APIs were classified as damaging and no damage was calculated.\n")


if __name__ == "__main__":
    raise SystemExit(main())
