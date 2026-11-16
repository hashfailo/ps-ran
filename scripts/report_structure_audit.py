#!/usr/bin/env python3
"""Audit the structure and event ordering of a small set of CAPE reports."""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import math
import os
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, DefaultDict, Dict, Iterable, Iterator, List, Optional, Tuple

try:
    import ijson
except ImportError as exc:  # pragma: no cover - exercised in user environments
    print(
        "Error: ijson is required for large reports. Install it in the Python "
        "environment used to run this script (for example: python -m pip install ijson).",
        file=sys.stderr,
    )
    raise SystemExit(2) from exc


CLASS_NAMES = ("benign", "ransomware")
TARGET_APIS = (
    "NtWriteFile",
    "WriteFile",
    "NtCreateFile",
    "CreateFile",
    "NtSetInformationFile",
    "MoveFileExW",
    "MoveFileW",
    "DeleteFileW",
    "NtDeleteFile",
    "SetFileAttributesW",
    "CopyFileW",
    "CopyFileA",
)
MAX_EXAMPLES = 5
MAX_VALUE_LENGTH = 240
MAX_LIST_ITEMS = 10
PID_KEYS = ("process_id", "pid", "processid", "processId")
TIMESTAMP_KEYS = ("timestamp", "time", "ts")
ID_KEYS = ("id", "call_id", "callid")
SENSITIVE_KEY_RE = re.compile(
    r"(buffer|data|content|password|secret|token|key|shellcode)", re.IGNORECASE
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Inspect selected CAPE report structures without loading whole reports."
    )
    parser.add_argument("dataset_root", type=Path, help="EN2025 dataset root directory")
    parser.add_argument(
        "-n",
        "--reports-per-class",
        type=int,
        default=3,
        help="Number of reports to inspect per class (default: 3)",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        default=Path("outputs/phase0b"),
        help="Output directory (default: outputs/phase0b)",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Allow replacing existing Phase 0B output files",
    )
    return parser.parse_args()


def warn(message: str) -> None:
    print(f"Warning: {message}", file=sys.stderr)


def discover_reports(root: Path, class_name: str) -> List[Path]:
    class_root = root / class_name
    reports: List[Path] = []
    if not class_root.is_dir():
        warn(f"class directory not found: {class_root}")
        return reports
    for current, dirs, files in os.walk(class_root, topdown=True, followlinks=False):
        dirs.sort()
        files.sort()
        current_path = Path(current)
        for filename in files:
            if filename == "report.json":
                reports.append(current_path / filename)
    return sorted(reports, key=lambda path: path.relative_to(root).as_posix())


def safe_stat_size(path: Path) -> Optional[int]:
    try:
        return path.stat().st_size
    except OSError as exc:
        warn(f"cannot stat {path}: {exc}")
        return None


def first_value(mapping: Dict[str, Any], keys: Iterable[str]) -> Any:
    for key in keys:
        if key in mapping:
            return mapping[key]
    return None


def process_id(process: Dict[str, Any]) -> Any:
    return first_value(process, PID_KEYS)


def call_id(call: Dict[str, Any]) -> Any:
    return first_value(call, ID_KEYS)


def timestamp_value(call: Dict[str, Any]) -> Any:
    return first_value(call, TIMESTAMP_KEYS)


def parse_timestamp(value: Any) -> Optional[float]:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    try:
        return float(text)
    except ValueError:
        pass
    try:
        return dt.datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def numeric_id(value: Any) -> Optional[float]:
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


def compact_value(value: Any, key: str = "") -> Any:
    if SENSITIVE_KEY_RE.search(key):
        return "<redacted>"
    if isinstance(value, str):
        value = value.replace("\x00", "\\x00")
        return value if len(value) <= MAX_VALUE_LENGTH else value[:MAX_VALUE_LENGTH] + "...<truncated>"
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if isinstance(value, dict):
        return {
            str(k): compact_value(v, str(k))
            for k, v in list(value.items())[:MAX_LIST_ITEMS]
        }
    if isinstance(value, list):
        return [compact_value(item, key) for item in value[:MAX_LIST_ITEMS]]
    return str(value)[:MAX_VALUE_LENGTH]


def sample_arguments(call: Dict[str, Any]) -> Dict[str, Any]:
    arguments = call.get("arguments")
    if isinstance(arguments, dict):
        return {str(k): compact_value(v, str(k)) for k, v in arguments.items()}
    if isinstance(arguments, list):
        named: Dict[str, Any] = {}
        for item in arguments:
            if isinstance(item, dict) and "name" in item and "value" in item:
                name = str(item["name"])
                value: Any = item["value"]
                if "pretty_value" in item:
                    value = {"value": value, "pretty_value": item["pretty_value"]}
                named[name] = compact_value(value, name)
        if named:
            return named
    if arguments is None:
        return {}
    return {"value": compact_value(arguments, "arguments")}


def empty_ordering() -> Dict[str, Any]:
    return {
        "calls_observed": 0,
        "calls_with_ids": 0,
        "unique_call_ids": True,
        "duplicate_call_id_count": 0,
        "numeric_ids": 0,
        "numeric_id_adjacent_comparisons": {"increasing": 0, "decreasing": 0, "equal": 0},
        "cross_process_id_adjacent_comparisons": {
            "comparisons": 0,
            "increasing": 0,
            "decreasing": 0,
            "equal": 0,
        },
        "timestamps_present": 0,
        "timestamps_parsed": 0,
        "timestamp_parse_failures": 0,
        "timestamps_monotonic_within_processes": True,
        "within_process_timestamp_violations": 0,
        "timestamps_monotonic_combined": True,
        "combined_timestamp_violations": 0,
        "multiple_calls_share_timestamp": False,
        "shared_timestamp_groups": 0,
        "id_timestamp_adjacent_observations": {
            "comparisons": 0,
            "agreeing_direction": 0,
            "disagreeing_direction": 0,
            "id_equal_or_unordered": 0,
            "timestamp_equal_or_unordered": 0,
        },
    }


def inspect_report(path: Path, root: Path, class_name: str) -> Dict[str, Any]:
    size = safe_stat_size(path)
    result: Dict[str, Any] = {
        "class": class_name,
        "sample_directory": path.parent.name,
        "relative_report_path": path.relative_to(root).as_posix(),
        "report_size_bytes": size,
        "sections": {"info": False, "behavior": False, "signatures": False, "dropped": False},
        "processes": 0,
        "total_api_calls": 0,
        "call_field_presence": {
            "timestamps": 0,
            "ids": 0,
            "repeated": 0,
            "status": 0,
            "return": 0,
            "arguments": 0,
        },
        "api_frequencies": Counter(),
        "category_frequencies": Counter(),
        "api_reports": set(),
        "file_api_arguments": {},
        "ordering": empty_ordering(),
        "errors": [],
    }
    ids: List[Any] = []
    numeric_ids: List[Optional[float]] = []
    timestamps: List[Optional[float]] = []
    timestamp_counts: Counter = Counter()
    previous_process: Any = None
    previous_id: Optional[float] = None
    previous_timestamp: Optional[float] = None

    def update_adjacent_ordering(current_id: Optional[float], current_ts: Optional[float], current_process: Any) -> None:
        nonlocal previous_id, previous_timestamp, previous_process
        ordering = result["ordering"]
        if current_id is not None:
            ordering["numeric_ids"] += 1
            if previous_id is not None:
                direction = "increasing" if current_id > previous_id else "decreasing" if current_id < previous_id else "equal"
                ordering["numeric_id_adjacent_comparisons"][direction] += 1
            if previous_id is not None and current_process != previous_process:
                direction = "increasing" if current_id > previous_id else "decreasing" if current_id < previous_id else "equal"
                comparisons = ordering["cross_process_id_adjacent_comparisons"]
                comparisons["comparisons"] += 1
                comparisons[direction] += 1
        if current_ts is not None and previous_timestamp is not None:
            if current_ts < previous_timestamp:
                ordering["timestamps_monotonic_combined"] = False
                ordering["combined_timestamp_violations"] += 1
        if current_id is not None and current_ts is not None and previous_id is not None and previous_timestamp is not None:
            id_direction = current_id - previous_id
            ts_direction = current_ts - previous_timestamp
            observations = ordering["id_timestamp_adjacent_observations"]
            observations["comparisons"] += 1
            if id_direction == 0:
                observations["id_equal_or_unordered"] += 1
            elif ts_direction == 0:
                observations["timestamp_equal_or_unordered"] += 1
            elif (id_direction > 0) == (ts_direction > 0):
                observations["agreeing_direction"] += 1
            else:
                observations["disagreeing_direction"] += 1
        previous_id = current_id
        previous_timestamp = current_ts
        previous_process = current_process

    try:
        with path.open("rb") as stream:
            try:
                next(ijson.items(stream, "info"))
                result["sections"]["info"] = True
            except (ijson.common.IncompleteJSONError, StopIteration):
                pass
    except (OSError, ValueError) as exc:
        result["errors"].append(f"info: {exc}")

    try:
        with path.open("rb") as stream:
            for process in ijson.items(stream, "behavior.processes.item"):
                result["sections"]["behavior"] = True
                if not isinstance(process, dict):
                    continue
                result["processes"] += 1
                pid = process_id(process)
                pid_key = str(pid)
                calls = process.get("calls", [])
                if not isinstance(calls, list):
                    continue
                process_call_times: List[float] = []
                previous_process_time: Optional[float] = None
                for call in calls:
                    if not isinstance(call, dict):
                        continue
                    result["total_api_calls"] += 1
                    api = str(call.get("api", "<missing>"))
                    category = str(call.get("category", "<missing>"))
                    result["api_frequencies"][api] += 1
                    result["category_frequencies"][category] += 1
                    result["api_reports"].add(api)
                    fields = result["call_field_presence"]
                    for field, present in (
                        ("timestamps", any(key in call for key in TIMESTAMP_KEYS)),
                        ("ids", any(key in call for key in ID_KEYS)),
                        ("repeated", "repeated" in call),
                        ("status", "status" in call),
                        ("return", "return" in call),
                        ("arguments", "arguments" in call),
                    ):
                        fields[field] += int(present)
                    raw_id = call_id(call)
                    current_id = numeric_id(raw_id)
                    current_ts = parse_timestamp(timestamp_value(call))
                    if raw_id is not None:
                        ids.append(raw_id)
                    numeric_ids.append(current_id)
                    timestamps.append(current_ts)
                    if timestamp_value(call) is not None:
                        result["ordering"]["timestamps_present"] += 1
                        if current_ts is None:
                            result["ordering"]["timestamp_parse_failures"] += 1
                        else:
                            result["ordering"]["timestamps_parsed"] += 1
                            timestamp_counts[current_ts] += 1
                            process_call_times.append(current_ts)
                            if previous_process_time is not None and current_ts < previous_process_time:
                                result["ordering"]["timestamps_monotonic_within_processes"] = False
                                result["ordering"]["within_process_timestamp_violations"] += 1
                            previous_process_time = current_ts
                    update_adjacent_ordering(current_id, current_ts, pid_key)
                    if api in TARGET_APIS:
                        api_data = result["file_api_arguments"].setdefault(
                            api,
                            {
                                "calls": 0,
                                "argument_names": Counter(),
                                "examples": [],
                                "file_information_class_values": [],
                            }
                        )
                        api_data["calls"] += 1
                        arguments = sample_arguments(call)
                        api_data["argument_names"].update(arguments.keys())
                        if api == "NtSetInformationFile":
                            info_class = arguments.get("FileInformationClass")
                            if (
                                info_class is not None
                                and info_class not in api_data["file_information_class_values"]
                                and len(api_data["file_information_class_values"]) < MAX_EXAMPLES
                            ):
                                api_data["file_information_class_values"].append(info_class)
                        if len(api_data["examples"]) < MAX_EXAMPLES:
                            api_data["examples"].append(
                                {
                                    "arguments": arguments,
                                    "return": compact_value(call.get("return"), "return"),
                                    "status": compact_value(call.get("status"), "status"),
                                    "repeated": compact_value(call.get("repeated"), "repeated"),
                                    "process_id": compact_value(pid, "process_id"),
                                }
                            )
    except (OSError, ValueError, ijson.common.JSONError) as exc:
        result["errors"].append(f"behavior.processes: {exc}")

    try:
        with path.open("rb") as stream:
            for section_name in ("signatures", "dropped"):
                stream.seek(0)
                try:
                    found = next(ijson.items(stream, section_name))
                    result["sections"][section_name] = found is not None
                except StopIteration:
                    pass
    except (OSError, ValueError, ijson.common.JSONError) as exc:
        result["errors"].append(f"top-level sections: {exc}")

    result["ordering"]["calls_observed"] = result["total_api_calls"]
    result["ordering"]["calls_with_ids"] = len(ids)
    result["ordering"]["unique_call_ids"] = len(ids) == len(set(map(str, ids)))
    result["ordering"]["duplicate_call_id_count"] = len(ids) - len(set(map(str, ids)))
    shared = sum(count > 1 for count in timestamp_counts.values())
    result["ordering"]["shared_timestamp_groups"] = shared
    result["ordering"]["multiple_calls_share_timestamp"] = shared > 0
    result["api_frequencies"] = dict(result["api_frequencies"])
    result["category_frequencies"] = dict(result["category_frequencies"])
    result["api_reports"] = sorted(result["api_reports"])
    for api, data in result["file_api_arguments"].items():
        data["argument_names"] = dict(data["argument_names"])
    return result


def json_ready(value: Any) -> Any:
    if isinstance(value, Counter):
        return dict(value)
    if isinstance(value, set):
        return sorted(value)
    if isinstance(value, dict):
        return {str(key): json_ready(item) for key, item in value.items()}
    if isinstance(value, list):
        return [json_ready(item) for item in value]
    return value


def write_json(path: Path, value: Any) -> None:
    with path.open("w", encoding="utf-8") as stream:
        json.dump(json_ready(value), stream, indent=2, allow_nan=False)
        stream.write("\n")


def write_api_frequency(path: Path, reports: List[Dict[str, Any]]) -> None:
    counts: Counter = Counter()
    report_counts: Counter = Counter()
    for report in reports:
        for api, count in report["api_frequencies"].items():
            key = (report["class"], api)
            counts[key] += count
            report_counts[key] += int(count > 0)
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(
            stream, fieldnames=("class", "api", "total_calls", "reports_with_api")
        )
        writer.writeheader()
        for (class_name, api), count in sorted(counts.items()):
            writer.writerow(
                {
                    "class": class_name,
                    "api": api,
                    "total_calls": count,
                    "reports_with_api": report_counts[(class_name, api)],
                }
            )


def main() -> int:
    args = parse_args()
    if args.reports_per_class < 1:
        print("Error: --reports-per-class must be at least 1", file=sys.stderr)
        return 2
    root = args.dataset_root.expanduser().resolve()
    if not root.is_dir():
        print(f"Error: dataset root is not a directory: {root}", file=sys.stderr)
        return 2
    output_dir = args.output_dir.expanduser()
    output_names = (
        "report_structure_summary.json",
        "api_frequency.csv",
        "file_api_arguments.json",
        "event_ordering_audit.json",
    )
    if output_dir.exists() and not output_dir.is_dir():
        print(f"Error: output path is not a directory: {output_dir}", file=sys.stderr)
        return 2
    if not args.overwrite:
        existing = [output_dir / name for name in output_names if (output_dir / name).exists()]
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
        print(f"Error: cannot create output directory {output_dir}: {exc}", file=sys.stderr)
        return 1

    reports: List[Dict[str, Any]] = []
    for class_name in CLASS_NAMES:
        available = discover_reports(root, class_name)
        selected = available[: args.reports_per_class]
        print(
            f"{class_name}: selected {len(selected)} of {len(available)} "
            "reports (lexicographic relative path order)",
            file=sys.stderr,
        )
        for index, report_path in enumerate(selected, start=1):
            print(f"Inspecting {class_name} {index}/{len(selected)}: {report_path}", file=sys.stderr)
            reports.append(inspect_report(report_path, root, class_name))

    summary = {
        "dataset_root": str(root),
        "reports_per_class": args.reports_per_class,
        "selection": "first reports by lexicographically sorted relative report path",
        "reports": [
            {
                key: value
                for key, value in report.items()
                if key != "file_api_arguments"
            }
            for report in reports
        ],
    }
    file_arguments = {
        report["relative_report_path"]: {
            "class": report["class"],
            "sample_directory": report["sample_directory"],
            "apis": report["file_api_arguments"],
        }
        for report in reports
    }
    ordering = {
        report["relative_report_path"]: {
            "class": report["class"],
            "sample_directory": report["sample_directory"],
            "ordering": report["ordering"],
        }
        for report in reports
    }
    try:
        write_json(output_dir / "report_structure_summary.json", summary)
        write_api_frequency(output_dir / "api_frequency.csv", reports)
        write_json(output_dir / "file_api_arguments.json", file_arguments)
        write_json(output_dir / "event_ordering_audit.json", ordering)
    except (OSError, TypeError, ValueError) as exc:
        print(f"Error: cannot write audit outputs: {exc}", file=sys.stderr)
        return 1

    print(f"Inspected {len(reports)} reports.")
    for class_name in CLASS_NAMES:
        class_reports = [report for report in reports if report["class"] == class_name]
        calls = sum(report["total_api_calls"] for report in class_reports)
        print(f"{class_name}: {len(class_reports)} reports, {calls} API calls")
    print(f"Outputs written to {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
