#!/usr/bin/env python3
"""Audit candidate file-handle lifecycles in the fixed Phase 0C report sample."""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

try:
    import ijson
except ImportError as exc:
    print(
        "Error: ijson is required in the existing environment; "
        "this script does not install dependencies.",
        file=sys.stderr,
    )
    raise SystemExit(2) from exc


TARGET_APIS = ("NtCreateFile", "NtClose", "NtWriteFile", "NtSetInformationFile")
OPERATION_APIS = {"NtWriteFile", "NtSetInformationFile"}
SENSITIVE_KEY_RE = re.compile(
    r"(buffer|data|content|password|secret|token|key|shellcode)", re.IGNORECASE
)
MAX_VALUE_LENGTH = 240
MAX_EXAMPLES_PER_TYPE = 50
PID_KEYS = ("process_id", "pid", "processid", "processId")
ID_KEYS = ("id", "call_id", "callid")
TIMESTAMP_KEYS = ("timestamp", "time", "ts")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Audit candidate handle lifecycles in the fixed Phase 0C sample."
    )
    parser.add_argument("dataset_root", type=Path)
    parser.add_argument(
        "--phase0c-summary",
        type=Path,
        default=Path("outputs/phase0c/phase0c_summary.json"),
    )
    parser.add_argument("-o", "--output-dir", type=Path, default=Path("outputs/phase0c2"))
    return parser.parse_args()


def compact(value: Any, key: str = "") -> Any:
    if SENSITIVE_KEY_RE.search(key):
        return "<redacted>"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        value = value.replace("\x00", "\\x00")
        return value if len(value) <= MAX_VALUE_LENGTH else value[:MAX_VALUE_LENGTH] + "...<truncated>"
    if isinstance(value, dict):
        return {
            str(name): compact(item, str(name))
            for name, item in list(value.items())[:20]
        }
    if isinstance(value, list):
        return [compact(item, key) for item in value[:20]]
    return str(value)[:MAX_VALUE_LENGTH]


def first(mapping: Dict[str, Any], keys: Iterable[str]) -> Any:
    for key in keys:
        if key in mapping:
            return mapping[key]
    return None


def named_arguments(call: Dict[str, Any]) -> Dict[str, Any]:
    arguments = call.get("arguments")
    if isinstance(arguments, dict):
        return {str(key): value for key, value in arguments.items()}
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


def normalize_handle(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, dict):
        value = value.get("value", value)
    text = str(value).strip()
    return text.lower() if text else None


def path_values(arguments: Dict[str, Any]) -> List[str]:
    paths: List[str] = []
    for key in (
        "FileName",
        "HandleName",
        "ExistingFileName",
        "NewFileName",
        "FilePath",
        "Path",
    ):
        value = arguments.get(key)
        if value is None:
            continue
        if isinstance(value, dict):
            value = value.get("value", value)
        text = compact(value, key)
        if isinstance(text, str) and text not in paths:
            paths.append(text)
    return paths


def outcome_value(value: Any, key: str) -> str:
    compacted = compact(value, key)
    if isinstance(compacted, (dict, list)):
        return json.dumps(compacted, sort_keys=True, separators=(",", ":"))
    return str(compacted)


def load_selection(summary_path: Path, root: Path) -> List[Dict[str, Any]]:
    try:
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"cannot read Phase 0C summary: {exc}") from exc
    selected: List[Dict[str, Any]] = []
    for class_name in ("benign", "ransomware"):
        reports = summary.get("selection", {}).get(class_name, {}).get("reports", [])
        for report in reports:
            relative = report.get("relative_report_path")
            if not isinstance(relative, str):
                raise ValueError("invalid selected report path")
            path = root / relative
            if not path.is_file():
                raise ValueError(f"selected report is missing: {path}")
            selected.append(
                {
                    "class": class_name,
                    "relative_report_path": relative,
                    "size_bytes": report.get("size_bytes"),
                    "path": path,
                }
            )
    if len(selected) != 20:
        raise ValueError(f"expected exactly 20 Phase 0C reports, found {len(selected)}")
    return selected


def event_record(
    api: str,
    call: Dict[str, Any],
    arguments: Dict[str, Any],
    process_id: str,
    position: int,
) -> Dict[str, Any]:
    return {
        "api": api,
        "position": position,
        "call_id": compact(first(call, ID_KEYS), "id"),
        "timestamp": compact(first(call, TIMESTAMP_KEYS), "timestamp"),
        "handle": normalize_handle(
            arguments.get("Handle" if api == "NtClose" else "FileHandle")
        ),
        "paths": path_values(arguments),
        "status": compact(call.get("status"), "status"),
        "return": compact(call.get("return"), "return"),
        "arguments": {
            str(key): compact(value, str(key)) for key, value in arguments.items()
        },
        "process_id": process_id,
    }


def sequence_row(
    report: Dict[str, Any],
    sequence_type: str,
    handle: str,
    events: List[Dict[str, Any]],
    operations: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    row: Dict[str, Any] = {
        "relative_report_path": report["relative_report_path"],
        "class": report["class"],
        "process_id": events[0]["process_id"],
        "normalized_handle": handle,
        "sequence_type": sequence_type,
        "event_positions": "|".join(str(event["position"]) for event in events),
        "event_apis": "|".join(event["api"] for event in events),
        "event_call_ids": "|".join(str(event["call_id"]) for event in events),
        "event_timestamps": "|".join(str(event["timestamp"]) for event in events),
        "event_paths": "|".join(
            path for event in events for path in event["paths"]
        ),
        "operation_count_between": len(operations or []),
        "operation_apis_between": "|".join(
            event["api"] for event in (operations or [])
        ),
        "operation_positions_between": "|".join(
            str(event["position"]) for event in (operations or [])
        ),
        "note": "candidate sequence in stored process-call order; no timestamp ordering applied",
    }
    return row


def analyze_handle_events(
    report: Dict[str, Any],
    process_id: str,
    events: List[Dict[str, Any]],
    counts: Counter,
    examples: Dict[str, List[Dict[str, Any]]],
    lifecycle_rows: List[Dict[str, Any]],
) -> None:
    last_create: Optional[Dict[str, Any]] = None
    closes_since_create: List[Dict[str, Any]] = []
    operations_since_create: List[Dict[str, Any]] = []
    for event in events:
        if event["api"] == "NtCreateFile":
            if closes_since_create:
                counts["close_create"] += 1
                row = sequence_row(
                    report,
                    "close_create",
                    event["handle"] or "",
                    [closes_since_create[-1], event],
                )
                lifecycle_rows.append(row)
                if len(examples["close_create"]) < MAX_EXAMPLES_PER_TYPE:
                    examples["close_create"].append(row)
                if last_create is not None:
                    counts["create_close_create"] += 1
                    triple_row = sequence_row(
                        report,
                        "create_close_create",
                        event["handle"] or "",
                        [last_create, closes_since_create[-1], event],
                    )
                    lifecycle_rows.append(triple_row)
                    if len(examples["create_close_create"]) < MAX_EXAMPLES_PER_TYPE:
                        examples["create_close_create"].append(triple_row)
            last_create = event
            closes_since_create = []
            operations_since_create = []
            continue
        if event["api"] == "NtClose":
            if last_create is not None:
                counts["create_close"] += 1
                row = sequence_row(
                    report,
                    "create_close",
                    event["handle"] or "",
                    [last_create, event],
                    operations_since_create,
                )
                lifecycle_rows.append(row)
                if len(examples["create_close"]) < MAX_EXAMPLES_PER_TYPE:
                    examples["create_close"].append(row)
                if operations_since_create:
                    counts["operations_between_create_close"] += len(operations_since_create)
                    operation_row = sequence_row(
                        report,
                        "operations_between_create_close",
                        event["handle"] or "",
                        [last_create, event],
                        operations_since_create,
                    )
                    lifecycle_rows.append(operation_row)
                    if len(examples["operations_between_create_close"]) < MAX_EXAMPLES_PER_TYPE:
                        examples["operations_between_create_close"].append(operation_row)
            if closes_since_create:
                counts["multiple_closes"] += 1
                row = sequence_row(
                    report,
                    "multiple_closes",
                    event["handle"] or "",
                    [closes_since_create[-1], event],
                )
                lifecycle_rows.append(row)
                if len(examples["multiple_closes"]) < MAX_EXAMPLES_PER_TYPE:
                    examples["multiple_closes"].append(row)
            closes_since_create.append(event)
            operations_since_create = []
            continue
        if event["api"] in OPERATION_APIS and last_create is not None and not closes_since_create:
            operations_since_create.append(event)


def inspect_report(
    selection: Dict[str, Any],
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    report = {
        "class": selection["class"],
        "relative_report_path": selection["relative_report_path"],
        "size_bytes": selection["size_bytes"],
        "processes": 0,
        "total_calls": 0,
        "candidate_sequence_counts": Counter(),
        "examples": {
            "create_close": [],
            "close_create": [],
            "create_close_create": [],
            "multiple_closes": [],
            "operations_between_create_close": [],
        },
        "create_outcomes": Counter(),
        "create_status_false_with_file_handle": 0,
        "create_status_false_examples": [],
        "errors": [],
    }
    lifecycle_rows: List[Dict[str, Any]] = []
    try:
        stream = selection["path"].open("rb")
    except OSError as exc:
        report["errors"].append(str(exc))
        return report, lifecycle_rows
    with stream:
        try:
            for process in ijson.items(stream, "behavior.processes.item"):
                if not isinstance(process, dict):
                    continue
                report["processes"] += 1
                pid = compact(first(process, PID_KEYS), "process_id")
                calls = process.get("calls", [])
                if not isinstance(calls, list):
                    continue
                report["total_calls"] += len(calls)
                by_handle: Dict[str, List[Dict[str, Any]]] = {}
                for position, call in enumerate(calls):
                    if not isinstance(call, dict):
                        continue
                    api = call.get("api")
                    if api not in TARGET_APIS:
                        continue
                    arguments = named_arguments(call)
                    event = event_record(api, call, arguments, pid, position)
                    handle = event["handle"]
                    if api == "NtCreateFile":
                        outcome = (
                            outcome_value(call.get("status"), "status"),
                            outcome_value(call.get("return"), "return"),
                            "present" if "FileHandle" in arguments else "absent",
                            outcome_value(
                                arguments.get("CreateDisposition"), "CreateDisposition"
                            ),
                            outcome_value(arguments.get("ExistedBefore"), "ExistedBefore"),
                        )
                        report["create_outcomes"][outcome] += 1
                        if call.get("status") is False and "FileHandle" in arguments:
                            report["create_status_false_with_file_handle"] += 1
                            if len(report["create_status_false_examples"]) < 20:
                                report["create_status_false_examples"].append(
                                    {
                                        "process_id": pid,
                                        "position": position,
                                        "call_id": compact(first(call, ID_KEYS), "id"),
                                        "timestamp": compact(first(call, TIMESTAMP_KEYS), "timestamp"),
                                        "file_handle": compact(arguments.get("FileHandle"), "FileHandle"),
                                        "file_name": compact(arguments.get("FileName"), "FileName"),
                                        "create_disposition": compact(
                                            arguments.get("CreateDisposition"), "CreateDisposition"
                                        ),
                                        "existed_before": compact(
                                            arguments.get("ExistedBefore"), "ExistedBefore"
                                        ),
                                        "return": compact(call.get("return"), "return"),
                                        "status": compact(call.get("status"), "status"),
                                    }
                                )
                    if handle is None:
                        continue
                    by_handle.setdefault(handle, []).append(event)
                for handle, events in by_handle.items():
                    analyze_handle_events(
                        report,
                        pid,
                        events,
                        report["candidate_sequence_counts"],
                        report["examples"],
                        lifecycle_rows,
                    )
            report["candidate_sequence_counts"] = dict(report["candidate_sequence_counts"])
            report["create_outcomes"] = [
                {
                    "status": key[0],
                    "return": key[1],
                    "file_handle": key[2],
                    "create_disposition": key[3],
                    "existed_before": key[4],
                    "count": count,
                }
                for key, count in sorted(report["create_outcomes"].items())
            ]
        except (ijson.common.JSONError, OSError, ValueError) as exc:
            report["errors"].append(str(exc))
    return report, lifecycle_rows


def write_json(path: Path, value: Any) -> None:
    with path.open("w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write("\n")


def write_lifecycle_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    fields = (
        "relative_report_path",
        "class",
        "process_id",
        "normalized_handle",
        "sequence_type",
        "event_positions",
        "event_apis",
        "event_call_ids",
        "event_timestamps",
        "event_paths",
        "operation_count_between",
        "operation_apis_between",
        "operation_positions_between",
        "note",
    )
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def write_counts(path: Path, reports: List[Dict[str, Any]]) -> None:
    counts = Counter()
    for report in reports:
        for sequence_type, count in report["candidate_sequence_counts"].items():
            counts[(report["class"], sequence_type)] += count
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(
            stream, fieldnames=("class", "sequence_type", "count", "interpretation")
        )
        writer.writeheader()
        interpretations = {
            "create_close": "create before later close in stored process-call order",
            "close_create": "close before later create in stored process-call order",
            "create_close_create": "create, close, then create for the same key in stored order",
            "multiple_closes": "close after a prior close without intervening create",
            "operations_between_create_close": "write/set-information events between candidate create and close",
        }
        for (class_name, sequence_type), count in sorted(counts.items()):
            writer.writerow(
                {
                    "class": class_name,
                    "sequence_type": sequence_type,
                    "count": count,
                    "interpretation": interpretations[sequence_type],
                }
            )


def write_review(path: Path, reports: List[Dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as stream:
        stream.write("# Phase 0C2 Handle Lifecycle Audit\n\n")
        stream.write(
            "Exactly the 20 report paths from Phase 0C were analyzed. Sequences "
            "use stored process-call positions only; timestamps were retained but "
            "never used to break ties. These are candidate sequences, not confirmed "
            "kernel handle lifetimes.\n\n"
        )
        for class_name in ("benign", "ransomware"):
            class_reports = [r for r in reports if r["class"] == class_name]
            stream.write(f"## {class_name.title()}\n\n")
            stream.write(
                f"- Reports: {len(class_reports)}\n"
                f"- Processes: {sum(r['processes'] for r in class_reports)}\n"
                f"- Calls: {sum(r['total_calls'] for r in class_reports)}\n"
            )
            for sequence_type in (
                "create_close",
                "close_create",
                "create_close_create",
                "multiple_closes",
                "operations_between_create_close",
            ):
                stream.write(
                    f"- `{sequence_type}`: "
                    f"{sum(r['candidate_sequence_counts'].get(sequence_type, 0) for r in class_reports)}\n"
                )
            stream.write(
                f"- `NtCreateFile` with `status=false` and `FileHandle` present: "
                f"{sum(r['create_status_false_with_file_handle'] for r in class_reports)}\n\n"
            )
        stream.write("## Interpretation and limitations\n\n")
        stream.write(
            "- `create_close` means the same normalized `(process_id, handle)` key "
            "was observed in a create and a later close in stored process-call order.\n"
            "- `close_create` means a close preceded a later create for that key; "
            "it does not prove reuse because an earlier lifetime may be outside the "
            "selected call sequence or the fields may not identify the same object.\n"
            "- `create_close_create` is a subset of `close_create` where the same "
            "stored process sequence also has a preceding create.\n"
            "- `multiple_closes` counts a close after another close without an "
            "intervening create in stored order.\n"
            "- `operations_between_create_close` records `NtWriteFile` and "
            "`NtSetInformationFile` events between the latest create and close.\n"
            "- Different paths are reported as observations only. They do not prove "
            "different file objects because aliases and normalization are unresolved.\n"
            "- `status`, `return`, `FileHandle`, `CreateDisposition`, and "
            "`ExistedBefore` combinations are descriptive; no success rule is applied.\n"
            "- No damage extraction or damaging-API classification was performed.\n"
        )


def main() -> int:
    args = parse_args()
    root = args.dataset_root.expanduser().resolve()
    output_dir = args.output_dir.expanduser()
    names = (
        "phase0c2_summary.json",
        "handle_lifecycle_examples.csv",
        "handle_sequence_counts.csv",
        "phase0c2_review.md",
    )
    if not root.is_dir():
        print(f"Error: dataset root is not a directory: {root}", file=sys.stderr)
        return 2
    existing = [output_dir / name for name in names if (output_dir / name).exists()]
    if existing:
        print("Error: refusing to overwrite: " + ", ".join(map(str, existing)), file=sys.stderr)
        return 1
    try:
        selections = load_selection(args.phase0c_summary.expanduser(), root)
        output_dir.mkdir(parents=True, exist_ok=True)
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    reports: List[Dict[str, Any]] = []
    lifecycle_rows: List[Dict[str, Any]] = []
    for index, selection in enumerate(selections, start=1):
        print(
            f"Inspecting {index}/{len(selections)}: {selection['relative_report_path']}",
            file=sys.stderr,
        )
        report, rows = inspect_report(selection)
        reports.append(report)
        lifecycle_rows.extend(rows)

    summary = {
        "selection_manifest": [
            {
                "class": selection["class"],
                "relative_report_path": selection["relative_report_path"],
                "size_bytes": selection["size_bytes"],
            }
            for selection in selections
        ],
        "reports": reports,
        "normalization": "handle values are stringified, stripped, and lowercased; process IDs remain report values",
        "constraints": [
            "Stored process-call order only; timestamps do not order events.",
            "Candidate sequences do not establish kernel handle lifetimes.",
            "No damage extraction or success classification was performed.",
        ],
    }
    try:
        write_json(output_dir / "phase0c2_summary.json", summary)
        write_lifecycle_csv(output_dir / "handle_lifecycle_examples.csv", lifecycle_rows)
        write_counts(output_dir / "handle_sequence_counts.csv", reports)
        write_review(output_dir / "phase0c2_review.md", reports)
    except (OSError, TypeError, ValueError) as exc:
        print(f"Error: cannot write outputs: {exc}", file=sys.stderr)
        return 1
    print(
        f"Inspected {len(reports)} reports; wrote {len(lifecycle_rows)} lifecycle rows."
    )
    print(f"Outputs written to {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
