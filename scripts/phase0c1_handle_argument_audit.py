#!/usr/bin/env python3
"""Audit raw argument shapes for CAPE file-handle APIs in the Phase 0C sample."""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

try:
    import ijson
except ImportError as exc:
    print(
        "Error: ijson is required. Install it in the existing Phase 0C environment; "
        "this script does not install dependencies.",
        file=sys.stderr,
    )
    raise SystemExit(2) from exc


TARGET_APIS = ("NtClose", "NtCreateFile", "NtWriteFile", "NtSetInformationFile")
SENSITIVE_KEY_RE = re.compile(
    r"(buffer|data|content|password|secret|token|key|shellcode)", re.IGNORECASE
)
MAX_VALUE_LENGTH = 240
MAX_CONTAINER_ITEMS = 20
PID_KEYS = ("process_id", "pid", "processid", "processId")
ID_KEYS = ("id", "call_id", "callid")
TIMESTAMP_KEYS = ("timestamp", "time", "ts")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Inspect raw CAPE handle argument structures for the Phase 0C reports."
    )
    parser.add_argument("dataset_root", type=Path)
    parser.add_argument(
        "--phase0c-summary",
        type=Path,
        default=Path("outputs/phase0c/phase0c_summary.json"),
        help="Exact Phase 0C selection manifest",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        default=Path("outputs/phase0c1"),
    )
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
            for name, item in list(value.items())[:MAX_CONTAINER_ITEMS]
        }
    if isinstance(value, list):
        return [compact(item, key) for item in value[:MAX_CONTAINER_ITEMS]]
    return str(value)[:MAX_VALUE_LENGTH]


def first(mapping: Dict[str, Any], keys: Iterable[str]) -> Any:
    for key in keys:
        if key in mapping:
            return mapping[key]
    return None


def process_id(process: Dict[str, Any]) -> Any:
    return first(process, PID_KEYS)


def call_id(call: Dict[str, Any]) -> Any:
    return first(call, ID_KEYS)


def timestamp(call: Dict[str, Any]) -> Any:
    return first(call, TIMESTAMP_KEYS)


def argument_items(call: Dict[str, Any]) -> List[Tuple[str, Any]]:
    arguments = call.get("arguments")
    if isinstance(arguments, dict):
        return [(str(name), value) for name, value in arguments.items()]
    if isinstance(arguments, list):
        items: List[Tuple[str, Any]] = []
        for item in arguments:
            if isinstance(item, dict) and "name" in item and "value" in item:
                value: Any = item["value"]
                if "pretty_value" in item:
                    value = {"value": value, "pretty_value": item["pretty_value"]}
                items.append((str(item["name"]), value))
        return items
    return []


def bounded_call(
    report_path: str,
    class_name: str,
    pid: Any,
    call: Dict[str, Any],
    process_call_index: int,
    report_call_index: int,
) -> Dict[str, Any]:
    arguments = argument_items(call)
    return {
        "relative_report_path": report_path,
        "class": class_name,
        "process_id": compact(pid, "process_id"),
        "process_call_index": process_call_index,
        "report_call_index": report_call_index,
        "call_id": compact(call_id(call), "id"),
        "timestamp": compact(timestamp(call), "timestamp"),
        "api": call.get("api"),
        "argument_names": [name for name, _ in arguments],
        "arguments": {name: compact(value, name) for name, value in arguments},
        "status": compact(call.get("status"), "status"),
        "return": compact(call.get("return"), "return"),
    }


def read_selection(summary_path: Path, root: Path) -> List[Dict[str, Any]]:
    try:
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"cannot read Phase 0C summary {summary_path}: {exc}") from exc
    selected: List[Dict[str, Any]] = []
    for class_name in ("benign", "ransomware"):
        reports = summary.get("selection", {}).get(class_name, {}).get("reports", [])
        if not isinstance(reports, list):
            raise ValueError(f"missing report selection for class {class_name}")
        for report in reports:
            relative = report.get("relative_report_path")
            if not isinstance(relative, str):
                raise ValueError(f"invalid selected report path for class {class_name}")
            path = root / relative
            if not path.is_file():
                raise ValueError(f"selected report is inaccessible or missing: {path}")
            selected.append(
                {
                    "class": class_name,
                    "relative_report_path": relative,
                    "size_bytes": report.get("size_bytes"),
                    "path": path,
                }
            )
    if len(selected) != 20:
        raise ValueError(f"Phase 0C summary contains {len(selected)} reports, expected 20")
    return selected


def inspect_report(selection: Dict[str, Any]) -> Dict[str, Any]:
    ntclose: List[Dict[str, Any]] = []
    ntcreate: List[Dict[str, Any]] = []
    frequencies: Counter = Counter()
    counts: Counter = Counter()
    errors: List[str] = []
    report_path = selection["relative_report_path"]
    try:
        stream = selection["path"].open("rb")
    except OSError as exc:
        return {
            **{key: selection[key] for key in ("class", "relative_report_path", "size_bytes")},
            "ntclose": [],
            "ntcreatefile": [],
            "argument_frequency": {},
            "api_counts": {},
            "errors": [str(exc)],
        }

    with stream:
        try:
            report_call_index = 0
            for process in ijson.items(stream, "behavior.processes.item"):
                if not isinstance(process, dict):
                    continue
                pid = process_id(process)
                calls = process.get("calls", [])
                if not isinstance(calls, list):
                    continue
                for process_call_index, call in enumerate(calls):
                    if not isinstance(call, dict):
                        continue
                    report_call_index += 1
                    api = call.get("api")
                    if api not in TARGET_APIS:
                        continue
                    counts[api] += 1
                    args = argument_items(call)
                    for name, _ in args:
                        frequencies[(api, name)] += 1
                    bounded = bounded_call(
                        report_path,
                        selection["class"],
                        pid,
                        call,
                        process_call_index,
                        report_call_index,
                    )
                    if api == "NtClose":
                        ntclose.append(bounded)
                    elif api == "NtCreateFile":
                        ntcreate.append(bounded)
        except (ijson.common.JSONError, OSError, ValueError) as exc:
            errors.append(str(exc))
    return {
        "class": selection["class"],
        "relative_report_path": report_path,
        "size_bytes": selection["size_bytes"],
        "ntclose": ntclose,
        "ntcreatefile": ntcreate,
        "argument_frequency": {
            f"{api}\t{name}": count for (api, name), count in sorted(frequencies.items())
        },
        "api_counts": dict(counts),
        "errors": errors,
    }


def write_json(path: Path, value: Any) -> None:
    with path.open("w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write("\n")


def write_frequency(path: Path, reports: List[Dict[str, Any]]) -> None:
    counts: Counter = Counter()
    reports_with_name: Counter = Counter()
    for report in reports:
        seen = set()
        for encoded, count in report["argument_frequency"].items():
            api, name = encoded.split("\t", 1)
            counts[(api, name)] += count
            seen.add((api, name))
        for key in seen:
            reports_with_name[key] += 1
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(
            stream,
            fieldnames=("api", "argument_name", "total_occurrences", "reports_with_api_argument"),
        )
        writer.writeheader()
        for (api, name), count in sorted(counts.items()):
            writer.writerow(
                {
                    "api": api,
                    "argument_name": name,
                    "total_occurrences": count,
                    "reports_with_api_argument": reports_with_name[(api, name)],
                }
            )


def write_review(path: Path, reports: List[Dict[str, Any]]) -> None:
    ntclose_calls = [call for report in reports for call in report["ntclose"]]
    ntcreate_calls = [call for report in reports for call in report["ntcreatefile"]]
    with path.open("w", encoding="utf-8") as stream:
        stream.write("# Phase 0C1 Handle Argument Audit\n\n")
        stream.write(
            "This audit uses exactly the 20 paths recorded by "
            "`outputs/phase0c/phase0c_summary.json`. It observes argument shapes "
            "only; it does not infer handle lifetimes, reuse, chronology, or damage.\n\n"
        )
        stream.write("## Coverage\n\n")
        stream.write(
            f"- `NtClose` calls recorded: {len(ntclose_calls)}\n"
            f"- `NtCreateFile` calls recorded: {len(ntcreate_calls)}\n"
            f"- Reports with parser errors: {sum(bool(r['errors']) for r in reports)}\n\n"
        )
        for api in ("NtClose", "NtCreateFile", "NtWriteFile", "NtSetInformationFile"):
            names = Counter()
            calls = 0
            for report in reports:
                calls += report["api_counts"].get(api, 0)
                for encoded, count in report["argument_frequency"].items():
                    encoded_api, name = encoded.split("\t", 1)
                    if encoded_api == api:
                        names[name] += count
            stream.write(f"## `{api}`\n\n")
            stream.write(f"Observed calls: {calls}. Argument occurrences:\n\n")
            for name, count in names.most_common():
                stream.write(f"- `{name}`: {count}\n")
            stream.write("\n")
        stream.write("## Observed handle representation\n\n")
        stream.write(
            "The JSON outputs contain bounded per-call arguments, including all "
            "argument names, status, return, process ID, call ID, and timestamp. "
            "Compare `NtClose` argument names with `NtCreateFile` fields directly; "
            "this audit intentionally does not assume that `FileHandle` is the "
            "closed or newly created object.\n\n"
        )
        stream.write("## Lifetime-tracking implications\n\n")
        stream.write(
            "- A candidate tracker should first identify the actual close-handle "
            "field from the `NtClose` examples.\n"
            "- It should separately identify whether `NtCreateFile` exposes an "
            "output handle, an input/placeholder handle, or only related metadata.\n"
            "- Any lifetime or reuse claim requires a process-scoped sequence with "
            "a resolved create/output handle, a close event, and a later assignment "
            "to the same handle key. Repeated observations alone are insufficient.\n"
            "- Missing, differently named, or non-file handle arguments remain "
            "unresolved until the bounded examples are reviewed.\n"
        )


def main() -> int:
    args = parse_args()
    root = args.dataset_root.expanduser().resolve()
    if not root.is_dir():
        print(f"Error: dataset root is not a directory: {root}", file=sys.stderr)
        return 2
    output_dir = args.output_dir.expanduser()
    names = (
        "ntclose_examples.json",
        "ntcreatefile_examples.json",
        "handle_argument_frequency.csv",
        "phase0c1_review.md",
    )
    existing = [output_dir / name for name in names if (output_dir / name).exists()]
    if existing:
        print(
            "Error: output files already exist; refusing to overwrite: "
            + ", ".join(map(str, existing)),
            file=sys.stderr,
        )
        return 1
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        selections = read_selection(args.phase0c_summary.expanduser(), root)
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    reports: List[Dict[str, Any]] = []
    for index, selection in enumerate(selections, start=1):
        print(
            f"Inspecting {index}/{len(selections)}: "
            f"{selection['relative_report_path']}",
            file=sys.stderr,
        )
        reports.append(inspect_report(selection))

    try:
        write_json(
            output_dir / "ntclose_examples.json",
            {
                "selection_manifest": [
                    {
                        key: report[key]
                        for key in ("class", "relative_report_path", "size_bytes")
                    }
                    for report in reports
                ],
                "reports": [
                    {
                        key: report[key]
                        for key in ("class", "relative_report_path", "size_bytes", "ntclose", "errors")
                    }
                    for report in reports
                ],
            },
        )
        write_json(
            output_dir / "ntcreatefile_examples.json",
            {
                "selection_manifest": [
                    {
                        key: report[key]
                        for key in ("class", "relative_report_path", "size_bytes")
                    }
                    for report in reports
                ],
                "reports": [
                    {
                        key: report[key]
                        for key in (
                            "class",
                            "relative_report_path",
                            "size_bytes",
                            "ntcreatefile",
                            "errors",
                        )
                    }
                    for report in reports
                ],
            },
        )
        write_frequency(output_dir / "handle_argument_frequency.csv", reports)
        write_review(output_dir / "phase0c1_review.md", reports)
    except (OSError, TypeError, ValueError) as exc:
        print(f"Error: cannot write outputs: {exc}", file=sys.stderr)
        return 1

    print(
        f"Inspected {len(reports)} reports; "
        f"NtClose={sum(len(r['ntclose']) for r in reports)}, "
        f"NtCreateFile={sum(len(r['ntcreatefile']) for r in reports)}."
    )
    print(f"Outputs written to {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
