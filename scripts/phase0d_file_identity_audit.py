#!/usr/bin/env python3
"""Audit raw path and handle representations in the fixed Phase 0C sample."""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

try:
    import ijson
except ImportError as exc:
    print(
        "Error: ijson is required in the existing project environment; "
        "this script does not install dependencies.",
        file=sys.stderr,
    )
    raise SystemExit(2) from exc


TARGET_APIS = (
    "NtCreateFile",
    "NtOpenFile",
    "NtWriteFile",
    "NtSetInformationFile",
    "NtClose",
    "NtQueryAttributesFile",
)
HANDLE_ARGUMENT_NAMES = {"FileHandle", "Handle", "HandleValue", "FileObject"}
PATH_ARGUMENT_NAMES = {
    "ApplicationName",
    "DirectoryName",
    "DllName",
    "FileName",
    "HandleName",
    "ExistingFileName",
    "ModuleName",
    "NewFileName",
    "FilePath",
    "Path",
    "Filename",
}
PATH_NAME_RE = re.compile(
    r"(path|filename|file_name|handle_name|pathname|directory|dirname|dllname|modulename)$",
    re.I,
)
HANDLE_NAME_RE = re.compile(r"(handle|fileobject|file_object)", re.I)
SENSITIVE_KEY_RE = re.compile(
    r"(buffer|data|content|password|secret|token|key|shellcode)", re.IGNORECASE
)
MAX_VALUE_LENGTH = 240
MAX_EXAMPLES_PER_GROUP = 20
PID_KEYS = ("process_id", "pid", "processid", "processId")
ID_KEYS = ("id", "call_id", "callid")
TIMESTAMP_KEYS = ("timestamp", "time", "ts")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Audit raw file path and handle representations in the fixed Phase 0C sample."
    )
    parser.add_argument("dataset_root", type=Path)
    parser.add_argument(
        "--phase0c-summary",
        type=Path,
        default=Path("outputs/phase0c/phase0c_summary.json"),
    )
    parser.add_argument("-o", "--output-dir", type=Path, default=Path("outputs/phase0d"))
    return parser.parse_args()


def warn(message: str) -> None:
    print(f"Warning: {message}", file=sys.stderr)


def write_json(path: Path, value: Any) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


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
            str(name): compact(item, str(name)) for name, item in list(value.items())[:20]
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
        return {str(name): value for name, value in arguments.items()}
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


def is_path_name(name: str) -> bool:
    return name in PATH_ARGUMENT_NAMES or bool(PATH_NAME_RE.search(name))


def is_handle_name(name: str) -> bool:
    return name in HANDLE_ARGUMENT_NAMES or bool(HANDLE_NAME_RE.search(name))


def unwrap(value: Any) -> Any:
    if isinstance(value, dict) and "value" in value:
        return value["value"]
    return value


def value_state(value: Any) -> str:
    if value is None:
        return "null"
    value = unwrap(value)
    if isinstance(value, str):
        return "empty" if not value.strip() else "usable"
    return "unusable"


def raw_text(value: Any, key: str) -> str:
    value = compact(value, key)
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return "" if value is None else str(value)


def classify_path(value: Any) -> str:
    state = value_state(value)
    if state != "usable":
        return state
    text = str(unwrap(value))
    lower = text.lower()
    if lower.startswith("\\\\"):
        return "unc_network"
    if lower.startswith("\\device\\"):
        return "nt_device"
    if lower.startswith("\\??\\") or lower.startswith("\\?\\"):
        return "dos_device"
    if re.match(r"^[A-Za-z]:[\\/]", text):
        return "drive_letter"
    if lower.startswith(("hklm\\", "hkcu\\", "hkcr\\", "hkey_")):
        return "registry_or_configuration"
    if text.startswith(("/", "./", "../")) or not re.match(r"^[A-Za-z]:", text):
        return "relative_or_rooted_unknown"
    if text.endswith(("\\", "/")):
        return "directory_like"
    return "file_like_or_unknown"


def normalize_handle(value: Any) -> Optional[str]:
    if value_state(value) != "usable":
        return None
    return str(unwrap(value)).strip().lower()


def load_selection(summary_path: Path, root: Path) -> List[Dict[str, Any]]:
    try:
        data = json.loads(summary_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"cannot read Phase 0C summary: {exc}") from exc
    selected: List[Dict[str, Any]] = []
    for class_name in ("benign", "ransomware"):
        reports = data.get("selection", {}).get(class_name, {}).get("reports", [])
        if not isinstance(reports, list):
            raise ValueError(f"missing selection for {class_name}")
        for report in reports:
            relative = report.get("relative_report_path")
            if not isinstance(relative, str):
                raise ValueError("invalid selected report path")
            path = root / relative
            if not path.is_file():
                raise ValueError(f"selected report missing: {path}")
            selected.append(
                {
                    "class": class_name,
                    "relative_report_path": relative,
                    "size_bytes": report.get("size_bytes"),
                    "path": path,
                }
            )
    if len(selected) != 20:
        raise ValueError(f"expected exactly 20 selected reports, found {len(selected)}")
    return selected


def inspect_report(selection: Dict[str, Any]) -> Dict[str, Any]:
    api_stats: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {
            "calls": 0,
            "argument_frequency": Counter(),
            "path_calls": 0,
            "handle_calls": 0,
            "missing_path_calls": 0,
            "empty_path_calls": 0,
            "null_path_calls": 0,
            "unusable_path_calls": 0,
            "missing_handle_calls": 0,
            "empty_handle_calls": 0,
            "null_handle_calls": 0,
            "unusable_handle_calls": 0,
            "both_path_handle_calls": 0,
        }
    )
    relevant_events: List[Dict[str, Any]] = []
    path_examples: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    path_to_handles: Dict[str, Set[Tuple[str, str]]] = defaultdict(set)
    handle_to_paths: Dict[Tuple[str, str], Set[str]] = defaultdict(set)
    handle_event_counts: Counter = Counter()
    errors: List[str] = []
    try:
        stream = selection["path"].open("rb")
    except OSError as exc:
        return {
            "class": selection["class"],
            "relative_report_path": selection["relative_report_path"],
            "size_bytes": selection["size_bytes"],
            "api_stats": {},
            "events": [],
            "path_examples": {},
            "path_to_handles": {},
            "handle_to_paths": {},
            "errors": [str(exc)],
        }

    with stream:
        try:
            for process in ijson.items(stream, "behavior.processes.item"):
                if not isinstance(process, dict):
                    continue
                process_id = str(first(process, PID_KEYS))
                calls = process.get("calls", [])
                if not isinstance(calls, list):
                    continue
                for position, call in enumerate(calls):
                    if not isinstance(call, dict):
                        continue
                    api = call.get("api")
                    arguments = named_arguments(call)
                    candidate_path_names = [name for name in arguments if is_path_name(name)]
                    candidate_handle_names = [name for name in arguments if is_handle_name(name)]
                    relevant = api in TARGET_APIS or candidate_path_names or candidate_handle_names
                    if not relevant:
                        continue
                    path_values = [
                        (name, value)
                        for name, value in arguments.items()
                        if is_path_name(name)
                    ]
                    handle_values = [
                        (name, value)
                        for name, value in arguments.items()
                        if is_handle_name(name)
                    ]
                    stats = api_stats[api or "<missing>"]
                    stats["calls"] += 1
                    for name in arguments:
                        stats["argument_frequency"][name] += 1
                    path_states = [value_state(value) for _, value in path_values]
                    handle_states = [value_state(value) for _, value in handle_values]
                    usable_paths = [
                        (name, value) for name, value in path_values if value_state(value) == "usable"
                    ]
                    usable_handles = [
                        (name, value)
                        for name, value in handle_values
                        if value_state(value) == "usable"
                    ]
                    if usable_paths:
                        stats["path_calls"] += 1
                    elif path_values:
                        state = "null" if "null" in path_states else "empty" if "empty" in path_states else "unusable"
                        stats[f"{state}_path_calls"] += 1
                    else:
                        stats["missing_path_calls"] += 1
                    if usable_handles:
                        stats["handle_calls"] += 1
                    elif handle_values:
                        state = "null" if "null" in handle_states else "empty" if "empty" in handle_states else "unusable"
                        stats[f"{state}_handle_calls"] += 1
                    else:
                        stats["missing_handle_calls"] += 1
                    if usable_paths and usable_handles:
                        stats["both_path_handle_calls"] += 1
                    event_context = {
                        "relative_report_path": selection["relative_report_path"],
                        "class": selection["class"],
                        "api": api,
                        "process_id": process_id,
                        "process_call_position": position,
                        "call_id": compact(first(call, ID_KEYS), "id"),
                        "timestamp": compact(first(call, TIMESTAMP_KEYS), "timestamp"),
                        "path_arguments": [
                            {
                                "argument_name": name,
                                "raw_value": raw_text(value, name),
                                "state": value_state(value),
                                "representation": classify_path(value),
                            }
                            for name, value in path_values
                        ],
                        "handle_arguments": [
                            {
                                "argument_name": name,
                                "raw_value": raw_text(value, name),
                                "state": value_state(value),
                                "normalized_handle": normalize_handle(value),
                            }
                            for name, value in handle_values
                        ],
                    }
                    relevant_events.append(event_context)
                    candidate_handle_keys: List[Tuple[str, str]] = []
                    for _, handle in usable_handles:
                        normalized = normalize_handle(handle)
                        if normalized is not None:
                            key = (process_id, normalized)
                            candidate_handle_keys.append(key)
                            handle_to_paths.setdefault(key, set())
                    for name, value in usable_paths:
                        raw = raw_text(value, name)
                        representation = classify_path(value)
                        if len(path_examples[representation]) < MAX_EXAMPLES_PER_GROUP:
                            path_examples[representation].append(
                                {
                                    "class": selection["class"],
                                    "relative_report_path": selection["relative_report_path"],
                                    "api": api,
                                    "argument_name": name,
                                    "raw_value": raw,
                                    "process_id": process_id,
                                    "call_id": compact(first(call, ID_KEYS), "id"),
                                    "representation": representation,
                                }
                            )
                        for key in candidate_handle_keys:
                            path_to_handles[raw].add(key)
                            handle_to_paths[key].add(raw)
                            handle_event_counts[key] += 1
        except (ijson.common.JSONError, OSError, ValueError) as exc:
            errors.append(str(exc))

    serialized_stats: Dict[str, Any] = {}
    for api, stats in sorted(api_stats.items()):
        serialized_stats[api] = {
            key: (dict(value) if isinstance(value, Counter) else value)
            for key, value in stats.items()
        }
    return {
        "class": selection["class"],
        "relative_report_path": selection["relative_report_path"],
        "size_bytes": selection["size_bytes"],
        "api_stats": serialized_stats,
        "events": relevant_events,
        "path_examples": dict(path_examples),
        "path_to_handles": {
            path: sorted([f"{pid}\t{handle}" for pid, handle in handles])
            for path, handles in path_to_handles.items()
        },
        "handle_to_paths": {
            f"{pid}\t{handle}": sorted(paths) for (pid, handle), paths in handle_to_paths.items()
        },
        "errors": errors,
    }


def aggregate(reports: List[Dict[str, Any]]) -> Dict[str, Any]:
    by_class: Dict[str, Any] = {}
    for class_name in ("benign", "ransomware"):
        class_reports = [report for report in reports if report["class"] == class_name]
        api: Dict[str, Any] = {}
        all_handles: Dict[str, Set[str]] = defaultdict(set)
        all_paths: Dict[str, Set[str]] = defaultdict(set)
        file_calls = 0
        no_usable_path = 0
        no_usable_handle = 0
        both = 0
        for report in class_reports:
            for api_name, stats in report["api_stats"].items():
                target = api.setdefault(
                    api_name,
                    {
                        "calls": 0,
                        "argument_frequency": Counter(),
                        "path_calls": 0,
                        "handle_calls": 0,
                        "missing_path_calls": 0,
                        "empty_path_calls": 0,
                        "null_path_calls": 0,
                        "unusable_path_calls": 0,
                        "missing_handle_calls": 0,
                        "empty_handle_calls": 0,
                        "null_handle_calls": 0,
                        "unusable_handle_calls": 0,
                        "both_path_handle_calls": 0,
                    },
                )
                for key, value in stats.items():
                    if isinstance(value, dict):
                        target[key].update(value)
                    else:
                        target[key] += value
                if api_name in TARGET_APIS:
                    file_calls += stats["calls"]
                    no_usable_path += stats["calls"] - stats["path_calls"]
                    no_usable_handle += stats["calls"] - stats["handle_calls"]
                    both += stats["both_path_handle_calls"]
            for key, paths in report["handle_to_paths"].items():
                all_handles[key].update(paths)
            for path, handles in report["path_to_handles"].items():
                all_paths[path].update(handles)
        one_path = sum(len(paths) == 1 for paths in all_handles.values())
        multiple_paths = sum(len(paths) > 1 for paths in all_handles.values())
        no_path = sum(len(paths) == 0 for paths in all_handles.values())
        by_class[class_name] = {
            "reports_processed": len(class_reports),
            "file_related_target_calls": file_calls,
            "file_related_calls_without_usable_path": no_usable_path,
            "file_related_calls_without_usable_handle": no_usable_handle,
            "file_related_calls_with_both_usable": both,
            "api_stats": {
                name: {
                    key: (dict(value) if isinstance(value, Counter) else value)
                    for key, value in sorted(stats.items())
                }
                for name, stats in sorted(api.items())
            },
            "candidate_handles_with_one_path": one_path,
            "candidate_handles_with_multiple_paths": multiple_paths,
            "candidate_handles_with_no_observed_path": no_path,
            "distinct_raw_path_strings": len(all_paths),
            "raw_paths_associated_with_multiple_candidate_handles": sum(
                len(handles) > 1 for handles in all_paths.values()
            ),
        }
    return by_class


def write_csvs(output_dir: Path, reports: List[Dict[str, Any]]) -> None:
    audit_fields = (
        "class", "relative_report_path", "api", "argument_name", "argument_occurrences",
        "calls", "path_calls", "handle_calls", "missing_path_calls", "empty_path_calls",
        "null_path_calls", "unusable_path_calls", "missing_handle_calls",
        "empty_handle_calls", "null_handle_calls", "unusable_handle_calls",
        "both_path_handle_calls",
    )
    with (output_dir / "file_path_argument_audit.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=audit_fields)
        writer.writeheader()
        for report in reports:
            for api, stats in sorted(report["api_stats"].items()):
                for argument_name, occurrences in sorted(stats["argument_frequency"].items()):
                    writer.writerow(
                        {
                            "class": report["class"],
                            "relative_report_path": report["relative_report_path"],
                            "api": api,
                            "argument_name": argument_name,
                            "argument_occurrences": occurrences,
                            **{key: stats[key] for key in audit_fields[5:]},
                        }
                    )

    variation_fields = (
        "class", "relative_report_path", "api", "argument_name",
        "raw_value", "process_id", "call_id", "representation",
    )
    with (output_dir / "path_variation_examples.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=variation_fields)
        writer.writeheader()
        for report in reports:
            for representation in sorted(report["path_examples"]):
                for example in report["path_examples"][representation]:
                    writer.writerow(example)

    consistency_fields = (
        "class", "relative_report_path", "process_id", "normalized_handle",
        "api", "process_call_position", "call_id", "timestamp",
        "path_argument_name", "raw_path_value", "path_representation",
        "handle_argument_name", "raw_handle_value", "note",
    )
    with (output_dir / "handle_path_consistency.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=consistency_fields)
        writer.writeheader()
        for report in reports:
            for event in report["events"]:
                for handle in event["handle_arguments"]:
                    if handle["state"] != "usable":
                        continue
                    paths = event["path_arguments"] or [
                        {
                            "argument_name": "",
                            "raw_value": "",
                            "representation": "missing",
                        }
                    ]
                    for path in paths:
                        writer.writerow(
                            {
                                "class": event["class"],
                                "relative_report_path": event["relative_report_path"],
                                "process_id": event["process_id"],
                                "normalized_handle": handle["normalized_handle"],
                                "api": event["api"],
                                "process_call_position": event["process_call_position"],
                                "call_id": event["call_id"],
                                "timestamp": event["timestamp"],
                                "path_argument_name": path["argument_name"],
                                "raw_path_value": path["raw_value"],
                                "path_representation": path["representation"],
                                "handle_argument_name": handle["argument_name"],
                                "raw_handle_value": handle["raw_value"],
                                "note": "candidate association only; no identity or lifetime inferred",
                            }
                        )


def write_review(path: Path, summary: Dict[str, Any], reports: List[Dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as stream:
        stream.write("# Phase 0D File Identity and Path Audit\n\n")
        stream.write(
            "Exactly the 20 report paths in the Phase 0C manifest were processed "
            "one at a time. This is an observational audit; it does not normalize "
            "paths, count damage, classify APIs, or infer file identity.\n\n"
        )
        for class_name in ("benign", "ransomware"):
            data = summary[class_name]
            stream.write(f"## {class_name.title()}\n\n")
            stream.write(
                f"- Reports: {data['reports_processed']}\n"
                f"- Target file-related calls: {data['file_related_target_calls']}\n"
                f"- Candidate handles with one path: {data['candidate_handles_with_one_path']}\n"
                f"- Candidate handles with multiple paths: {data['candidate_handles_with_multiple_paths']}\n"
                f"- Candidate handles with no observed path: {data['candidate_handles_with_no_observed_path']}\n"
                f"- Distinct raw path strings: {data['distinct_raw_path_strings']}\n"
                f"- Raw paths associated with multiple candidate handles: {data['raw_paths_associated_with_multiple_candidate_handles']}\n"
                f"- Target calls without usable path: {data['file_related_calls_without_usable_path']}\n"
                f"- Target calls without usable handle: {data['file_related_calls_without_usable_handle']}\n"
                f"- Target calls with both usable path and handle: {data['file_related_calls_with_both_usable']}\n\n"
            )
            stream.write("### API observations\n\n")
            for api, stats in data["api_stats"].items():
                stream.write(
                    f"- `{api}`: {stats['calls']} calls; "
                    f"path calls={stats['path_calls']}, handle calls={stats['handle_calls']}, "
                    f"both={stats['both_path_handle_calls']}\n"
                )
            stream.write("\n")
        stream.write("## Representation rules\n\n")
        stream.write(
            "- Missing means the argument name was absent. Empty means a string "
            "with only whitespace. Null means JSON null. Unusable means present "
            "but non-string/non-scalar after unwrapping a `value` wrapper.\n"
            "- Handles are normalized only for candidate grouping by stripping "
            "surrounding whitespace and lowercasing; raw handle values remain in "
            "the CSV. Paths are never normalized, lowercased, resolved, or merged.\n"
            "- Drive-letter, UNC, NT-device, DOS-device, registry/configuration, "
            "relative/rooted-unknown, directory-like, and file-like/unknown labels "
            "are descriptive string-pattern categories, not validity judgments.\n\n"
        )
        stream.write("## Representative observations\n\n")
        examples = []
        for report in reports:
            for group in report["path_examples"].values():
                examples.extend(group[:2])
        for example in examples[:20]:
            stream.write(
                f"- `{example['class']}` `{example['api']}.{example['argument_name']}` "
                f"({example['representation']}): `{example['raw_value']}` "
                f"(process {example['process_id']}, call {example['call_id']})\n"
            )
        stream.write(
            "\n## Conclusion and limitations\n\n"
            "The evidence **partially supports candidate association only**: "
            "some process-scoped handle values co-occur with raw paths, while "
            "other calls lack usable paths or handles and some handles/path "
            "strings have multiple associations. Matching values do not prove "
            "the same kernel object, and differing strings do not prove different "
            "files. No reliable distinct-file identification method is established.\n\n"
            "Additional APIs containing path-like or handle-like arguments are "
            "included in the API audit separately; their inclusion does not mean "
            "they modify files. Timestamps are retained as context only and never "
            "used to order or merge events. The selected sample is not the full "
            "dataset, and malformed/unexpected records are reported per report.\n"
        )


def main() -> int:
    args = parse_args()
    root = args.dataset_root.expanduser().resolve()
    output_dir = args.output_dir.expanduser()
    names = (
        "file_path_argument_audit.csv",
        "path_variation_examples.csv",
        "handle_path_consistency.csv",
        "file_identity_summary.json",
        "phase0d_review.md",
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
    for index, selection in enumerate(selections, start=1):
        print(
            f"Inspecting {index}/{len(selections)}: {selection['relative_report_path']}",
            file=sys.stderr,
        )
        reports.append(inspect_report(selection))
    summary = {
        "dataset_root": str(root),
        "selection_manifest": [
            {
                "class": selection["class"],
                "relative_report_path": selection["relative_report_path"],
                "size_bytes": selection["size_bytes"],
            }
            for selection in selections
        ],
        "classes": aggregate(reports),
        "reports_processed": len(reports),
        "report_errors": {
            report["relative_report_path"]: report["errors"]
            for report in reports
            if report["errors"]
        },
        "methodology": {
            "target_apis": list(TARGET_APIS),
            "additional_api_rule": "include any call with a path-like or handle-like argument name",
            "path_normalization": "none",
            "handle_grouping": "strip and lowercase only for candidate keys",
            "missing_rules": {
                "missing": "argument name absent",
                "empty": "string containing only whitespace",
                "null": "JSON null",
                "unusable": "present but non-string/non-scalar after unwrapping value",
            },
            "ordering": "stored process-call position only; timestamps never used to order",
        },
        "limitations": [
            "Candidate handle/path associations do not prove file identity or kernel object identity.",
            "Path representation labels are descriptive pattern matches, not validity checks.",
            "The audit processes the fixed 20-report Phase 0C sample, not the full dataset.",
            "Additional path/handle APIs are reported observationally and are not classified as modifying APIs.",
        ],
    }
    try:
        write_csvs(output_dir, reports)
        write_json(output_dir / "file_identity_summary.json", summary)
        write_review(output_dir / "phase0d_review.md", summary["classes"], reports)
    except (OSError, TypeError, ValueError) as exc:
        print(f"Error: cannot write outputs: {exc}", file=sys.stderr)
        return 1
    print(f"Processed {len(reports)} reports.")
    print(f"Outputs written to {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
