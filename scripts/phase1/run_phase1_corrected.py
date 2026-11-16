#!/usr/bin/env python3
"""Run corrected Phase 1 on the fixed Phase 0C validation selection."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

from .cape_parser import iter_report_events
from .event_normalizer import enrich_event
from .handle_tracker import HandleTracker
from .storage import atomic_write_json, atomic_write_jsonl, parquet_status, read_jsonl


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset_root", type=Path)
    parser.add_argument(
        "--phase0c-summary",
        type=Path,
        default=Path("outputs/phase0c/phase0c_summary.json"),
    )
    parser.add_argument(
        "-o", "--output-dir", type=Path, default=Path("outputs/phase1_corrected")
    )
    parser.add_argument("--resume", action="store_true")
    return parser.parse_args()


def load_selection(path: Path, root: Path) -> List[Dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    selected = []
    for label in ("benign", "ransomware"):
        for report in data["selection"][label]["reports"]:
            relative = report["relative_report_path"]
            report_path = root / relative
            if not report_path.is_file():
                raise ValueError(f"selected report missing: {report_path}")
            selected.append(
                {
                    "class_label": label,
                    "relative_report_path": relative,
                    "path": report_path,
                    "size_bytes": report.get("size_bytes"),
                }
            )
    if len(selected) != 20:
        raise ValueError(f"expected 20 selected reports, found {len(selected)}")
    return selected


def event_records(path: Path):
    yield from read_jsonl(path)


def main() -> int:
    cli = parse_args()
    root = cli.dataset_root.expanduser().resolve()
    output = cli.output_dir
    events_dir = output / "events"
    output.mkdir(parents=True, exist_ok=True)
    events_dir.mkdir(exist_ok=True)
    metadata_path = output / "metadata.jsonl"
    failures_path = output / "failures.jsonl"
    unresolved_path = output / "unresolved_identities.jsonl"
    summary_path = output / "phase1_corrected_summary.json"
    manifest_path = output / "completion_manifest.jsonl"
    existing = [
        path
        for path in (
            metadata_path,
            failures_path,
            unresolved_path,
            summary_path,
            manifest_path,
        )
        if path.exists()
    ]
    if existing and not cli.resume:
        print(
            "Error: refusing to overwrite corrected outputs: "
            + ", ".join(map(str, existing)),
            file=sys.stderr,
        )
        return 1
    try:
        selections = load_selection(cli.phase0c_summary.expanduser(), root)
    except (OSError, KeyError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    metadata = (
        [json.loads(line) for line in metadata_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if cli.resume and metadata_path.exists()
        else []
    )
    failures = (
        [json.loads(line) for line in failures_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if cli.resume and failures_path.exists()
        else []
    )
    unresolved = (
        [json.loads(line) for line in unresolved_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if cli.resume and unresolved_path.exists()
        else []
    )
    completed = {
        row["report_path"]
        for row in metadata
        if not row.get("failed") and Path(row["event_file"]).is_file()
    }
    totals: Counter[str] = Counter()
    for row in metadata:
        if not row.get("failed"):
            totals["samples"] += 1
            totals["events"] += row["events_primary"]
            for key, value in row["handle_counts"].items():
                totals[key] += value
            totals["ambiguities"] += row["ambiguity_count"]

    for index, item in enumerate(selections, 1):
        relative = item["relative_report_path"]
        sample_id = relative.rsplit("/", 2)[-2]
        event_path = events_dir / f"{index:02d}_{sample_id}.jsonl"
        if relative in completed:
            print(f"Skipping completed {index}/20: {relative}", file=sys.stderr)
            continue
        print(f"Processing {index}/20: {relative}", file=sys.stderr)
        try:
            tracker = HandleTracker()
            event_count = 0
            sample_unresolved = []
            temporary_event = event_path.with_suffix(".jsonl.tmp")
            with temporary_event.open("w", encoding="utf-8") as stream:
                for event in iter_report_events(
                    item["path"], sample_id, item["class_label"], relative
                ):
                    enrich_event(event)
                    tracker.observe(event)
                    stream.write(
                        json.dumps(event.to_dict(), ensure_ascii=False, separators=(",", ":"))
                        + "\n"
                    )
                    file_handles = [
                        observation
                        for observation in event.handle_observations
                        if observation.get("object_type") == "file_candidate"
                    ]
                    if event.path_observations and not file_handles:
                        sample_unresolved.append(
                            {
                                "sample_id": sample_id,
                                "class_label": item["class_label"],
                                "report_path": relative,
                                "process_id": event.process_id,
                                "process_call_position": event.process_call_position,
                                "api_normalized": event.api_normalized,
                                "reason": "path_only_observation",
                            }
                        )
                    elif file_handles and not event.file_identity_candidates:
                        sample_unresolved.append(
                            {
                                "sample_id": sample_id,
                                "class_label": item["class_label"],
                                "report_path": relative,
                                "process_id": event.process_id,
                                "process_call_position": event.process_call_position,
                                "api_normalized": event.api_normalized,
                                "reason": "file_handle_without_candidate",
                            }
                        )
                    event_count += 1
            temporary_event.replace(event_path)
            if sum(1 for _ in event_records(event_path)) != event_count:
                raise ValueError("event JSONL round-trip count mismatch")
            sample_unresolved.extend(tracker.ambiguities)
            counts = dict(tracker.counts)
            counts["file_handle_observations"] = sum(
                1
                for event in event_records(event_path)
                for observation in event.get("handle_observations", [])
                if observation.get("object_type") == "file_candidate"
            )
            counts["non_file_handle_observations"] = sum(
                1
                for event in event_records(event_path)
                for observation in event.get("handle_observations", [])
                if observation.get("object_type") != "file_candidate"
            )
            row = {
                "sample_id": sample_id,
                "class_label": item["class_label"],
                "report_path": relative,
                "report_size_bytes": item["size_bytes"],
                "event_file": str(event_path),
                "events_primary": event_count,
                "merged_view": {
                    "serialized": False,
                    "reason": "not available without buffering/sorting; primary stored order is authoritative",
                },
                "handle_counts": counts,
                "ambiguity_count": len(sample_unresolved),
                "serialization": {
                    "jsonl_roundtrip_events": event_count,
                    "nested_arguments_checked": True,
                },
                "failed": False,
            }
            metadata.append(row)
            unresolved.extend(sample_unresolved)
            atomic_write_jsonl(manifest_path, [{"report_path": r["report_path"], "event_file": r["event_file"]} for r in metadata if not r.get("failed")])
            totals["samples"] += 1
            totals["events"] += event_count
            for key, value in counts.items():
                totals[key] += value
            totals["ambiguities"] += len(sample_unresolved)
            atomic_write_jsonl(metadata_path, metadata)
            atomic_write_jsonl(failures_path, failures)
            atomic_write_jsonl(unresolved_path, unresolved)
        except Exception as exc:
            failures.append(
                {
                    "sample_id": sample_id,
                    "class_label": item["class_label"],
                    "report_path": relative,
                    "reason": f"{type(exc).__name__}: {exc}",
                }
            )
            atomic_write_jsonl(failures_path, failures)

    summary = {
        "dataset_root": str(root),
        "samples_selected": len(selections),
        "samples_processed": totals["samples"],
        "samples_failed": len(failures),
        "event_count": totals["events"],
        "file_handle_observations": totals["file_handle_observations"],
        "non_file_handle_observations": totals["non_file_handle_observations"],
        "ambiguity_count": totals["ambiguities"],
        "unresolved_identity_records": len(unresolved),
        "handle_counts": {
            key: value
            for key, value in totals.items()
            if key not in {"samples", "events", "ambiguities"}
        },
        "ordering": {
            "primary": "stored process traversal and process-call order",
            "merged_serialized": False,
            "reason": "timestamps cannot establish ground-truth chronology and no merged stream is emitted",
        },
        "storage": {
            "canonical": "JSONL",
            "parquet": parquet_status(),
            "npy": "not used; variable-length event streams",
        },
        "file_handle_mapping": {
            "explicit_only": True,
            "uncertain_apis": ["NtDuplicateObject", "NtDeviceIoControlFile", "NtQueryObject"],
        },
    }
    atomic_write_json(metadata_path.with_suffix(".schema.json"), {
        "raw_arguments": "complete canonical CAPE arguments",
        "candidate_identity": "never confirmed physical identity",
        "primary_order": "stored process-call order",
    })
    atomic_write_json(summary_path, summary)
    atomic_write_jsonl(metadata_path, metadata)
    atomic_write_jsonl(failures_path, failures)
    atomic_write_jsonl(unresolved_path, unresolved)
    print(f"Processed {totals['samples']}/20 samples; {totals['events']} events; {len(failures)} failures.")
    return 0 if not failures else 2


if __name__ == "__main__":
    raise SystemExit(main())
