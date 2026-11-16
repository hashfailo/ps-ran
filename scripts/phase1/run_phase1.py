#!/usr/bin/env python3
"""Run Phase 1 on the exact Phase 0C validation selection."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

from .cape_parser import iter_report_events
from .storage import parquet_status, read_jsonl, write_jsonl
from .event_normalizer import enrich_event
from .handle_tracker import HandleTracker


OUTPUT_FILES = ("metadata.jsonl", "failures.jsonl")


def args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset_root", type=Path)
    parser.add_argument("--phase0c-summary", type=Path, default=Path("outputs/phase0c/phase0c_summary.json"))
    parser.add_argument("-o", "--output-dir", type=Path, default=Path("outputs/phase1"))
    parser.add_argument("--resume", action="store_true", help="resume completed sample event files in an existing output directory")
    return parser.parse_args()


def selection(path: Path, root: Path) -> List[Dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    result: List[Dict[str, Any]] = []
    for label in ("benign", "ransomware"):
        for report in data["selection"][label]["reports"]:
            relative = report["relative_report_path"]
            report_path = root / relative
            if not report_path.is_file():
                raise ValueError(f"selected report missing: {report_path}")
            result.append({"class_label": label, "relative_report_path": relative, "path": report_path, "size_bytes": report.get("size_bytes")})
    if len(result) != 20:
        raise ValueError(f"expected 20 selected reports, found {len(result)}")
    return result


def main() -> int:
    cli = args()
    root = cli.dataset_root.expanduser().resolve()
    output = cli.output_dir
    output.mkdir(parents=True, exist_ok=True)
    events_dir = output / "events"
    events_dir.mkdir(exist_ok=True)
    metadata_path = output / "metadata.jsonl"
    failures_path = output / "failures.jsonl"
    unresolved_path = output / "unresolved_identities.jsonl"
    summary_path = output / "phase1_summary.json"
    existing = [p for p in (metadata_path, failures_path, unresolved_path, summary_path) if p.exists()]
    if existing and not cli.resume:
        print("Error: refusing to overwrite existing Phase 1 outputs: " + ", ".join(map(str, existing)), file=sys.stderr)
        print("Use --resume to continue an interrupted run.", file=sys.stderr)
        return 1
    try:
        selections = selection(cli.phase0c_summary.expanduser(), root)
    except (OSError, ValueError, KeyError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    metadata: List[dict[str, Any]] = []
    failures: List[dict[str, Any]] = []
    if cli.resume and metadata_path.exists():
        metadata = [json.loads(line) for line in metadata_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        failures = [json.loads(line) for line in failures_path.read_text(encoding="utf-8").splitlines() if line.strip()] if failures_path.exists() else []
    completed = {
        row["report_path"]
        for row in metadata
        if not row.get("failed")
        and Path(row.get("event_file", "")).is_file()
    }
    unresolved_records: List[dict[str, Any]] = []
    if cli.resume and unresolved_path.exists():
        unresolved_records = [
            json.loads(line)
            for line in unresolved_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    totals: Counter[str] = Counter()
    for row in metadata:
        if not row.get("failed"):
            totals["samples"] += 1
            totals["events"] += int(row.get("events_primary", 0))
            totals["ambiguities"] += int(row.get("ambiguity_count", 0))
    for index, item in enumerate(selections, 1):
        relative = item["relative_report_path"]
        sample_id = relative.rsplit("/", 2)[-2]
        event_path = events_dir / f"{index:02d}_{sample_id}.jsonl"
        if relative in completed:
            print(f"Skipping completed {index}/{len(selections)}: {relative}", file=sys.stderr)
            continue
        print(f"Processing {index}/{len(selections)}: {relative}", file=sys.stderr)
        try:
            tracker = HandleTracker()
            event_count = 0
            with event_path.open("w", encoding="utf-8") as stream:
                for event in iter_report_events(
                    item["path"], sample_id, item["class_label"], relative
                ):
                    enrich_event(event)
                    tracker.observe(event)
                    stream.write(json.dumps(event.to_dict(), ensure_ascii=False, separators=(",", ":")) + "\n")
                    if (event.path_observations or event.handle_observations) and not event.file_identity_candidates:
                        unresolved_records.append(
                            {
                                "sample_id": event.sample_id,
                                "class_label": event.class_label,
                                "report_path": event.report_path,
                                "process_id": event.process_id,
                                "process_call_position": event.process_call_position,
                                "api_normalized": event.api_normalized,
                                "reason": "path_or_handle_observation_without_candidate_identity",
                                "path_observations": event.path_observations,
                                "handle_observations": event.handle_observations,
                            }
                        )
                    event_count += 1
            # Validate deserialization of nested arguments and provenance.
            roundtrip_count = sum(1 for _ in read_jsonl(event_path))
            if roundtrip_count != event_count:
                raise ValueError(f"event JSONL round-trip count mismatch: {roundtrip_count} != {event_count}")
            item_metadata = {
                "sample_id": sample_id,
                "class_label": item["class_label"],
                "report_path": relative,
                "report_size_bytes": item["size_bytes"],
                "event_file": str(event_path),
                "events_primary": event_count,
                "events_merged_view": event_count,
                "handle_counts": dict(tracker.counts),
                "ambiguity_count": len(tracker.ambiguities),
                "serialization": {"jsonl_roundtrip_events": roundtrip_count, "nested_arguments_checked": True},
                "ordering": {"primary": "stored process traversal and call order", "merged": "timestamp, process index, call position; deterministic reconstruction only"},
                "failed": False,
            }
            metadata.append(item_metadata)
            totals["samples"] += 1
            totals["events"] += event_count
            totals["ambiguities"] += len(tracker.ambiguities)
        except Exception as exc:
            failure = {"sample_id": sample_id, "class_label": item["class_label"], "report_path": relative, "reason": f"{type(exc).__name__}: {exc}"}
            failures.append(failure)
            metadata.append({**failure, "failed": True})
    write_jsonl(metadata_path, metadata)
    write_jsonl(failures_path, failures)
    write_jsonl(unresolved_path, unresolved_records)
    summary = {
        "dataset_root": str(root),
        "selection_manifest": [{"class_label": x["class_label"], "report_path": x["relative_report_path"], "size_bytes": x["size_bytes"]} for x in selections],
        "samples_selected": len(selections),
        "samples_processed": totals["samples"],
        "samples_failed": len(failures),
        "event_count": totals["events"],
        "ambiguity_count": totals["ambiguities"],
        "unresolved_identity_records": len(unresolved_records),
        "storage": {"canonical": "JSONL", "parquet": parquet_status(), "npy": "not used; variable-length event streams"},
        "limitations": [
            "Candidate handle generations and path associations do not prove physical file identity.",
            "Primary order is stored process-call order; merged order is deterministic, not ground-truth chronology.",
            "No damage, operation success, or detector alert is inferred.",
        ],
    }
    (output / "phase1_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Processed {totals['samples']}/{len(selections)} samples; {totals['events']} events; {len(failures)} failures.")
    return 0 if not failures else 2


if __name__ == "__main__":
    raise SystemExit(main())
