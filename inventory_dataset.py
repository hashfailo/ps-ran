#!/usr/bin/env python3
"""Inventory EN2025 sample artifacts using filesystem metadata only."""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import statistics
import sys
from itertools import chain
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple


CLASS_NAMES = ("benign", "ransomware")
REPORT_NAME = "report.json"
PCAP_NAME = "dump.pcap"
MB = 1024 * 1024
PROGRESS_INTERVAL = 1000


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Inventory EN2025 reports and packet captures without reading report contents."
    )
    parser.add_argument("dataset_root", type=Path, help="EN2025 dataset root directory")
    parser.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        default=Path.cwd(),
        help="Directory for inventory.csv and summary.json (default: current directory)",
    )
    return parser.parse_args()


def warn(message: str) -> None:
    print(f"Warning: {message}", file=sys.stderr)


def iter_directories(root: Path) -> Iterator[Path]:
    """Yield directories below root, continuing after inaccessible entries."""
    try:
        with os.scandir(root) as entries:
            for entry in entries:
                try:
                    if entry.is_dir(follow_symlinks=False):
                        directory = Path(entry.path)
                        yield directory
                        yield from iter_directories(directory)
                except OSError as exc:
                    warn(f"cannot inspect {entry.path}: {exc}")
    except OSError as exc:
        warn(f"cannot read directory {root}: {exc}")


def sample_metadata(directory: Path) -> Tuple[bool, Optional[int], bool]:
    report_exists = False
    report_size: Optional[int] = None
    pcap_exists = False
    try:
        with os.scandir(directory) as entries:
            for entry in entries:
                if entry.name == REPORT_NAME and entry.is_file(follow_symlinks=False):
                    report_exists = True
                    report_size = entry.stat(follow_symlinks=False).st_size
                elif entry.name == PCAP_NAME and entry.is_file(follow_symlinks=False):
                    pcap_exists = True
    except OSError as exc:
        warn(f"cannot inspect {directory}: {exc}")
    return report_exists, report_size, pcap_exists


def discover_samples(
    class_root: Path, class_name: str
) -> Iterator[Dict[str, object]]:
    directories = chain((class_root,), iter_directories(class_root))
    for directory in directories:
        report_exists, report_size, pcap_exists = sample_metadata(directory)
        if not report_exists and not pcap_exists:
            continue

        report_path = directory / REPORT_NAME
        yield {
            "class_label": class_name,
            "sample_directory": directory.name,
            "relative_report_path": str(report_path.relative_to(class_root.parent)),
            "report_exists": report_exists,
            "report_size_bytes": report_size if report_size is not None else 0,
            "report_size_mb": (
                round(report_size / MB, 6) if report_size is not None else 0.0
            ),
            "dump_pcap_exists": pcap_exists,
            "sample_hash": directory.name,
        }


def percentile(sorted_values: List[int], percent: float) -> Optional[float]:
    if not sorted_values:
        return None
    rank = (len(sorted_values) - 1) * percent / 100
    lower = math.floor(rank)
    upper = math.ceil(rank)
    if lower == upper:
        return float(sorted_values[lower])
    fraction = rank - lower
    return sorted_values[lower] + (sorted_values[upper] - sorted_values[lower]) * fraction


def make_class_summary(sample_count: int, report_sizes: List[int]) -> Dict[str, object]:
    sizes = sorted(report_sizes)
    total = sum(sizes)
    return {
        "sample_directories": sample_count,
        "report_files": len(sizes),
        "missing_reports": sample_count - len(sizes),
        "total_report_storage_bytes": total,
        "total_report_storage_mb": round(total / MB, 6),
        "report_size_bytes": {
            "minimum": min(sizes) if sizes else None,
            "median": statistics.median(sizes) if sizes else None,
            "mean": statistics.mean(sizes) if sizes else None,
            "p90": percentile(sizes, 90),
            "p95": percentile(sizes, 95),
            "maximum": max(sizes) if sizes else None,
        },
        "reports_exceeding": {
            "10_mb": sum(size > 10 * MB for size in sizes),
            "50_mb": sum(size > 50 * MB for size in sizes),
            "100_mb": sum(size > 100 * MB for size in sizes),
        },
    }


INVENTORY_FIELDS = (
        "class_label",
        "sample_directory",
        "relative_report_path",
        "report_exists",
        "report_size_bytes",
        "report_size_mb",
        "dump_pcap_exists",
        "sample_hash",
    )


def print_summary(summary: Dict[str, object]) -> None:
    for class_name in CLASS_NAMES:
        data = summary["classes"][class_name]
        print(
            f"{class_name}: {data['sample_directories']} samples, "
            f"{data['report_files']} reports, {data['missing_reports']} missing, "
            f"{data['total_report_storage_mb']:.2f} MB"
        )


def main() -> int:
    args = parse_args()
    root = args.dataset_root.expanduser().resolve()
    if not root.is_dir():
        print(f"Error: dataset root is not a directory: {root}", file=sys.stderr)
        return 2

    summary: Dict[str, object] = {
        "dataset_root": str(root),
        "classes": {},
        "warnings": [],
    }

    try:
        args.output_dir.expanduser().mkdir(parents=True, exist_ok=True)
        inventory_path = args.output_dir.expanduser() / "inventory.csv"
        summary_path = args.output_dir.expanduser() / "summary.json"
        scanned = 0
        with inventory_path.open("w", newline="", encoding="utf-8") as output:
            writer = csv.DictWriter(output, fieldnames=INVENTORY_FIELDS)
            writer.writeheader()
            for class_name in CLASS_NAMES:
                class_root = root / class_name
                if not class_root.is_dir():
                    warn(f"class directory not found: {class_root}")
                    summary["classes"][class_name] = make_class_summary(0, [])
                    continue
                class_sizes: List[int] = []
                class_samples = 0
                for row in discover_samples(class_root, class_name):
                    writer.writerow(row)
                    class_samples += 1
                    scanned += 1
                    if row["report_exists"]:
                        class_sizes.append(int(row["report_size_bytes"]))
                    if scanned % PROGRESS_INTERVAL == 0:
                        print(
                            f"Progress: discovered {scanned} sample directories",
                            file=sys.stderr,
                        )
                summary["classes"][class_name] = make_class_summary(
                    class_samples, class_sizes
                )
        with summary_path.open("w", encoding="utf-8") as output:
            json.dump(summary, output, indent=2)
            output.write("\n")
    except OSError as exc:
        print(f"Error: cannot write output files: {exc}", file=sys.stderr)
        return 1

    print_summary(summary)
    print(f"Outputs: {inventory_path}, {summary_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
