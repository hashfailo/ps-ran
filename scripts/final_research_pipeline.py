#!/usr/bin/env python3
"""Run a compact, streaming end-to-end EN2025 research experiment.

The experiment deliberately writes sample-level aggregates instead of canonical
event archives. It therefore remains usable on storage-constrained machines
while preserving the raw reports as the source of truth.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import statistics
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence

from .phase1.cape_parser import iter_report_events
from .phase1.event_normalizer import enrich_event


PREFIXES = (0.10, 0.25, 0.50, 0.75, 1.00)
FEATURE_NAMES = (
    "events",
    "processes",
    "unique_apis",
    "file_handle_observations",
    "path_observations",
    "create_open",
    "successful_create_open",
    "failed_create_open",
    "writes",
    "reads",
    "deletes",
    "renames",
    "file_information",
    "closes",
)
ACTIVITY_FEATURES = ("writes", "deletes", "renames", "file_information")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset_root", type=Path)
    parser.add_argument(
        "-i",
        "--inventory",
        type=Path,
        default=Path("inventory.csv"),
        help="Phase 0A inventory CSV (default: ./inventory.csv)",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        default=Path("outputs/final_research"),
    )
    parser.add_argument("--overwrite", action="store_true")
    return parser.parse_args()


def load_inventory(path: Path, root: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with path.open(newline="", encoding="utf-8") as stream:
        for row in csv.DictReader(stream):
            if row.get("report_exists", "").lower() != "true":
                continue
            relative = row["relative_report_path"]
            report_path = root / relative
            if report_path.is_file():
                rows.append(
                    {
                        "class_label": row["class_label"],
                        "relative_report_path": relative,
                        "report_path": report_path,
                        "sample_id": row["sample_hash"],
                        "report_size_bytes": int(row["report_size_bytes"]),
                    }
                )
    return sorted(rows, key=lambda row: row["relative_report_path"])


def empty_counts() -> Dict[str, Any]:
    result: Dict[str, Any] = {name: 0 for name in FEATURE_NAMES}
    result["api_set"] = set()
    result["process_set"] = set()
    result["usable_paths"] = set()
    result["path_overflow"] = False
    return result


def add_event(counts: Dict[str, Any], event: Any) -> None:
    counts["events"] += 1
    counts["api_set"].add(event.api_normalized)
    counts["process_set"].add(event.process_id)
    api = event.api_normalized
    kind = event.operation_kind
    if kind in {"write"} or "writefile" in api:
        counts["writes"] += 1
    if kind in {"read"} or "readfile" in api:
        counts["reads"] += 1
    if kind == "delete" or "delete" in api:
        counts["deletes"] += 1
    if kind == "rename" or "movefile" in api:
        counts["renames"] += 1
    if kind == "set_file_information" or "informationfile" in api:
        counts["file_information"] += 1
    if kind == "close" or api == "ntclose":
        counts["closes"] += 1
    if api in {"ntcreatefile", "ntopenfile"}:
        counts["create_open"] += 1
        if event.status_raw is True:
            counts["successful_create_open"] += 1
        elif event.status_raw is False:
            counts["failed_create_open"] += 1
    counts["file_handle_observations"] += sum(
        1
        for observation in event.handle_observations
        if observation.get("object_type") == "file_candidate"
    )
    usable = [
        str(path["raw_value"])
        for path in event.path_observations
        if path.get("state") == "usable"
    ]
    if len(counts["usable_paths"]) < 20_000:
        counts["usable_paths"].update(usable)
    elif usable:
        counts["path_overflow"] = True


def vector_from_counts(counts: Dict[str, Any]) -> Dict[str, float]:
    result = {name: float(counts[name]) for name in FEATURE_NAMES}
    result["processes"] = float(len(counts["process_set"]))
    result["unique_apis"] = float(len(counts["api_set"]))
    result["path_observations"] = float(len(counts["usable_paths"]))
    return result


def add_vectors(left: Dict[str, float], right: Dict[str, float]) -> Dict[str, float]:
    return {name: left[name] + right[name] for name in FEATURE_NAMES}


def split_vector(vector: Dict[str, float], denominator: float) -> Dict[str, float]:
    return {
        name: (vector[name] / denominator if denominator else 0.0)
        for name in FEATURE_NAMES
    }


def process_sample(item: Dict[str, Any]) -> Dict[str, Any]:
    counts = empty_counts()
    snapshots: List[tuple[int, Dict[str, float]]] = []
    next_snapshot = 1000
    for event in iter_report_events(
        item["report_path"],
        item["sample_id"],
        item["class_label"],
        item["relative_report_path"],
    ):
        enrich_event(event)
        add_event(counts, event)
        if counts["events"] >= next_snapshot:
            snapshots.append((counts["events"], vector_from_counts(counts)))
            next_snapshot += 1000
    total = counts["events"]
    final = vector_from_counts(counts)
    if not snapshots or snapshots[-1][0] != total:
        snapshots.append((total, final))
    prefix_vectors: Dict[str, Dict[str, float]] = {}
    for prefix in PREFIXES:
        target = max(1, math.ceil(total * prefix))
        chosen = next((vector for position, vector in snapshots if position >= target), final)
        denominator = chosen["events"] or 1.0
        prefix_vectors[str(prefix)] = split_vector(chosen, denominator)
    return {
        "sample_id": item["sample_id"],
        "class_label": item["class_label"],
        "report_path": item["relative_report_path"],
        "report_size_bytes": item["report_size_bytes"],
        "events": total,
        "unique_paths_observed": len(counts["usable_paths"]),
        "path_observation_overflow": counts["path_overflow"],
        "features": final,
        "prefix_features_per_event": prefix_vectors,
    }


def is_test(sample_id: str) -> bool:
    return int(hashlib.sha256(sample_id.encode()).hexdigest()[:8], 16) % 5 == 0


def gaussian_model(rows: Sequence[Dict[str, Any]], prefix: str) -> Dict[str, Any]:
    grouped: Dict[str, List[Dict[str, float]]] = {"benign": [], "ransomware": []}
    for row in rows:
        grouped[row["class_label"]].append(row["prefix_features_per_event"][prefix])
    model: Dict[str, Any] = {}
    for label, values in grouped.items():
        means = {}
        variances = {}
        for name in FEATURE_NAMES:
            series = [value[name] for value in values]
            mean = statistics.mean(series) if series else 0.0
            variance = statistics.pvariance(series) if len(series) > 1 else 0.0
            means[name] = mean
            variances[name] = max(variance, 1e-12)
        model[label] = {"n": len(values), "means": means, "variances": variances}
    return model


def score(model: Dict[str, Any], vector: Dict[str, float], label: str) -> float:
    prior = math.log((model[label]["n"] + 1) / (sum(model[x]["n"] for x in model) + 2))
    value = prior
    for name in FEATURE_NAMES:
        variance = model[label]["variances"][name]
        delta = vector[name] - model[label]["means"][name]
        value += -0.5 * (math.log(2 * math.pi * variance) + delta * delta / variance)
    return value


def auc(labels: Sequence[int], scores: Sequence[float]) -> float | None:
    positives = sorted(score for label, score in zip(labels, scores) if label)
    negatives = sorted(score for label, score in zip(labels, scores) if not label)
    if not positives or not negatives:
        return None
    wins = sum(1 for positive in positives for negative in negatives if positive > negative)
    ties = sum(1 for positive in positives for negative in negatives if positive == negative)
    return (wins + 0.5 * ties) / (len(positives) * len(negatives))


def evaluate(rows: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    train = [row for row in rows if not is_test(row["sample_id"])]
    test = [row for row in rows if is_test(row["sample_id"])]
    metrics: Dict[str, Any] = {
        "split": {"train": len(train), "test": len(test), "rule": "sha256(sample_id) mod 5 == 0"},
        "prefixes": {},
    }
    for prefix in (str(value) for value in PREFIXES):
        model = gaussian_model(train, prefix)
        results = []
        for row in test:
            ransomware_score = score(model, row["prefix_features_per_event"][prefix], "ransomware")
            benign_score = score(model, row["prefix_features_per_event"][prefix], "benign")
            results.append(
                {
                    "sample_id": row["sample_id"],
                    "class_label": row["class_label"],
                    "score": ransomware_score - benign_score,
                    "predicted": "ransomware" if ransomware_score >= benign_score else "benign",
                }
            )
        tp = sum(r["predicted"] == "ransomware" and r["class_label"] == "ransomware" for r in results)
        tn = sum(r["predicted"] == "benign" and r["class_label"] == "benign" for r in results)
        fp = sum(r["predicted"] == "ransomware" and r["class_label"] == "benign" for r in results)
        fn = sum(r["predicted"] == "benign" and r["class_label"] == "ransomware" for r in results)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        metrics["prefixes"][prefix] = {
            "n_test": len(results),
            "true_positive": tp,
            "true_negative": tn,
            "false_positive": fp,
            "false_negative": fn,
            "accuracy": (tp + tn) / len(results) if results else None,
            "balanced_accuracy": ((tp / (tp + fn)) + (tn / (tn + fp))) / 2 if (tp + fn) and (tn + fp) else None,
            "precision": precision,
            "recall": recall,
            "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
            "roc_auc": auc(
                [int(r["class_label"] == "ransomware") for r in results],
                [r["score"] for r in results],
            ),
        }
    return metrics


def main() -> int:
    args = parse_args()
    root = args.dataset_root.expanduser().resolve()
    inventory = args.inventory.expanduser()
    output = args.output_dir.expanduser()
    if not root.is_dir():
        print(f"Error: dataset root is not a directory: {root}", file=sys.stderr)
        return 2
    if not inventory.is_file():
        print(f"Error: inventory not found: {inventory}", file=sys.stderr)
        return 2
    if output.exists() and any(output.iterdir()) and not args.overwrite:
        print(f"Error: refusing to overwrite non-empty output: {output}", file=sys.stderr)
        return 1
    output.mkdir(parents=True, exist_ok=True)
    rows = load_inventory(inventory, root)
    if not rows:
        print("Error: inventory contains no readable reports", file=sys.stderr)
        return 2
    feature_path = output / "sample_features.jsonl"
    processed: List[Dict[str, Any]] = []
    with feature_path.open("w", encoding="utf-8") as stream:
        for index, item in enumerate(rows, 1):
            print(f"Processing {index}/{len(rows)}: {item['relative_report_path']}", file=sys.stderr)
            try:
                row = process_sample(item)
                processed.append(row)
                stream.write(json.dumps(row, separators=(",", ":")) + "\n")
            except Exception as exc:
                print(f"Warning: failed {item['relative_report_path']}: {type(exc).__name__}: {exc}", file=sys.stderr)
    metrics = evaluate(processed)
    summary = {
        "dataset_root": str(root),
        "inventory": str(inventory),
        "samples_selected": len(rows),
        "samples_processed": len(processed),
        "samples_failed": len(rows) - len(processed),
        "class_counts": dict(Counter(row["class_label"] for row in processed)),
        "event_counts": {
            label: sum(row["events"] for row in processed if row["class_label"] == label)
            for label in ("benign", "ransomware")
        },
        "methodology": {
            "raw_reports": "streamed with ijson; no report is loaded in full",
            "features": list(FEATURE_NAMES),
            "prefixes": list(PREFIXES),
            "damage_proxy": "observable write/delete/rename/file-information call counts before a model alarm; not physical damage",
            "identity": "candidate handle/path evidence only; no physical-file claims",
            "classifier": "Gaussian Naive Bayes on per-event prefix-normalized sample features",
        },
        "metrics": metrics,
    }
    (output / "metrics.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    report_lines = [
        "# Final EN2025 Streaming Detector Experiment",
        "",
        "## Scope",
        "",
        f"Processed {len(processed)} of {len(rows)} inventory reports in a streaming pass. "
        "The experiment writes compact sample-level aggregates and never modifies raw reports.",
        "",
        "## Scientific safeguards",
        "",
        "- Features are observable CAPE event activity, not claims of physical file damage.",
        "- File handles and paths remain candidate evidence, not guaranteed identities.",
        "- The split is deterministic by SHA-256(sample_id) modulo 5.",
        "- The classifier is a transparent Gaussian Naive Bayes baseline; results are not a production detector.",
        "",
        "## Dataset totals",
        "",
        f"- Benign samples: {summary['class_counts'].get('benign', 0)}",
        f"- Ransomware samples: {summary['class_counts'].get('ransomware', 0)}",
        f"- Benign events: {summary['event_counts']['benign']}",
        f"- Ransomware events: {summary['event_counts']['ransomware']}",
        "",
        "## Detection metrics",
        "",
        "| Prefix | Accuracy | Balanced accuracy | Precision | Recall | F1 | ROC AUC |",
        "|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for prefix, values in metrics["prefixes"].items():
        report_lines.append(
            f"| {float(prefix):.0%} | {values['accuracy']:.3f} | "
            f"{values['balanced_accuracy']:.3f} | {values['precision']:.3f} | "
            f"{values['recall']:.3f} | {values['f1']:.3f} | "
            f"{values['roc_auc']:.3f} |"
        )
    report_lines.extend(
        [
            "",
            "## Limitations",
            "",
            "The available reports do not establish changed bytes, successful content "
            "encryption, physical file identity, or alarm causality. Prefix results "
            "are checkpoint evaluations, not sub-event alarm timestamps. The final "
            "paper must report these as observational proxy results.",
            "",
            "Artifacts: `sample_features.jsonl` and `metrics.json`.",
        ]
    )
    (output / "final_research_report.md").write_text("\n".join(report_lines) + "\n", encoding="utf-8")
    print(f"Processed {len(processed)}/{len(rows)} reports; outputs: {output}")
    return 0 if len(processed) == len(rows) else 2


if __name__ == "__main__":
    raise SystemExit(main())
