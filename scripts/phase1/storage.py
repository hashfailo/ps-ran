"""JSONL storage and explicit Parquet capability reporting."""

from __future__ import annotations

import importlib.util
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Iterable, Iterator


def parquet_status() -> dict[str, Any]:
    available = importlib.util.find_spec("pyarrow") is not None or importlib.util.find_spec("fastparquet") is not None
    return {
        "available": available,
        "writer": "pyarrow" if importlib.util.find_spec("pyarrow") is not None else "fastparquet" if importlib.util.find_spec("fastparquet") is not None else None,
        "message": "Parquet writer available." if available else "Parquet unavailable; no silent format substitution.",
    }


def write_jsonl(path: Path, records: Iterable[dict[str, Any]]) -> int:
    count = 0
    with path.open("w", encoding="utf-8") as stream:
        for record in records:
            stream.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
            count += 1
    return count


def atomic_write_jsonl(path: Path, records: Iterable[dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    count = 0
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            for record in records:
                stream.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
                count += 1
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        return count
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def atomic_write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def read_jsonl(path: Path) -> Iterator[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as stream:
        for line in stream:
            if line.strip():
                yield json.loads(line)
