#!/usr/bin/env python3
"""Train the lightweight causal GRU."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.train_neural import run

if __name__ == "__main__":
    raise SystemExit(run("gru"))
