#!/usr/bin/env python3
"""Load a saved Bag-of-APIs model and score an API sequence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from src.detection.inference import load_saved_model
from src.detection.bag_of_apis import IncrementalBagOfAPIs


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("model_dir", type=Path)
    parser.add_argument("apis", nargs="+")
    args = parser.parse_args()
    model = load_saved_model(args.model_dir)
    predictor = IncrementalBagOfAPIs(model)
    results = [
        {"api": api, **predictor.update(api, index)}
        for index, api in enumerate(args.apis)
    ]
    print(json.dumps({"model": model.metadata, "results": results}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
