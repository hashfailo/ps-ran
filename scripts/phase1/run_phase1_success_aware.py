#!/usr/bin/env python3
"""Run the success-aware Phase 1 validation on the fixed Phase 0C selection."""

from __future__ import annotations

import sys

from . import run_phase1_corrected


if __name__ == "__main__":
    if "--output-dir" not in sys.argv:
        sys.argv.extend(["--output-dir", "outputs/phase1_success_aware"])
    raise SystemExit(run_phase1_corrected.main())
