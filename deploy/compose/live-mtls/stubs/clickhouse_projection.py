#!/usr/bin/env python3
"""Shim: live-mTLS compose mounts this path; delegates to reference provider."""

from __future__ import annotations

import runpy
import sys
from pathlib import Path

# When running in the live-mTLS container, the package is mounted beside stubs.
# live-mtls/stubs → repo root is parents[4]
ROOT = Path(__file__).resolve().parents[4] / "apps" / "reference-providers"
if ROOT.is_dir():
    sys.path.insert(0, str(ROOT))
from apex_reference_providers.clickhouse_projection import main  # noqa: E402

if __name__ == "__main__":
    main()
