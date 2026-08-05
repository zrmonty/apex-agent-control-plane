#!/usr/bin/env python3
"""Fail CI if a lab/dev-only escape hatch leaks outside its approved files.

Some settings are safe only because they're scoped to a specific, reviewed
lab or reference-topology file (e.g. a fixed set of container hostnames, or a
throwaway CI credential). Copy-pasting one of those files as a starting point
for a real deployment silently carries the escape hatch along with it. This
script greps tracked deployment manifests for each guarded pattern and fails
if it turns up anywhere outside that pattern's explicit allowlist.

Run directly: python3 scripts/check_lab_only_settings.py
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Only deployment manifests are scanned -- not docs or source, where the
# setting's own name legitimately appears (e.g. where it's defined or
# explained). The risk this guards against is a manifest an operator might
# copy toward a real deployment, not documentation describing the setting.
MANIFEST_GLOBS = (
    "deploy/compose/**/*.yaml",
    "deploy/compose/**/*.yml",
    "deploy/kubernetes/**/*.yaml",
    "deploy/kubernetes/**/*.yml",
    "deploy/helm/**/*.yaml",
    "deploy/helm/**/*.yml",
    "deploy/helm/**/*.tpl",
)

# pattern -> file paths (relative to repo root) where it is reviewed and
# expected to appear. Anywhere else in a scanned manifest is a failure.
GUARDED_PATTERNS: dict[str, tuple[str, ...]] = {
    "APEX_PROVIDER_ALLOW_UNPINNED_CLIENT": (
        "deploy/compose/compose.e2e.yaml",
        "deploy/compose/compose.gateway-ref.yaml",
    ),
    # World-readable (0644) private key material is a documented Docker-mount
    # workaround for the lab/live-mtls harnesses only; a real deployment's
    # secrets must never be world-readable.
    "0644": (
        "deploy/compose/live-mtls/compose.yaml",
        "deploy/lab/",
    ),
}


def tracked_manifest_files() -> list[Path]:
    output = subprocess.run(
        ["git", "ls-files"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    tracked = {REPO_ROOT / line for line in output.splitlines() if line}
    matched: list[Path] = []
    for pattern in MANIFEST_GLOBS:
        matched.extend(path for path in REPO_ROOT.glob(pattern) if path in tracked)
    return sorted(set(matched))


def is_allowed(path: Path, allowed: tuple[str, ...]) -> bool:
    relative = path.relative_to(REPO_ROOT).as_posix()
    return any(
        relative == entry or relative.startswith(entry) for entry in allowed
    )


def main() -> int:
    violations: list[str] = []
    for path in tracked_manifest_files():
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for pattern, allowed in GUARDED_PATTERNS.items():
            if pattern in text and not is_allowed(path, allowed):
                violations.append(
                    f"{path.relative_to(REPO_ROOT).as_posix()}: contains lab-only "
                    f"setting {pattern!r}, which is only reviewed for {', '.join(allowed)}"
                )

    if violations:
        print("Lab-only settings found outside their approved files:", file=sys.stderr)
        for violation in violations:
            print(f"  - {violation}", file=sys.stderr)
        print(
            "\nIf this file is a genuinely new lab/reference topology, add it to "
            "the pattern's allowlist in scripts/check_lab_only_settings.py after "
            "reviewing why the setting is safe there.",
            file=sys.stderr,
        )
        return 1

    print("No lab-only settings found outside their approved files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
