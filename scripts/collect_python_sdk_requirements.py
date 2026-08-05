#!/usr/bin/env python3
"""Flatten pyproject.toml's dependency + optional-dependency groups into a
plain requirements file for `pip-audit -r`, which needs a real path (not
`pip list`/the environment) so it also reports on extras nothing has
installed yet.

Usage: python3 scripts/collect_python_sdk_requirements.py <pyproject.toml> <output.txt>
"""

from __future__ import annotations

import sys
import tomllib


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    pyproject_path, output_path = sys.argv[1], sys.argv[2]
    with open(pyproject_path, "rb") as handle:
        data = tomllib.load(handle)
    project = data["project"]
    deps = list(project.get("dependencies", []))
    for extra_deps in project.get("optional-dependencies", {}).values():
        deps.extend(extra_deps)
    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(sorted(set(deps))) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
