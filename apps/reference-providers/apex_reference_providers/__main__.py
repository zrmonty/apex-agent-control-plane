"""python -m apex_reference_providers <clickhouse_projection|archive_provider> ..."""

from __future__ import annotations

import sys


def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] not in {
        "clickhouse_projection",
        "archive_provider",
    }:
        print(
            "usage: python -m apex_reference_providers "
            "{clickhouse_projection|archive_provider} [args...]",
            file=sys.stderr,
        )
        raise SystemExit(2)
    service = sys.argv[1]
    sys.argv = [sys.argv[0], *sys.argv[2:]]
    if service == "clickhouse_projection":
        from .clickhouse_projection import main as run
    else:
        from .archive_provider import main as run
    run()


if __name__ == "__main__":
    main()
