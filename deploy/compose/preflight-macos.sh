#!/usr/bin/env bash
set -Eeuo pipefail

if [[ "$(uname -s)" != Darwin ]]; then
  printf 'Compose preflight: preflight-macos.sh must run on macOS (Darwin).\n' >&2
  exit 1
fi

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
exec "${SCRIPT_DIR}/preflight.sh" "$@"
