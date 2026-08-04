#!/usr/bin/env bash
# Apex lab installer entrypoint for Linux and macOS.
# Usage:
#   ./deploy/lab/install.sh
#   ./deploy/lab/install.sh install --force --start-live-mtls
#   ./deploy/lab/install.sh enroll --agent my-bot
#   ./deploy/lab/install.sh status

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALLER="${HERE}/install_lab.py"

die() {
  echo "ERROR: $*" >&2
  exit 1
}

find_python() {
  local candidate
  for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then
      if "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then
        echo "$candidate"
        return 0
      fi
    fi
  done
  die "Python 3.11+ is required (python3 on PATH)."
}

PYTHON="$(find_python)"
echo "==> Python: ${PYTHON} ($("${PYTHON}" -c 'import sys; print(sys.version.split()[0])'))"

echo "==> Ensuring cryptography is installed"
if ! "${PYTHON}" -c 'import cryptography' 2>/dev/null; then
  "${PYTHON}" -m pip install --user --quiet 'cryptography>=42' \
    || "${PYTHON}" -m pip install --quiet 'cryptography>=42'
fi

# Default subcommand is install when first arg is a flag or empty.
if [[ $# -eq 0 ]]; then
  set -- install
elif [[ "$1" == -* ]]; then
  set -- install "$@"
fi

echo "==> ${PYTHON} ${INSTALLER} $*"
exec "${PYTHON}" "${INSTALLER}" "$@"
