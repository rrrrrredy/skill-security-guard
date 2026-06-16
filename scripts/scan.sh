#!/bin/bash
# skill-security-guard: portable shell wrapper around scripts/scan.py
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

find_python() {
  for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c "import sys" >/dev/null 2>&1; then
      echo "$candidate"
      return 0
    fi
  done
  return 1
}

PYTHON_BIN="$(find_python)" || {
  echo "error: python3 or python is required" >&2
  exit 127
}

exec "$PYTHON_BIN" "$SCRIPT_DIR/scan.py" "$@"
