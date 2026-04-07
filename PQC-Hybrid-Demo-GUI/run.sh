#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"

# Source global config
if [[ -f "$PROJECT_ROOT/config.env" ]]; then
    set -a
    source "$PROJECT_ROOT/config.env"
    set +a
fi

if ! python3 -c "import PySide6" 2>/dev/null; then
    echo "PySide6 is not installed. Run: ./install.sh"
    exit 1
fi

# Kill any leftover server on PQC_PORT
PQC_PORT="${PQC_PORT:-8080}"
GUI_PORT="${GUI_PORT:-8081}"
fuser -k "${PQC_PORT}/tcp" 2>/dev/null || true
fuser -k "${GUI_PORT}/tcp" 2>/dev/null || true

echo "Starting PQC Hybrid Key Exchange Demo..."

cd "$PROJECT_ROOT/src/gui"
exec python3 -c "from app import main; main()" "$@"
