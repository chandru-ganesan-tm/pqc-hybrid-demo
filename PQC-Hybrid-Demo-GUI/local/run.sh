#!/usr/bin/env bash
set -euo pipefail

LOCAL_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$LOCAL_DIR/.." && pwd)"

# Source global config
if [[ -f "$PROJECT_ROOT/config.env" ]]; then
    set -a
    source "$PROJECT_ROOT/config.env"
    set +a
fi

# Kill any leftover server on ports
PQC_PORT="${PQC_PORT:-8080}"
GUI_PORT="${GUI_PORT:-8081}"
fuser -k "${PQC_PORT}/tcp" 2>/dev/null || true
fuser -k "${GUI_PORT}/tcp" 2>/dev/null || true

echo "Starting PQC Demo (local mode)..."

# Ensure host binaries match latest source to avoid protocol/version mismatch.
cd "$PROJECT_ROOT"
make -s server local/client

cd "$LOCAL_DIR"
exec python3 -c "from app import main; main()" "$@"
