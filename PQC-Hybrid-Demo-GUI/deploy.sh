#!/usr/bin/env bash
# Deploy shared/ (src + binaries) to the S4SK board.
# Uses Windows scp.exe to bypass WSL2 mirrored networking firewall issues.

set -euo pipefail
cd "$(dirname "$0")"

BOARD_IP="192.168.0.5"
BOARD_USER="root"
REMOTE_DIR="/home/root/PQC-DEMO-Chandru"

if [[ ! -d "shared" ]]; then
    echo "Error: shared/ directory not found"
    exit 1
fi

echo "Deploying shared/ → ${BOARD_USER}@${BOARD_IP}:${REMOTE_DIR}/shared/"
echo ""

# Use Windows scp/ssh if WSL can't reach the board directly
if ping -c 1 -W 1 "$BOARD_IP" &>/dev/null; then
    SCP="scp"
    SSH="ssh"
else
    echo "  (Using Windows scp.exe — WSL can't reach board directly)"
    SCP="scp.exe"
    SSH="ssh.exe"
fi

$SSH -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
    "${BOARD_USER}@${BOARD_IP}" "mkdir -p ${REMOTE_DIR}" 2>/dev/null || true

if $SCP -r -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
    shared "${BOARD_USER}@${BOARD_IP}:${REMOTE_DIR}/"; then
    echo "  OK — deployed to ${REMOTE_DIR}/shared/"
else
    echo "  FAILED (check SSH: ssh ${BOARD_USER}@${BOARD_IP})"
    exit 1
fi

echo ""
echo "Deploy done."
echo "  On the board:  cd ${REMOTE_DIR}/shared/bin && ./client"
