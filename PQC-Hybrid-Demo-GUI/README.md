# PQC Hybrid Key Exchange Demo

Interactive GUI demo of a **Post-Quantum Cryptographic (PQC) hybrid key exchange** combining ECDH (X25519) and Kyber-768 KEM, with AES-256-GCM authenticated encryption.

## Architecture

| Component | Description |
|-----------|-------------|
| **Server** (`server.c`) | x86_64 C binary — performs the hybrid key exchange and encrypted messaging |
| **Client** (`client.c`) | Connects to the server and initiates the key exchange |
| **GUI** (`src/gui/app.py`) | PySide6 dashboard — visualises the live cryptographic flow with drag-and-drop bundle building |

The GUI and server communicate over a Unix socketpair control/event channel (`--gui-fd`) and the board client is launched over SSH with a reverse tunnel for reliable client→server TCP transport.

Detailed runtime architecture: [`Documentation/ARCHITECTURE.md`](Documentation/ARCHITECTURE.md)

## Prerequisites

- **Python 3.10+**
- **PySide6** (Qt 6 for Python)
- **libsodium** (`sudo apt install libsodium-dev`)
- **GCC** (host) + **aarch64-linux-gnu-gcc** (cross-compiler, only for board deployment)

## Quick Start

### 1. Install Python dependencies

```bash
./install.sh
```

Or manually:

```bash
pip install PySide6
```

### 2. Build the binaries

```bash
make
```

This builds:
- `server` — x86_64 host binary
- `local/client` — x86_64 local client (for testing without a board)
- `shared/bin/client` — aarch64 cross-compiled client (for S4SK board)

### 3. Deploy client to the S4SK board

If using the physical board (not local mode), deploy the cross-compiled client first:

```bash
./deploy.sh
```

This copies `shared/` to the board via SCP. The client must be on the board before starting the demo.

### 4. Run the demo

**Standard mode** (server + GUI, client via SSH to board):

```bash
./run.sh
```

**Local mode** (everything on one machine, no board needed):

```bash
cd local
./run.sh
```

### 5. Using the GUI

1. The server starts automatically and the GUI opens.
2. Click **Connect Vehicle** (or SSH connects to the board).
3. Watch the cryptographic flow appear step-by-step in the flowchart.
4. Drag generated keys into the **bundle collector** slots, then zip and drag the bundle to the broker drop zone.
5. Enter a message (or pick a preset) — it is encrypted, sent, and decrypted on the server side.
6. Click **Reset** to run another exchange.

## Configuration

All IPs, ports, and paths are set in [`config.env`](config.env):

| Variable | Default | Purpose |
|----------|---------|---------|
| `SERVER_IP` | `192.168.0.100` | Host machine IP |
| `BOARD_IP` | `192.168.0.5` | S4SK board IP |
| `PQC_PORT` | `9090` | Server ↔ Client crypto port |
| `GUI_PORT` | `8081` | Server → GUI JSON event port |
| `LOCAL_CLIENT` | `./local/client` | Set empty to use SSH to board instead |

## Project Structure

```
├── config.env          # Global configuration (IPs, ports, paths)
├── install.sh          # Install Python/PySide6 dependencies
├── run.sh              # Launch the GUI + server (standard mode)
├── deploy.sh           # Deploy client binary to S4SK board
├── Makefile            # Build server + client binaries
├── src/
│   ├── gui/
│   │   ├── app.py      # PySide6 GUI app (socketpair + SSH tunnel mode)
│   │   └── assets/     # Icons and images
│   └── server/
│       ├── server.c    # PQC hybrid key exchange server
│       ├── client.c    # PQC client (host build source)
│       └── kyber/      # Kyber KEM reference implementation
├── local/
│   ├── app.py          # GUI (Unix socketpair mode, local dev)
│   └── run.sh          # Launch local mode
└── shared/
    ├── src/client.c    # Client source (board build)
    └── bin/client      # Cross-compiled aarch64 binary
```
