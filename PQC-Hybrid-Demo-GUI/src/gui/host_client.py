"""
Host client: runs on the host and talks to the board agents via TCP only.
Uses one persistent socket per board (reused for all commands). Config from agent_A/variables and agent_B/variables.
Run wake_agents.sh first so agents listen on TCP; then run the GUI.
"""

import base64
import os
import socket
import sys
import threading
from pathlib import Path

# One persistent connection per board; lock per host so only one command at a time on that socket
_sockets: dict[str, socket.socket] = {}
_socket_locks: dict[str, threading.Lock] = {}
_connection_status: dict[str, str] = {}  # "connected" | "disconnected" | "unknown"
_END_MARKER = b"END\n"


def _load_variables(variables_path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    if not variables_path.exists():
        return out
    with open(variables_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip()
    return out


# UI root: ui/ (contains agent_A, agent_B, src)
_UI_ROOT = Path(__file__).resolve().parent.parent.parent
_vars_a = _load_variables(_UI_ROOT / "agent_A" / "variables")
_vars_b = _load_variables(_UI_ROOT / "agent_B" / "variables")

_board_ip_a = _vars_a.get("BOARD_IP", "192.168.1.30")
_board_ip_b = _vars_b.get("BOARD_IP", "192.168.1.40")
_tcp_port = int(_vars_a.get("TCP_PORT", _vars_b.get("TCP_PORT", "9999")), 10)

SOC_A_HOST = f"root@{_board_ip_a}"
SOC_B_HOST = f"root@{_board_ip_b}"
DEVICE_READ_SOC_A = _vars_a.get("DEVICE", "/dev/pci-mmap-ep-ob.0")
DEVICE_READ_SOC_B = _vars_b.get("DEVICE", "/dev/pci-mmap-rc-ib.0")
DEVICE_WRITE = DEVICE_READ_SOC_A
_AGENT_SLOT_SIZE = 0x8000   # 32KB — matches agent on board (do not change)
_AGENT_NUM_SLOTS = 8        # agent slot count (do not change)

SLOT_SIZE  = 0x2000         # 8KB — UI sub-slot size (4 per agent slot)
NUM_SLOTS  = 32             # UI sub-slot count (8 rows × 4 cols)
TOTAL_SIZE = _AGENT_NUM_SLOTS * _AGENT_SLOT_SIZE  # 256KB total

AGENT_TCP_PORT = int(os.environ.get("MEM_UI_AGENT_PORT", str(_tcp_port)), 10)
_tcp_socket_timeout = 15


def _ip_for_host(host: str) -> str:
    return host.split("@", 1)[1] if "@" in host else host


def _lock_for(host: str) -> threading.Lock:
    if host not in _socket_locks:
        _socket_locks[host] = threading.Lock()
    return _socket_locks[host]


def _close_socket(host: str) -> None:
    _connection_status[host] = "disconnected"
    if host in _sockets and _sockets[host] is not None:
        try:
            _sockets[host].close()
        except Exception:
            pass
        _sockets[host] = None


def _get_or_connect(host: str) -> socket.socket:
    """Return existing socket for host or create and connect a new one. Caller must hold lock for host."""
    ip = _ip_for_host(host)
    sock = _sockets.get(host)
    if sock is not None:
        try:
            # Quick check: if recv would block with 0 bytes, socket is still alive (or use a tiny send if supported)
            sock.getpeername()
        except OSError:
            _close_socket(host)
            sock = None
    if sock is None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(_tcp_socket_timeout)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.connect((ip, AGENT_TCP_PORT))
        _sockets[host] = sock
        _connection_status[host] = "connected"
    return sock


def get_connection_status(host: str) -> str:
    """Return 'connected', 'disconnected', or 'unknown' for the given board (host)."""
    return _connection_status.get(host, "unknown")


def probe_connection(host: str) -> None:
    """Try to connect so status is known before the first command. Safe to call from UI timer."""
    with _lock_for(host):
        try:
            _get_or_connect(host)
        except Exception:
            _close_socket(host)


def _read_until_end(sock: socket.socket) -> str:
    """Read until END\\n marker or connection close; return decoded response."""
    buf = b""
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        buf += chunk
        if _END_MARKER in buf:
            return buf.split(_END_MARKER, 1)[0].decode("utf-8", errors="replace").strip()
    return buf.decode("utf-8", errors="replace").strip()


def _tcp_run(host: str, cmd_line: str) -> tuple[bool, str]:
    with _lock_for(host):
        for attempt in range(2):
            try:
                sock = _get_or_connect(host)
                sock.sendall((cmd_line.strip() + "\n").encode("utf-8"))
                combined = _read_until_end(sock)
                if not combined:
                    _close_socket(host)  # peer likely closed; force reconnect on next command
                    if attempt == 1:
                        return False, "Agent TCP: empty response"
                    continue
                _connection_status[host] = "connected"
                return True, combined
            except socket.timeout:
                _close_socket(host)
                if attempt == 1:
                    return False, "Agent TCP: connection timed out"
            except ConnectionRefusedError:
                _close_socket(host)
                if attempt == 1:
                    return False, "Agent TCP: connection refused (run wake_agents.sh on the host first)"
            except OSError as e:
                _close_socket(host)
                if attempt == 1:
                    return False, f"Agent TCP: {e}"
            except Exception as e:
                _close_socket(host)
                if attempt == 1:
                    return False, str(e)
    return False, "Agent TCP: failed"


def _parse_agent_output(combined: str):
    lines = combined.splitlines()
    if not lines:
        return False, []
    first = lines[0].strip().upper()
    body = lines[1:] if len(lines) > 1 else []
    return first == "OK", body


def _run(host: str, cmd_line: str) -> tuple[bool, str]:
    """Send one command to the board agent via TCP. Run wake_agents.sh first."""
    return _tcp_run(host, cmd_line)


def send_to_slot(host: str, slot_index: int, message: str) -> tuple[bool, str]:
    """Write message to UI sub-slot slot_index (0-31).
    Maps to agent slot (slot_index // 4) at byte offset (slot_index % 4) * SLOT_SIZE.
    Uses SEND_AT for non-zero offsets; falls back to SEND for offset 0 (backward-compatible
    with agents that haven't been redeployed yet)."""
    if not (0 <= slot_index < NUM_SLOTS):
        return False, f"Invalid slot index {slot_index}"
    agent_slot = slot_index // 4
    sub_offset = (slot_index % 4) * SLOT_SIZE
    msg_bytes = message.encode("utf-8")[:SLOT_SIZE]
    b64 = base64.b64encode(msg_bytes).decode("ascii")
    if sub_offset == 0:
        cmd = f"SEND {agent_slot} {b64}"
    else:
        cmd = f"SEND_AT {agent_slot} {sub_offset} {b64}"
    ok, out = _run(host, cmd)
    if ok:
        ok_agent, body = _parse_agent_output(out)
        if ok_agent:
            return True, ""
        err_text = "\n".join(body) if body else out or ""
        if sub_offset > 0 and "unknown" in err_text.lower():
            return False, "Agent does not support SEND_AT — redeploy mem_agent.py to the board"
        return False, err_text or "Send failed"
    ok_agent, body = _parse_agent_output(out)
    return False, "\n".join(body) if body else out or "Send failed"


def get_physical_register(host: str) -> tuple[bool, str, str]:
    ok, out = _run(host, "PHYS")
    if not ok:
        return False, "", out
    ok_agent, body = _parse_agent_output(out)
    text = "\n".join(body).strip() if body else ""
    if not ok_agent:
        return False, "", text or out
    return True, text, ""


def clear_memory(host: str) -> tuple[bool, str]:
    ok, out = _run(host, "CLEAR")
    if ok:
        ok_agent, _ = _parse_agent_output(out)
        if ok_agent:
            return True, ""
    return False, out or "Clear failed"


def clear_slot(host: str, slot_index: int) -> tuple[bool, str]:
    """Zero one agent slot (by UI slot_index 0-31; maps to agent slot index 0-7)."""
    if not (0 <= slot_index < NUM_SLOTS):
        return False, f"Invalid slot index {slot_index}"
    agent_slot = slot_index // 4
    ok, out = _run(host, f"CLEAR_SLOT {agent_slot}")
    if not ok:
        return False, out
    ok_agent, _ = _parse_agent_output(out)
    return ok_agent, "" if ok_agent else (out or "Clear slot failed")


def timed_send_to_slot(host: str, slot_index: int, message: str) -> tuple[bool, float, float, str]:
    """Write message and return (ok, ts_before, ts_after, err). Uses agent slot; timestamps are board monotonic."""
    if not (0 <= slot_index < NUM_SLOTS):
        return False, 0.0, 0.0, f"Invalid slot index {slot_index}"
    agent_slot = slot_index // 4
    sub_offset = (slot_index % 4) * SLOT_SIZE
    msg_bytes = message.encode("utf-8")[:SLOT_SIZE]
    b64 = base64.b64encode(msg_bytes).decode("ascii")
    ok, out = _run(host, f"TIMED_SEND {agent_slot} {b64}")  # TIMED_SEND still writes at slot start; sub-offset not needed for timing demo
    if not ok:
        return False, 0.0, 0.0, out
    ok_agent, body = _parse_agent_output(out)
    if not ok_agent:
        return False, 0.0, 0.0, "\n".join(body) if body else out
    lines = [ln.strip() for ln in body if ln.strip()]
    if len(lines) < 2:
        return False, 0.0, 0.0, "Missing timestamps"
    try:
        ts_before = float(lines[0])
        ts_after = float(lines[1])
        return True, ts_before, ts_after, ""
    except ValueError:
        return False, 0.0, 0.0, "Bad timestamp format"


def poll_slot(host: str, slot_index: int, timeout_sec: float = 10.0) -> tuple[bool, float, str]:
    """Poll until slot has data; return (ok, timestamp, err). Uses agent slot."""
    if not (0 <= slot_index < NUM_SLOTS):
        return False, 0.0, f"Invalid slot index {slot_index}"
    agent_slot = slot_index // 4
    ok, out = _run(host, f"POLL_SLOT {agent_slot} {timeout_sec}")
    if not ok:
        return False, 0.0, out
    ok_agent, body = _parse_agent_output(out)
    if not ok_agent:
        return False, 0.0, "\n".join(body) if body else out
    if not body:
        return False, 0.0, "No timestamp"
    try:
        ts = float(body[0].strip())
        return True, ts, ""
    except ValueError:
        return False, 0.0, "Bad timestamp format"


def timed_read_slot(host: str, slot_index: int, size: int) -> tuple[bool, float, float, str, str]:
    """Read slot with timestamps. Returns (ok, ts_before, ts_after, text, err)."""
    if not (0 <= slot_index < NUM_SLOTS):
        return False, 0.0, 0.0, "", f"Invalid slot index {slot_index}"
    agent_slot = slot_index // 4
    sub_offset = (slot_index % 4) * SLOT_SIZE
    read_size = min(size, SLOT_SIZE)
    ok, out = _run(host, f"TIMED_READ_SLOT {agent_slot} {_AGENT_SLOT_SIZE}")
    if not ok:
        return False, 0.0, 0.0, "", out
    ok_agent, body = _parse_agent_output(out)
    if not ok_agent:
        return False, 0.0, 0.0, "", "\n".join(body) if body else out
    # Body: ts_before, ts_after, base64
    if len(body) < 3:
        return False, 0.0, 0.0, "", "Missing timestamps or data"
    try:
        ts_before = float(body[0].strip())
        ts_after = float(body[1].strip())
        raw = base64.b64decode(body[2].strip())
        sub_raw = raw[sub_offset : sub_offset + read_size]
        text = sub_raw.decode("utf-8", errors="replace").split("\x00")[0].strip()
        return True, ts_before, ts_after, text, ""
    except (ValueError, Exception) as e:
        return False, 0.0, 0.0, "", str(e)


def get_time(host: str) -> tuple[bool, float, str]:
    """Return (ok, monotonic_timestamp, err)."""
    ok, out = _run(host, "GET_TIME")
    if not ok:
        return False, 0.0, out
    ok_agent, body = _parse_agent_output(out)
    if not ok_agent or not body:
        return False, 0.0, "\n".join(body) if body else out
    try:
        return True, float(body[0].strip()), ""
    except ValueError:
        return False, 0.0, "Bad timestamp"


def set_time(host: str) -> tuple[bool, str]:
    """No-op for protocol compatibility. Returns (True, '')."""
    ok, out = _run(host, "SET_TIME")
    if not ok:
        return False, out
    ok_agent, _ = _parse_agent_output(out)
    return ok_agent, "" if ok_agent else (out or "SET_TIME failed")


def write_region(host: str, byte_offset: int, data: bytes) -> tuple[bool, str]:
    """Write data at an exact byte offset via single WRITE command. One TCP round-trip."""
    b64 = base64.b64encode(data).decode("ascii")
    ok, out = _run(host, f"WRITE {byte_offset} {b64}")
    if ok:
        ok_agent, body = _parse_agent_output(out)
        if ok_agent:
            return True, ""
        return False, "\n".join(body) if body else out or "Write failed"
    return False, out or "Write failed"


def write_slots(host: str, ui_slots: list[int], chunks: list[str]) -> tuple[bool, str]:
    """Write chunks to UI sub-slots efficiently. Groups contiguous slots into single WRITE commands."""
    if not ui_slots:
        return True, ""
    # Group into contiguous runs for minimal WRITE commands
    runs: list[tuple[int, bytes]] = []  # (byte_offset, payload)
    current_offset = ui_slots[0] * SLOT_SIZE
    current_data = chunks[0].encode("utf-8")[:SLOT_SIZE]
    for i in range(1, len(ui_slots)):
        expected_offset = current_offset + len(current_data)
        actual_offset = ui_slots[i] * SLOT_SIZE
        chunk_bytes = chunks[i].encode("utf-8")[:SLOT_SIZE]
        if actual_offset == expected_offset:
            current_data += chunk_bytes
        else:
            runs.append((current_offset, current_data))
            current_offset = actual_offset
            current_data = chunk_bytes
    runs.append((current_offset, current_data))
    for offset, data in runs:
        ok, err = write_region(host, offset, data)
        if not ok:
            return False, err
    return True, ""


def read_slot(host: str, slot_index: int, size: int) -> tuple[bool, str, str]:
    """Read up to SLOT_SIZE bytes from UI sub-slot slot_index (0-31).
    Maps to the correct 8KB region within agent slot slot_index // 4."""
    if not (0 <= slot_index < NUM_SLOTS):
        return False, "", f"Invalid slot index {slot_index}"
    agent_slot = slot_index // 4
    sub_offset = (slot_index % 4) * SLOT_SIZE  # byte offset within agent slot
    read_size = min(size, SLOT_SIZE)
    # Read the full agent slot and extract the right sub-region
    ok, out = _run(host, f"READ_SLOT {agent_slot} {_AGENT_SLOT_SIZE}")
    if not ok:
        return False, "", out
    ok_agent, body = _parse_agent_output(out)
    if not ok_agent:
        return False, "", "\n".join(body) if body else out
    b64_line = "\n".join(body).strip()
    if not b64_line:
        return False, "", "No data from agent"
    try:
        raw = base64.b64decode(b64_line)
    except Exception as e:
        return False, "", str(e)
    sub_raw = raw[sub_offset : sub_offset + read_size]
    text = sub_raw.decode("utf-8", errors="replace").split("\x00")[0].strip()
    return True, text, ""


def read_slots_bulk(host: str, ui_slots: list[int], sizes: list[int]) -> tuple[bool, list[str], str]:
    """Read multiple UI sub-slots efficiently by grouping by agent slot.

    For full 256KB (all 32 slots), uses a single bulk READ command.
    Otherwise, reads each unique agent slot once and extracts sub-regions.

    Returns (ok, texts, error) where texts[i] corresponds to ui_slots[i].
    """
    if not ui_slots:
        return True, [], ""

    # Full region -> single bulk READ
    if len(ui_slots) >= NUM_SLOTS:
        ok, slot_texts, _raw, err = read_memory(host)
        if not ok:
            return False, [""] * len(ui_slots), err
        texts = [slot_texts[s] if s < len(slot_texts) else "" for s in ui_slots]
        return True, texts, ""

    # Group UI slots by agent slot to avoid redundant reads
    agent_slot_cache: dict[int, bytes] = {}
    errors: list[str] = []

    for ui_slot in ui_slots:
        agent_slot = ui_slot // 4
        if agent_slot in agent_slot_cache:
            continue  # already fetched
        ok, out = _run(host, f"READ_SLOT {agent_slot} {_AGENT_SLOT_SIZE}")
        if not ok:
            errors.append(out)
            agent_slot_cache[agent_slot] = b"\x00" * _AGENT_SLOT_SIZE
            continue
        ok_agent, body = _parse_agent_output(out)
        if not ok_agent:
            errors.append("\n".join(body) if body else out)
            agent_slot_cache[agent_slot] = b"\x00" * _AGENT_SLOT_SIZE
            continue
        b64_line = "\n".join(body).strip()
        if not b64_line:
            errors.append("No data from agent")
            agent_slot_cache[agent_slot] = b"\x00" * _AGENT_SLOT_SIZE
            continue
        try:
            raw = base64.b64decode(b64_line)
            if len(raw) < _AGENT_SLOT_SIZE:
                raw = raw + b"\x00" * (_AGENT_SLOT_SIZE - len(raw))
            agent_slot_cache[agent_slot] = raw
        except Exception as e:
            errors.append(str(e))
            agent_slot_cache[agent_slot] = b"\x00" * _AGENT_SLOT_SIZE

    # Extract sub-regions for each requested UI slot
    texts: list[str] = []
    for i, ui_slot in enumerate(ui_slots):
        agent_slot = ui_slot // 4
        sub_offset = (ui_slot % 4) * SLOT_SIZE
        read_size = min(sizes[i] if i < len(sizes) else SLOT_SIZE, SLOT_SIZE)
        raw = agent_slot_cache.get(agent_slot, b"\x00" * _AGENT_SLOT_SIZE)
        sub_raw = raw[sub_offset : sub_offset + read_size]
        text = sub_raw.decode("utf-8", errors="replace").split("\x00")[0].strip()
        texts.append(text)

    if errors:
        return False, texts, "; ".join(errors)
    return True, texts, ""


def read_memory(host: str) -> tuple[bool, list[str], bytes | None, str]:
    ok, out = _run(host, "READ")
    if not ok:
        return False, [""] * NUM_SLOTS, None, out
    ok_agent, body = _parse_agent_output(out)
    if not ok_agent:
        return False, [""] * NUM_SLOTS, None, "\n".join(body) if body else out
    b64_line = "\n".join(body).strip()
    if not b64_line:
        return False, [""] * NUM_SLOTS, None, "No data from agent"
    try:
        raw = base64.b64decode(b64_line)
    except Exception as e:
        return False, [""] * NUM_SLOTS, None, str(e)
    if len(raw) < TOTAL_SIZE:
        raw = raw + b"\x00" * (TOTAL_SIZE - len(raw))
    else:
        raw = raw[:TOTAL_SIZE]
    slots = []
    for i in range(NUM_SLOTS):
        chunk = raw[i * SLOT_SIZE : (i + 1) * SLOT_SIZE]
        # Only show up to first null — slot may contain old data after the message
        text = chunk.decode("utf-8", errors="replace").split("\x00")[0].strip()
        slots.append(text)
    return True, slots, raw, ""
