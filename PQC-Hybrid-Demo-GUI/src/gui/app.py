import sys
import json
import subprocess
import socket
import threading
import logging
import traceback
import shlex
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from PySide6 import QtCore, QtGui, QtWidgets, QtSvg, QtSvgWidgets

# ═══════════════════════════════════════════════════════════════════
# Debug logging — writes to local/tmp/ directory
# ═══════════════════════════════════════════════════════════════════

_LOG_DIR = Path(__file__).resolve().parent / "tmp"
_LOG_DIR.mkdir(exist_ok=True)

def _make_logger(name: str, filename: str) -> logging.Logger:
    lg = logging.getLogger(name)
    lg.setLevel(logging.DEBUG)
    lg.handlers.clear()
    fh = logging.FileHandler(_LOG_DIR / filename, mode="w")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s.%(msecs)03d [%(name)s] %(message)s",
        datefmt="%H:%M:%S",
    ))
    lg.addHandler(fh)
    # Also echo to stderr so terminal shows it live
    sh = logging.StreamHandler(sys.stderr)
    sh.setLevel(logging.DEBUG)
    sh.setFormatter(logging.Formatter("[%(name)s] %(message)s"))
    lg.addHandler(sh)
    return lg

_log_srv = _make_logger("SERVER",  "server.log")   # C server process lifecycle + events
_log_cli = _make_logger("CLIENT",  "client.log")   # C client process lifecycle + events
_log_gui = _make_logger("GUI",     "gui.log")      # socket I/O, state machine, commands
_log_app = _make_logger("APP",     "app.log")       # phase transitions, drag/drop, UI actions


# ═══════════════════════════════════════════════════════════════════
# PQC protocol data — populated by LiveProto from real C binaries
# ═══════════════════════════════════════════════════════════════════

MIME_TOKEN = "application/x-pqc-token"
MIME_INGREDIENT = "application/x-pqc-ingredient"  # individual key dragged into bundle
CLR_ECDH = "#42a5f5"; CLR_KYBER = "#ab47bc"; CLR_HYBRID = "#ffa726"; CLR_CIPHER = "#ef5350"
MODE_ECDH = "ecdh"
MODE_PQC = "pqc"
MODE_HYBRID = "hybrid"

def _short(h, n=32): return h if len(h) <= n else h[:n] + "…"


def _format_duration_us(time_ms) -> str:
    return f"{time_ms * 1000:.0f} us"


def _step_with_duration(step_label: str, time_ms=None) -> str:
    if time_ms in (None, ""):
        return step_label
    return f"{step_label} | {_format_duration_us(time_ms)}"


def _sum_times_ms(values: list[float | None]) -> float | None:
    vals = [v for v in values if v not in (None, "")]
    if not vals:
        return None
    return float(sum(vals))


@dataclass
class KeyEntry:
    label: str
    hexval: str
    color: str
    step: str = ""  # e.g. "Step 1/5"
    in_bundle: bool = False  # part of the active transfer bundle
    size_bytes: int = 0  # byte size for bundle display
    bundle_key: str = ""  # ingredient ID for bundle drops, e.g. "ecdh_pk"
    flow_slot: str = ""   # flowchart position: ecdh_1, ecdh_2, kyber_1, kyber_2, hybrid, output


@dataclass
class Proto:
    """Data container for one exchange. All fields populated by LiveProto from real JSON."""
    s_ecdh_pk: str = ""; s_kyber_pk: str = ""
    c_ecdh_pk: str = ""
    kyber_ct: str = ""; kyber_ss_c: str = ""; kyber_ss_s: str = ""
    ecdh_ss_c: str = ""; ecdh_ss_s: str = ""
    hybrid_c: str = ""; hybrid_s: str = ""
    nonce: str = ""; enc_msg: str = ""
    decrypted: str = ""
    s_ecdh_pk_time_ms: float | None = None
    s_kyber_pk_time_ms: float | None = None
    c_ecdh_pk_time_ms: float | None = None
    ecdh_ss_c_time_ms: float | None = None
    ecdh_ss_s_time_ms: float | None = None
    kyber_ss_c_time_ms: float | None = None
    kyber_ss_s_time_ms: float | None = None
    hybrid_c_time_ms: float | None = None
    hybrid_s_time_ms: float | None = None
    encrypt_time_ms: float | None = None
    decrypt_time_ms: float | None = None

    def reset(self):
        self.__init__()


# ═══════════════════════════════════════════════════════════════════
# LiveProto — drives the GUI from real C server + board client JSON
# ═══════════════════════════════════════════════════════════════════

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent  # PQC-DEMO-Chandru/

def _load_config():
    cfg = {}
    p = _PROJECT_ROOT / "config.env"
    if p.exists():
        for line in p.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                v = v.split("#", 1)[0].strip()   # strip inline comments
                cfg[k.strip()] = v
    return cfg

_CFG = _load_config()
_SERVER_BIN = str(_PROJECT_ROOT / _CFG.get("SERVER_BIN", "./server").lstrip("./"))
_LOCAL_CLIENT = _CFG.get("LOCAL_CLIENT", "").strip()
if _LOCAL_CLIENT:
    _LOCAL_CLIENT = str(_PROJECT_ROOT / _LOCAL_CLIENT.lstrip("./"))
_BOARD_IP = _CFG.get("BOARD_IP", "192.168.0.5")
_BOARD_USER = _CFG.get("BOARD_USER", "root")
_BOARD_CLIENT = _CFG.get("BOARD_CLIENT_PATH", "/home/root/PQC-DEMO-Chandru/shared/bin/client")
_SERVER_IP = _CFG.get("SERVER_IP", "192.168.0.100")
_PQC_PORT = int(_CFG.get("PQC_PORT", "8080"))
_GUI_PORT = int(_CFG.get("GUI_PORT", "8081"))


class LiveProto(QtCore.QObject):
    """Manages real C server subprocess + SSH to board.
    Emits signals that MainWindow maps to panel updates."""

    # Signals carry the JSON dict as a Python dict
    server_event = QtCore.Signal(dict)
    client_event = QtCore.Signal(dict)
    status_msg = QtCore.Signal(str)        # for connection status updates
    exchange_done = QtCore.Signal()         # fired when both sides report complete

    def __init__(self, parent=None):
        super().__init__(parent)
        self._server_proc: subprocess.Popen | None = None
        self._gui_sock: socket.socket | None = None
        self._reader_thread: threading.Thread | None = None
        self._running = False

    # ── lifecycle ──────────────────────────────────────────────

    def start_server(self):
        """Spawn the C server with a Unix socketpair for GUI communication."""
        if self._server_proc is not None:
            _log_srv.warning("start_server called but already running (pid %s)", self._server_proc.pid)
            return  # already running

        self.status_msg.emit("Starting server...")

        # Create a pre-connected Unix socketpair — no TCP, no WSL2 RST bugs
        parent_sock, child_sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        child_sock.set_inheritable(True)
        child_fd = child_sock.fileno()

        srv_log_path = _LOG_DIR / "server_stderr.log"
        self._srv_log_fh = open(srv_log_path, "a")
        self._srv_log_fh.write(f"\n--- Server start {datetime.now()} ---\n")
        self._srv_log_fh.flush()

        _log_srv.info("Spawning: %s --gui-fd %d --port %s --debug", _SERVER_BIN, child_fd, _PQC_PORT)
        self._server_proc = subprocess.Popen(
            [_SERVER_BIN, "--gui-fd", str(child_fd), "--port", str(_PQC_PORT), "--debug"],
            stdout=subprocess.DEVNULL,
            stderr=self._srv_log_fh,
            close_fds=False,   # let child_fd pass through
            pass_fds=(child_fd,),
        )
        child_sock.close()  # parent doesn't need the child's end
        _log_srv.info("Server spawned pid=%d, gui via socketpair (parent fd=%d)",
                     self._server_proc.pid, parent_sock.fileno())

        # Use parent_sock as the GUI socket — already connected, no TCP
        self._gui_sock = parent_sock
        self._gui_sock.set_inheritable(False)
        self._running = True
        _log_gui.info("GUI socketpair connected (fd=%d)", self._gui_sock.fileno())
        self._reader_thread = threading.Thread(
            target=self._read_server_events, daemon=True
        )
        self._reader_thread.start()
        self.status_msg.emit("Server ready")

    def _connect_gui_socket(self):
        """No longer used — socketpair is created in start_server()."""
        pass

    def _read_server_events(self):
        """Background thread: read JSON lines from server GUI socket."""
        _log_gui.info("Reader thread started")
        buf = b""
        recv_count = 0
        while self._running and self._gui_sock:
            try:
                _log_gui.debug("recv() #%d waiting... (buf=%d bytes)", recv_count, len(buf))
                data = self._gui_sock.recv(8192)
                recv_count += 1
                if not data:
                    _log_gui.warning("Reader: recv() #%d returned empty — server closed connection", recv_count)
                    break
                _log_gui.debug("recv() #%d got %d bytes", recv_count, len(data))
                buf += data
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        evt = json.loads(line.decode("utf-8", errors="replace"))
                        _log_srv.debug("← %s", json.dumps(evt, separators=(',', ':')))
                        self.server_event.emit(evt)
                    except json.JSONDecodeError:
                        _log_gui.warning("Reader: non-JSON line: %s", line[:200])
            except OSError as exc:
                _log_gui.error("Reader: recv() #%d OSError %s: %s", recv_count, type(exc).__name__, exc)
                break
        # Diagnose WHY reader exited
        srv_alive = "?"
        if self._server_proc:
            rc = self._server_proc.poll()
            srv_alive = f"alive(pid={self._server_proc.pid})" if rc is None else f"DEAD(rc={rc})"
        _log_gui.warning("Reader thread exiting: server=%s, _running=%s, sock=%s",
                         srv_alive, self._running, self._gui_sock is not None)
        if self._running:
            self.status_msg.emit(f"[DIAG] reader exited: server={srv_alive}")

    def run_client(self, message="", kex_mode=MODE_HYBRID):
        """Run the client locally or via SSH to the board."""
        self._client_message = message
        self._client_kex_mode = kex_mode or MODE_HYBRID
        _log_cli.info("run_client(msg=%r, mode=%s)", message[:60] if message else "", self._client_kex_mode)
        if _LOCAL_CLIENT:
            self.status_msg.emit("Running client locally...")
        else:
            self.status_msg.emit("Running client on board...")
        t = threading.Thread(target=self._client_thread, daemon=True)
        t.start()

    def _client_thread(self):
        if _LOCAL_CLIENT:
            cmd = [_LOCAL_CLIENT, "127.0.0.1", "--json", "--port", str(_PQC_PORT)]
            if self._client_message:
                cmd += ["--msg", self._client_message]
            cmd += ["--kex-mode", self._client_kex_mode]
        else:
            # Route board->server traffic through this SSH session for reliability on WSL/firewalled setups.
            tunnel_port = 19090
            remote_parts = [_BOARD_CLIENT, "127.0.0.1", "--json", "--port", str(tunnel_port)]
            if self._client_message:
                remote_parts += ["--msg", self._client_message]
            remote_parts += ["--kex-mode", self._client_kex_mode]
            remote_cmd = " ".join(shlex.quote(p) for p in remote_parts)
            cmd = [
                "ssh", "-o", "ConnectTimeout=5",
                "-o", "ConnectionAttempts=1",
                "-o", "BatchMode=yes",
                "-o", "ExitOnForwardFailure=yes",
                "-o", "StrictHostKeyChecking=no",
                "-R", f"{tunnel_port}:127.0.0.1:{_PQC_PORT}",
                f"{_BOARD_USER}@{_BOARD_IP}",
                remote_cmd,
            ]
        _log_cli.info("Spawning: %s", " ".join(cmd))
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                close_fds=True,
            )
            _log_cli.info("Client spawned pid=%d", proc.pid)
            timed_out = False
            first_output = False
            startup_timeout = 20
            startup_watchdog_done = threading.Event()

            def _handle_client_output(line: str):
                line = line.strip()
                if not line:
                    return
                try:
                    evt = json.loads(line)
                    _log_cli.debug("← %s", json.dumps(evt, separators=(',', ':')))
                    self.client_event.emit(evt)
                except json.JSONDecodeError:
                    _log_cli.warning("non-JSON output: %s", line[:300])
                    self.status_msg.emit(f"[CLIENT] {line[:160]}")

            def _startup_watchdog():
                nonlocal timed_out
                if startup_watchdog_done.wait(startup_timeout):
                    return
                if first_output:
                    return
                if proc.poll() is None:
                    timed_out = True
                    _log_cli.error("Client produced no output for %ss; terminating pid=%d",
                                   startup_timeout, proc.pid)
                    self.status_msg.emit("Client launch timed out (no initial response from board/client)")
                    proc.terminate()
                    try:
                        proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        proc.kill()

            threading.Thread(target=_startup_watchdog, daemon=True).start()

            if proc.stdout is not None:
                for raw_line in proc.stdout:
                    first_output = True
                    startup_watchdog_done.set()
                    _handle_client_output(raw_line)

            rc = proc.wait()
            startup_watchdog_done.set()
            _log_cli.info("Client exited rc=%d", rc)
            if timed_out:
                self.status_msg.emit("Client timed out before first output.")
            elif rc != 0:
                self.status_msg.emit(f"Client launch failed (rc={rc})")
            self.exchange_done.emit()
        except OSError as e:
            _log_cli.error("Client spawn failed: %s\n%s", e, traceback.format_exc())
            self.status_msg.emit(f"SSH failed: {e}")

    def send_command(self, cmd: str):
        """Send a command (e.g. 'PROCESS') to the server via the GUI socket."""
        srv_status = "?"
        if self._server_proc:
            rc = self._server_proc.poll()
            srv_status = f"alive(pid={self._server_proc.pid})" if rc is None else f"DEAD(rc={rc})"
        else:
            srv_status = "no_proc"
        reader_alive = self._reader_thread.is_alive() if self._reader_thread else False
        sock_fd = self._gui_sock.fileno() if self._gui_sock else -1

        if self._gui_sock:
            try:
                self._gui_sock.sendall((cmd + "\n").encode())
                _log_gui.info("→ send_command(%s) OK  [server=%s, reader=%s, fd=%s]",
                              cmd, srv_status, reader_alive, sock_fd)
                return True
            except OSError as exc:
                _log_gui.error("→ send_command(%s) FAILED: %s: %s  [server=%s, reader=%s, fd=%s]",
                               cmd, type(exc).__name__, exc, srv_status, reader_alive, sock_fd)
                self.status_msg.emit(f"[DIAG] send({cmd}) fail: {exc} | srv={srv_status}")
                return False
        _log_gui.error("→ send_command(%s): _gui_sock is None  [server=%s]", cmd, srv_status)
        self.status_msg.emit(f"[DIAG] send({cmd}): sock=None | srv={srv_status}")
        return False

    def stop(self):
        _log_gui.info("stop() called — shutting down LiveProto")
        self._running = False
        if self._gui_sock:
            try:
                fd = self._gui_sock.fileno()
                self._gui_sock.close()
                _log_gui.info("GUI socket closed (was fd=%s)", fd)
            except OSError as e:
                _log_gui.warning("GUI socket close error: %s", e)
            self._gui_sock = None
        if self._server_proc:
            pid = self._server_proc.pid
            self._server_proc.terminate()
            _log_srv.info("Sent SIGTERM to server pid=%d", pid)
            try:
                rc = self._server_proc.wait(timeout=3)
                _log_srv.info("Server pid=%d exited rc=%d", pid, rc)
            except subprocess.TimeoutExpired:
                self._server_proc.kill()
                _log_srv.warning("Server pid=%d did not exit, sent SIGKILL", pid)
            self._server_proc = None
        if hasattr(self, '_srv_log_fh') and self._srv_log_fh:
            self._srv_log_fh.close()
            self._srv_log_fh = None


# ═══════════════════════════════════════════════════════════════════
# Color palettes — Toyota (Vehicle: red), Toyota Tsusho (Server: blue)
# ═══════════════════════════════════════════════════════════════════

_PALETTES = {
    "A": {
        "header_start": "#0d0d0d", "header_mid": "#2a1518", "header_end": "#0d0d0d",
        "title_color": "#ffffff", "subtitle_color": "#eb0a1e",
        "content_bg": "#0a0a0a", "widget_bg": "#0a0a0a",
        "status_bg": "#1a1a1a", "status_border": "#58595b",
        "status_active": "#eb0a1e", "counter_color": "#eb0a1e",
        "section_bg": "#121212", "section_border": "#58595b",
        "section_title": "#eb0a1e",
        "read_bg": "#080808", "read_border": "#58595b",
        "read_active_border": "#eb0a1e", "read_active_text": "#e8e8e8",
        "read_muted_text": "#888888",
        "input_bg": "#1a1a1a", "input_border": "#58595b",
        "input_text": "#ffffff", "input_focus_border": "#eb0a1e", "input_focus_bg": "#252525",
        "btn_start": "#c40918", "btn_end": "#eb0a1e",
        "btn_hover_start": "#d60b1f", "btn_hover_end": "#ff0d24",
        "btn_press_start": "#9a0716", "btn_press_end": "#b8081b",
        "slot_filled_fill": "#2a1518", "slot_filled_border": "#eb0a1e",
        "slot_empty_fill": "#141414", "slot_empty_border": "#3a3a3a",
        "slot_addr": "#eb0a1e", "slot_label": "#eb0a1e",
        "slot_glow": "#eb0a1e", "slot_bg": "#121212",
    },
    "B": {
        "header_start": "#0d0d0d", "header_mid": "#0f1f2e", "header_end": "#0d0d0d",
        "title_color": "#ffffff", "subtitle_color": "#005ca2",
        "content_bg": "#0a0a0a", "widget_bg": "#0a0a0a",
        "status_bg": "#1a1a1a", "status_border": "#58595b",
        "status_active": "#005ca2", "counter_color": "#005ca2",
        "section_bg": "#121212", "section_border": "#58595b",
        "section_title": "#005ca2",
        "read_bg": "#080808", "read_border": "#58595b",
        "read_active_border": "#005ca2", "read_active_text": "#e8e8e8",
        "read_muted_text": "#888888",
        "input_bg": "#1a1a1a", "input_border": "#58595b",
        "input_text": "#ffffff", "input_focus_border": "#005ca2", "input_focus_bg": "#1a252e",
        "btn_start": "#004a85", "btn_end": "#005ca2",
        "btn_hover_start": "#0066b3", "btn_hover_end": "#0070c0",
        "btn_press_start": "#003d6b", "btn_press_end": "#004a85",
        "slot_filled_fill": "#0f1f2e", "slot_filled_border": "#005ca2",
        "slot_empty_fill": "#141414", "slot_empty_border": "#3a3a3a",
        "slot_addr": "#005ca2", "slot_label": "#005ca2",
        "slot_glow": "#005ca2", "slot_bg": "#121212",
    },
    "BROKER": {
        "header_start": "#0d0d0d", "header_mid": "#1a1a0f", "header_end": "#0d0d0d",
        "title_color": "#ffffff", "subtitle_color": "#f9a825",
        "content_bg": "#0a0a0a", "widget_bg": "#0a0a0a",
        "status_bg": "#1a1a1a", "status_border": "#58595b",
        "status_active": "#f9a825", "counter_color": "#f9a825",
        "section_bg": "#121212", "section_border": "#58595b",
        "section_title": "#f9a825",
        "read_bg": "#080808", "read_border": "#58595b",
        "read_active_border": "#f9a825", "read_active_text": "#e8e8e8",
        "read_muted_text": "#888888",
    },
}


# ═══════════════════════════════════════════════════════════════════
# _DragOverlay — QLabel parented to main window (avoids X11 issues)
# ═══════════════════════════════════════════════════════════════════

class _DragOverlay(QtWidgets.QLabel):
    """A QLabel child of the main window that floats above everything."""
    def __init__(self, pixmap: QtGui.QPixmap, parent_window: QtWidgets.QWidget):
        super().__init__(parent_window)
        self.setPixmap(pixmap)
        self.setFixedSize(pixmap.size())
        self.setAttribute(QtCore.Qt.WA_TransparentForMouseEvents)
        self.setStyleSheet("background: transparent; border: none;")
        self._pw = parent_window
        self._half_w = pixmap.width() // 2
        self._half_h = pixmap.height() // 2
        self.raise_()
        self.follow_cursor()

    def follow_cursor(self):
        # Map global cursor pos to parent widget coordinates
        gpos = QtGui.QCursor.pos()
        local = self._pw.mapFromGlobal(gpos)
        self.move(local.x() - self._half_w, local.y() - self._half_h)


# ═══════════════════════════════════════════════════════════════════
# _BundleCollector — drop target that collects key ingredients
# Shows empty slots → fills up → shows zip icon → becomes draggable
# ═══════════════════════════════════════════════════════════════════

@dataclass
class _BundleSlot:
    key: str        # ingredient ID, e.g. "ecdh_pk"
    label: str      # display name
    color: str
    filled: bool = False
    size_bytes: int = 0


class _BundleCollector(QtWidgets.QFrame):
    """Collects ingredient keys via drag-and-drop.  Once full, shows zip icon and is draggable to broker."""
    bundle_ready = QtCore.Signal()  # emitted when all slots filled

    def __init__(self, pal: dict, parent=None):
        super().__init__(parent)
        self._pal = pal
        self._slots: list[_BundleSlot] = []
        self._token_type: str = ""  # "server_keys" or "client_bundle"
        self._complete = False
        self._dragging = False
        self._drag_start = None
        self._drag_overlay: _DragOverlay | None = None
        self._poll_timer: QtCore.QTimer | None = None
        self._prev_left_down = False
        self.setAcceptDrops(True)
        self.setMouseTracking(True)
        self.setFixedSize(320, 160)

        # Load zip icon
        _assets = QtCore.QFileInfo(__file__).absolutePath() + "/assets"
        self._zip_pix = QtGui.QPixmap(QtCore.QDir(_assets).filePath("zip-folder.png"))
        if not self._zip_pix.isNull():
            self._zip_pix = self._zip_pix.scaled(64, 64, QtCore.Qt.KeepAspectRatio, QtCore.Qt.SmoothTransformation)

        self._restyle()

    def configure(self, token_type: str, slots: list[_BundleSlot]):
        """Set up the bundle with empty slots. Call once per phase."""
        self._token_type = token_type
        self._slots = [_BundleSlot(s.key, s.label, s.color, size_bytes=s.size_bytes) for s in slots]
        self._complete = False
        self._restyle()
        self.update()
        self.show()

    def fill_slot(self, key: str):
        """Mark a slot as filled (called after user drops a key into the bundle)."""
        for s in self._slots:
            if s.key == key and not s.filled:
                s.filled = True
                break
        self._check_complete()
        self.update()

    def auto_fill_all(self):
        """Fill all slots instantly (autonomous mode)."""
        for s in self._slots:
            s.filled = True
        self._check_complete()
        self.update()

    def is_slot_needed(self, key: str) -> bool:
        """Is this ingredient key still needed?"""
        return any(s.key == key and not s.filled for s in self._slots)

    def is_complete(self) -> bool:
        return self._complete

    def clear(self):
        self._slots = []
        self._token_type = ""
        self._complete = False
        self._restyle()
        self.update()
        self.hide()

    def _check_complete(self):
        was = self._complete
        self._complete = bool(self._slots) and all(s.filled for s in self._slots)
        if self._complete and not was:
            self.setCursor(QtCore.Qt.OpenHandCursor)
            self._restyle()
            self.bundle_ready.emit()
        elif not self._complete:
            self.setCursor(QtCore.Qt.ArrowCursor)

    def _restyle(self):
        pal = self._pal
        if self._complete:
            self.setStyleSheet(
                f"_BundleCollector{{ background:{pal['section_bg']}; "
                f"border:2px solid #4caf50; border-radius:10px; }}")
        else:
            self.setStyleSheet(
                f"_BundleCollector{{ background:{pal['section_bg']}; "
                f"border:2px dashed {pal['slot_empty_border']}; border-radius:10px; }}")

    # ── Accept ingredient drops ───────────────────────────────

    def dragEnterEvent(self, ev):
        if self._complete:
            return ev.ignore()
        if ev.mimeData().hasFormat(MIME_INGREDIENT):
            key = ev.mimeData().data(MIME_INGREDIENT).data().decode()
            if self.is_slot_needed(key):
                return ev.acceptProposedAction()
        ev.ignore()

    def dragMoveEvent(self, ev):
        if ev.mimeData().hasFormat(MIME_INGREDIENT):
            key = ev.mimeData().data(MIME_INGREDIENT).data().decode()
            if self.is_slot_needed(key):
                return ev.acceptProposedAction()
        ev.ignore()

    def dropEvent(self, ev):
        if ev.mimeData().hasFormat(MIME_INGREDIENT):
            key = ev.mimeData().data(MIME_INGREDIENT).data().decode()
            if self.is_slot_needed(key):
                self.fill_slot(key)
                ev.acceptProposedAction()
                return
        ev.ignore()

    # ── Drag completed bundle to broker ───────────────────────

    def _find_drop_zone_at(self, gpos):
        top = self.window()
        for dz in top.findChildren(_DropZone):
            if not dz._active:
                continue
            if dz._accept and self._token_type not in dz._accept:
                continue
            local = dz.mapFromGlobal(gpos)
            if dz.rect().contains(local):
                return dz
        return None

    def _highlight_drop_zones(self, gpos):
        top = self.window()
        for dz in top.findChildren(_DropZone):
            if not dz._active:
                continue
            if dz._accept and self._token_type not in dz._accept:
                continue
            local = dz.mapFromGlobal(gpos)
            hovering = dz.rect().contains(local)
            if hovering != dz._hovering:
                dz._hovering = hovering
                dz._restyle()
                if hovering:
                    dz._start_arrow()
                else:
                    dz._stop_arrow()

    def _poll_drag(self):
        gpos = QtGui.QCursor.pos()
        if self._drag_overlay:
            self._drag_overlay.follow_cursor()
        self._highlight_drop_zones(gpos)
        buttons = QtWidgets.QApplication.mouseButtons()
        left_down = bool(buttons & QtCore.Qt.LeftButton)
        if self._prev_left_down and not left_down:
            tok = self._token_type
            dz = self._find_drop_zone_at(gpos)
            self._finish_drag()
            if dz:
                dz.dropped.emit(tok)
            return
        self._prev_left_down = left_down

    def _finish_drag(self):
        if self._poll_timer:
            self._poll_timer.stop(); self._poll_timer = None
        if self._drag_overlay:
            self._drag_overlay.close(); self._drag_overlay = None
        self._dragging = False; self._drag_start = None; self._prev_left_down = False
        self.setCursor(QtCore.Qt.OpenHandCursor if self._complete else QtCore.Qt.ArrowCursor)
        top = self.window()
        for dz in top.findChildren(_DropZone):
            if dz._hovering:
                dz._hovering = False
                dz._restyle()
                dz._stop_arrow()

    def mousePressEvent(self, ev):
        if ev.button() == QtCore.Qt.LeftButton and self._complete:
            self._drag_start = ev.position().toPoint()
        super().mousePressEvent(ev)

    def mouseMoveEvent(self, ev):
        if self._drag_start and self._complete and not self._dragging:
            if (ev.position().toPoint() - self._drag_start).manhattanLength() >= 12:
                self._dragging = True; self._prev_left_down = True
                pix = self.grab()
                scaled = pix.scaled(max(pix.width() // 2, 1), max(pix.height() // 2, 1),
                            QtCore.Qt.KeepAspectRatio, QtCore.Qt.SmoothTransformation)
                self._drag_overlay = _DragOverlay(scaled, self.window())
                self._drag_overlay.show()
                self.setCursor(QtCore.Qt.ClosedHandCursor)
                self._poll_timer = QtCore.QTimer(self)
                self._poll_timer.setInterval(16)
                self._poll_timer.timeout.connect(self._poll_drag)
                self._poll_timer.start()
                return
        super().mouseMoveEvent(ev)

    def mouseReleaseEvent(self, ev):
        if self._dragging:
            gpos = QtGui.QCursor.pos()
            dz = self._find_drop_zone_at(gpos)
            self._finish_drag()
            if dz:
                dz.dropped.emit(self._token_type)
            return
        self._drag_start = None
        super().mouseReleaseEvent(ev)

    # ── Paint ─────────────────────────────────────────────────

    def paintEvent(self, event):
        super().paintEvent(event)
        p = QtGui.QPainter(self)
        p.setRenderHint(QtGui.QPainter.Antialiasing, True)
        p.setRenderHint(QtGui.QPainter.TextAntialiasing, True)
        pal = self._pal
        w = self.width(); h = self.height()

        if not self._slots:
            p.setPen(QtGui.QColor("#546e7a"))
            f = QtGui.QFont(); f.setPointSize(9)
            p.setFont(f)
            p.drawText(self.rect(), QtCore.Qt.AlignCenter, "No bundle required")
            p.end(); return

        if self._complete:
            # Show zip icon centred + label + drag hint
            icon_sz = 64
            block_h = icon_sz + 20 + 16  # icon + label + hint
            icon_y = max(8, (h - block_h) // 2)
            icon_x = (w - icon_sz) // 2
            if not self._zip_pix.isNull():
                p.drawPixmap(icon_x, icon_y, self._zip_pix)
            # Label
            p.setPen(QtGui.QColor("#4caf50"))
            f = QtGui.QFont("Consolas", 9); f.setBold(True)
            p.setFont(f)
            total_bytes = sum(s.size_bytes for s in self._slots)
            label = f"{self._token_type.replace('_', ' ').upper()}"
            p.drawText(QtCore.QRect(0, icon_y + icon_sz + 4, w, 16), QtCore.Qt.AlignCenter, label)
            # Size
            p.setPen(QtGui.QColor("#b0bec5"))
            sf = QtGui.QFont("Consolas", 8)
            p.setFont(sf)
            p.drawText(QtCore.QRect(0, icon_y + icon_sz + 20, w, 14), QtCore.Qt.AlignCenter, f"{total_bytes:,} bytes")
            # Drag hint
            p.setPen(QtGui.QColor("#78909c"))
            hf = QtGui.QFont("Consolas", 8)
            p.setFont(hf)
            p.drawText(QtCore.QRect(0, icon_y + icon_sz + 36, w, 14), QtCore.Qt.AlignCenter, "⟷ drag to broker")
        else:
            # Draw ingredient slots as square boxes
            n = len(self._slots)
            gap = 10
            max_slot = 80
            avail_w = w - 24 - (n - 1) * gap
            slot_sz = min(max_slot, max(50, avail_w // n))
            total_slots_w = n * slot_sz + (n - 1) * gap
            start_x = (w - total_slots_w) // 2
            y = max(8, (h - slot_sz - 24) // 2)

            for i, s in enumerate(self._slots):
                x = start_x + i * (slot_sz + gap)
                r = QtCore.QRect(x, y, slot_sz, slot_sz)
                color = QtGui.QColor(s.color)

                if s.filled:
                    fill = QtGui.QColor(s.color); fill.setAlpha(40)
                    p.setPen(QtCore.Qt.NoPen); p.setBrush(fill)
                    p.drawRoundedRect(r, 8, 8)
                    p.setPen(QtGui.QPen(color, 2)); p.setBrush(QtCore.Qt.NoBrush)
                    p.drawRoundedRect(r.adjusted(1, 1, -1, -1), 7, 7)
                    # Checkmark
                    p.setPen(QtGui.QPen(QtGui.QColor("#4caf50"), 2.5))
                    cx = r.center().x(); cy = r.center().y() + 6
                    p.drawLine(cx - 8, cy, cx - 2, cy + 6)
                    p.drawLine(cx - 2, cy + 6, cx + 8, cy - 6)
                    # Label
                    p.setPen(color)
                    lf = QtGui.QFont("Consolas", 8); lf.setBold(True)
                    p.setFont(lf)
                    p.drawText(r.adjusted(4, 4, -4, -slot_sz // 2), QtCore.Qt.AlignCenter, s.label)
                    # Size
                    p.setPen(QtGui.QColor("#78909c"))
                    sf = QtGui.QFont("Consolas", 7)
                    p.setFont(sf)
                    p.drawText(r.adjusted(4, slot_sz - 18, -4, -2), QtCore.Qt.AlignCenter, f"{s.size_bytes:,} B")
                else:
                    # Empty dashed square
                    p.setPen(QtGui.QPen(QtGui.QColor("#37474f"), 1.5, QtCore.Qt.DashLine))
                    p.setBrush(QtGui.QColor(pal['slot_bg']))
                    p.drawRoundedRect(r, 8, 8)
                    # Label
                    p.setPen(QtGui.QColor("#546e7a"))
                    lf = QtGui.QFont("Consolas", 8)
                    p.setFont(lf)
                    p.drawText(r, QtCore.Qt.AlignCenter, s.label)

            # Progress text
            filled = sum(1 for s in self._slots if s.filled)
            p.setPen(QtGui.QColor("#78909c"))
            pf = QtGui.QFont("Consolas", 9)
            p.setFont(pf)
            p.drawText(QtCore.QRect(0, y + slot_sz + 6, w, 18), QtCore.Qt.AlignCenter,
                       f"Drop keys here  ·  {filled}/{n}")

        p.end()


# ═══════════════════════════════════════════════════════════════════
# _KeyDisplay — painted widget (replaces _SlotDisplay)
# Same rendering style: shadow, gradient border, glow, monospace text
# ═══════════════════════════════════════════════════════════════════

class _KeyDisplay(QtWidgets.QWidget):
    send_clicked = QtCore.Signal(str)

    def __init__(self, board_panel: "BoardPanel", parent=None):
        super().__init__(parent)
        self.board_panel = board_panel
        self._entries: list[KeyEntry] = []
        self.setMouseTracking(True)
        self._hover_index: int | None = None
        self._drag_start = None
        self._drag_index: int | None = None  # which card is being dragged
        self._dragging = False
        self._drag_overlay: _DragOverlay | None = None
        self._poll_timer: QtCore.QTimer | None = None
        self._prev_left_down = False

    def set_entries(self, entries: list[KeyEntry]):
        self._entries = list(entries)
        self.update()

    def set_draggable(self, token_type: str):
        pass  # kept for API compat, no-op now

    def set_recipe(self, *a, **kw):
        pass  # no-op, bundle collector handles this

    def clear_recipe(self):
        pass

    def _flow_rects(self) -> dict[str, list[tuple[int, QtCore.QRect]]]:
        """Return {flow_slot: [(entry_index, rect), ...]} for flowchart layout."""
        pad = 12; arrow_gap = 36; col_gap = 14
        header_h = 16
        w = max(1, self.width()); h = max(1, self.height())

        slots: dict[str, list[int]] = {}
        for i, e in enumerate(self._entries):
            slot = e.flow_slot or "output"
            slots.setdefault(slot, []).append(i)

        # Row order: 0=pk, 1=shared, 2=hybrid, 3=decrypt, 4=nonce, 5=enc_msg
        row_slots = [
            ("ecdh_1", "kyber_1"),   # row 0
            ("ecdh_2", "kyber_2"),   # row 1
            ("hybrid",),             # row 2
            ("decrypt",),            # row 3 (server decrypt)
            ("encrypt_1",),          # row 4 (vehicle nonce)
            ("encrypt_2",),          # row 5 (vehicle enc msg)
            ("output",),             # fallback
        ]
        rows_present = []
        for idx, slot_names in enumerate(row_slots):
            if any(slots.get(s) for s in slot_names):
                rows_present.append(idx)
        n_rows = len(rows_present)
        if n_rows == 0:
            return {}

        # Dynamic gap: use available space, more rows = tighter
        min_gap = 32; max_gap = 60
        avail_for_gaps = h - pad * 2 - header_h - 38 * n_rows
        arrow_gap = max(min_gap, min(max_gap, avail_for_gaps // max(1, n_rows - 1))) if n_rows > 1 else min_gap

        avail_h = h - pad * 2 - header_h - arrow_gap * (n_rows - 1)
        entry_h = min(56, max(38, avail_h // n_rows))
        col_w = (w - pad * 2 - col_gap) // 2
        cw = min(col_w + 40, w - pad * 2)  # centered width

        result: dict[str, list[tuple[int, QtCore.QRect]]] = {}
        y = pad + header_h
        for row_idx in rows_present:
            if row_idx in (0, 1):
                left_slot = "ecdh_1" if row_idx == 0 else "ecdh_2"
                right_slot = "kyber_1" if row_idx == 0 else "kyber_2"
                for slot, x_off in [(left_slot, pad), (right_slot, pad + col_w + col_gap)]:
                    if slot in slots:
                        result[slot] = [(idx, QtCore.QRect(x_off, y, col_w, entry_h)) for idx in slots[slot]]
            elif row_idx == 2:
                if "hybrid" in slots:
                    hx = (w - cw) // 2
                    result["hybrid"] = [(idx, QtCore.QRect(hx, y, cw, entry_h)) for idx in slots["hybrid"]]
            elif row_idx in (3, 4, 5):
                slot_name = {3: "decrypt", 4: "encrypt_1", 5: "encrypt_2"}[row_idx]
                if slot_name in slots:
                    cx = (w - cw) // 2
                    result[slot_name] = [(idx, QtCore.QRect(cx, y, cw, entry_h)) for idx in slots[slot_name]]
            elif row_idx == 6:
                out = slots.get("output", [])
                if out:
                    cx = (w - cw) // 2
                    result["output"] = [(idx, QtCore.QRect(cx, y, cw, entry_h)) for idx in out]
            y += entry_h + arrow_gap
        return result

    def _entry_rects(self) -> list[QtCore.QRect]:
        """Return a flat list of rects indexed by entry index (for hit-testing)."""
        rects = [QtCore.QRect()] * len(self._entries)
        for slot_items in self._flow_rects().values():
            for idx, r in slot_items:
                rects[idx] = r
        return rects

    def _card_at(self, pos) -> int | None:
        for i, r in enumerate(self._entry_rects()):
            if r.contains(pos):
                return i
        return None

    def mousePressEvent(self, ev):
        if ev.button() == QtCore.Qt.LeftButton:
            idx = self._card_at(ev.position().toPoint())
            if idx is not None and self._entries[idx].bundle_key:
                self._drag_start = ev.position().toPoint()
                self._drag_index = idx
        super().mousePressEvent(ev)

    def mouseMoveEvent(self, event):
        pos = event.position().toPoint()
        # Start ingredient drag with visible overlay
        if self._drag_start is not None and self._drag_index is not None and not self._dragging:
            if (pos - self._drag_start).manhattanLength() >= 12:
                e = self._entries[self._drag_index]
                bc = self.board_panel._bundle_collector
                if bc and bc.is_slot_needed(e.bundle_key):
                    self._dragging = True
                    self._prev_left_down = True
                    # Grab the card as a visible overlay
                    rects = self._entry_rects()
                    r = rects[self._drag_index]
                    pix = self.grab(r)
                    self._drag_overlay = _DragOverlay(pix, self.window())
                    self._drag_overlay.show()
                    self.setCursor(QtCore.Qt.ClosedHandCursor)
                    self._poll_timer = QtCore.QTimer(self)
                    self._poll_timer.setInterval(16)
                    self._poll_timer.timeout.connect(self._poll_ingredient_drag)
                    self._poll_timer.start()
                    return
                else:
                    self._drag_start = None
                    self._drag_index = None

        # Hover tracking
        if not self._dragging:
            old = self._hover_index; self._hover_index = None
            for i, r in enumerate(self._entry_rects()):
                if r.contains(pos):
                    self._hover_index = i
                    e = self._entries[i]
                    tip = f"{e.label}\n{e.hexval[:80]}"
                    if e.bundle_key:
                        tip += "\n⟷ drag to bundle"
                    QtWidgets.QToolTip.showText(event.globalPosition().toPoint(), tip, self)
                    break
            else:
                QtWidgets.QToolTip.hideText()
            if old != self._hover_index: self.update()
        super().mouseMoveEvent(event)

    def _poll_ingredient_drag(self):
        gpos = QtGui.QCursor.pos()
        if self._drag_overlay:
            self._drag_overlay.follow_cursor()
        buttons = QtWidgets.QApplication.mouseButtons()
        left_down = bool(buttons & QtCore.Qt.LeftButton)
        if self._prev_left_down and not left_down:
            # Released — check if over bundle collector
            bc = self.board_panel._bundle_collector
            e = self._entries[self._drag_index] if self._drag_index is not None else None
            self._finish_ingredient_drag()
            if bc and e and bc.isVisible():
                local = bc.mapFromGlobal(gpos)
                if bc.rect().contains(local) and bc.is_slot_needed(e.bundle_key):
                    bc.fill_slot(e.bundle_key)
            return
        self._prev_left_down = left_down

    def _finish_ingredient_drag(self):
        if self._poll_timer:
            self._poll_timer.stop(); self._poll_timer = None
        if self._drag_overlay:
            self._drag_overlay.close(); self._drag_overlay = None
        self._dragging = False
        self._drag_start = None
        self._drag_index = None
        self._prev_left_down = False
        self.setCursor(QtCore.Qt.ArrowCursor)

    def mouseReleaseEvent(self, ev):
        if self._dragging:
            gpos = QtGui.QCursor.pos()
            bc = self.board_panel._bundle_collector
            e = self._entries[self._drag_index] if self._drag_index is not None else None
            self._finish_ingredient_drag()
            if bc and e and bc.isVisible():
                local = bc.mapFromGlobal(gpos)
                if bc.rect().contains(local) and bc.is_slot_needed(e.bundle_key):
                    bc.fill_slot(e.bundle_key)
            return
        self._drag_start = None
        self._drag_index = None
        self._dragging = False
        super().mouseReleaseEvent(ev)

    def paintEvent(self, _event):
        import math
        p = QtGui.QPainter(self)
        p.setRenderHint(QtGui.QPainter.Antialiasing, True)
        p.setRenderHint(QtGui.QPainter.TextAntialiasing, True)
        pal = self.board_panel._palette
        p.fillRect(self.rect(), QtGui.QColor(pal['slot_bg']))

        if not self._entries:
            p.setPen(QtGui.QColor("#546e7a"))
            f = QtGui.QFont(); f.setPointSize(11)
            p.setFont(f)
            p.drawText(self.rect(), QtCore.Qt.AlignCenter, "No keys generated yet")
            p.end(); return

        flow = self._flow_rects()
        rects = self._entry_rects()

        # ── Arrow helper with proper angled arrowhead ─────────
        arrow_color = QtGui.QColor("#90a4ae")

        def _draw_arrow(p, x1, y1, x2, y2):
            pen = QtGui.QPen(arrow_color, 1.5, QtCore.Qt.DashLine)
            p.setPen(pen)
            p.setBrush(QtCore.Qt.NoBrush)
            p.drawLine(int(x1), int(y1), int(x2), int(y2))
            angle = math.atan2(y2 - y1, x2 - x1)
            sz = 7
            ax1 = x2 - sz * math.cos(angle - 0.4)
            ay1 = y2 - sz * math.sin(angle - 0.4)
            ax2 = x2 - sz * math.cos(angle + 0.4)
            ay2 = y2 - sz * math.sin(angle + 0.4)
            p.setPen(QtGui.QPen(arrow_color, 1.5))
            p.setBrush(arrow_color)
            path = QtGui.QPainterPath()
            path.moveTo(x2, y2)
            path.lineTo(ax1, ay1)
            path.lineTo(ax2, ay2)
            path.closeSubpath()
            p.drawPath(path)
            p.setBrush(QtCore.Qt.NoBrush)

        # Row 0 → Row 1 (straight down per column)
        for top_slot, bot_slot in [("ecdh_1", "ecdh_2"), ("kyber_1", "kyber_2")]:
            if top_slot in flow and bot_slot in flow:
                tr = flow[top_slot][0][1]
                br = flow[bot_slot][0][1]
                cx = tr.center().x()
                _draw_arrow(p, cx, tr.bottom() + 2, cx, br.top() - 2)

        # Row 1 → Hybrid (diagonal — each arrow lands on its own side of hybrid)
        if "hybrid" in flow:
            hr = flow["hybrid"][0][1]
            hl_x = hr.x() + hr.width() // 3
            hr_x = hr.x() + hr.width() * 2 // 3
            for side_slot, target_x in [("ecdh_2", hl_x), ("kyber_2", hr_x)]:
                if side_slot in flow:
                    sr = flow[side_slot][0][1]
                    _draw_arrow(p, sr.center().x(), sr.bottom() + 2, target_x, hr.top() - 2)
            for top_slot, mid_slot, target_x in [("ecdh_1", "ecdh_2", hl_x), ("kyber_1", "kyber_2", hr_x)]:
                if top_slot in flow and mid_slot not in flow:
                    tr = flow[top_slot][0][1]
                    _draw_arrow(p, tr.center().x(), tr.bottom() + 2, target_x, hr.top() - 2)

        # Hybrid → Decrypt (server side)
        if "hybrid" in flow and "decrypt" in flow:
            hr = flow["hybrid"][0][1]
            dr = flow["decrypt"][0][1]
            _draw_arrow(p, hr.center().x(), hr.bottom() + 2, dr.center().x(), dr.top() - 2)
            # Label
            mid_y = (hr.bottom() + dr.top()) // 2
            p.setPen(QtGui.QColor("#4caf50"))
            lf = QtGui.QFont("Consolas", 7); lf.setBold(True)
            p.setFont(lf)
            p.drawText(QtCore.QRect(hr.center().x() + 6, mid_y - 7, 60, 14),
                       QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter, "Decrypt")

        # Hybrid → Encrypted Message (vehicle side)
        if "hybrid" in flow and "encrypt_1" in flow:
            hr = flow["hybrid"][0][1]
            nr = flow["encrypt_1"][0][1]
            _draw_arrow(p, hr.center().x(), hr.bottom() + 2, nr.center().x(), nr.top() - 2)
            # Label
            mid_y = (hr.bottom() + nr.top()) // 2
            p.setPen(QtGui.QColor(CLR_CIPHER))
            lf = QtGui.QFont("Consolas", 7); lf.setBold(True)
            p.setFont(lf)
            p.drawText(QtCore.QRect(hr.center().x() + 6, mid_y - 7, 60, 14),
                       QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter, "Encrypt")

        # Nonce → Encrypted Message
        if "encrypt_1" in flow and "encrypt_2" in flow:
            nr = flow["encrypt_1"][0][1]
            er = flow["encrypt_2"][0][1]
            _draw_arrow(p, nr.center().x(), nr.bottom() + 2, er.center().x(), er.top() - 2)

        # ── Column headers ────────────────────────────────────
        hf = QtGui.QFont("Consolas", 7); hf.setBold(True)
        if flow.get("ecdh_1") or flow.get("ecdh_2"):
            p.setPen(QtGui.QColor(CLR_ECDH))
            p.setFont(hf)
            ref = (flow.get("ecdh_1") or flow.get("ecdh_2"))[0][1]
            p.drawText(QtCore.QRect(ref.x(), ref.y() - 16, ref.width(), 14),
                       QtCore.Qt.AlignCenter, "CLASSIC (ECDH)")
        if flow.get("kyber_1") or flow.get("kyber_2"):
            p.setPen(QtGui.QColor(CLR_KYBER))
            p.setFont(hf)
            ref = (flow.get("kyber_1") or flow.get("kyber_2"))[0][1]
            p.drawText(QtCore.QRect(ref.x(), ref.y() - 16, ref.width(), 14),
                       QtCore.Qt.AlignCenter, "POST-QUANTUM (KYBER)")

        # ── Draw entry cards ──────────────────────────────────
        for i, r in enumerate(rects):
            if r.isNull():
                continue
            e = self._entries[i]
            color = QtGui.QColor(e.color)
            fill = QtGui.QColor(pal['slot_filled_fill'])
            is_bundle_item = False
            if e.bundle_key:
                bc = self.board_panel._bundle_collector
                is_bundle_item = bc and bc.is_slot_needed(e.bundle_key)

            # shadow
            sr = r.adjusted(2, 2, 2, 2)
            p.setPen(QtCore.Qt.NoPen)
            p.setBrush(QtGui.QColor(0, 0, 0, 80))
            p.drawRoundedRect(sr, 6, 6)
            # fill
            p.setBrush(fill)
            p.drawRoundedRect(r, 6, 6)
            # left accent bar
            bar = QtCore.QRect(r.x(), r.y() + 4, 4, r.height() - 8)
            p.setBrush(color)
            p.drawRoundedRect(bar, 2, 2)
            # border
            gradient = QtGui.QLinearGradient(r.topLeft(), r.bottomRight())
            gradient.setColorAt(0, color); gradient.setColorAt(1, color.darker(120))
            p.setPen(QtGui.QPen(QtGui.QBrush(gradient), 2))
            p.setBrush(QtCore.Qt.NoBrush)
            p.drawRoundedRect(r.adjusted(1, 1, -1, -1), 5, 5)

            # Bundle icon (top-left, inside accent bar area)
            right_reserve = 0
            if is_bundle_item:
                # Small package icon top-right
                pkg_sz = 16
                pkg_x = r.right() - pkg_sz - 4
                pkg_y = r.top() + 3
                pkg_r = QtCore.QRect(pkg_x, pkg_y, pkg_sz, pkg_sz)
                pkg_bg = QtGui.QColor(e.color); pkg_bg.setAlpha(50)
                p.setPen(QtCore.Qt.NoPen); p.setBrush(pkg_bg)
                p.drawRoundedRect(pkg_r, 3, 3)
                p.setPen(QtGui.QPen(QtGui.QColor("#b0bec5"), 1.2))
                p.setBrush(QtCore.Qt.NoBrush)
                # Draw a small box outline
                bx = pkg_x + 3; by = pkg_y + 4; bw = pkg_sz - 6; bh = pkg_sz - 7
                p.drawRect(bx, by, bw, bh)
                # ribbon across middle
                p.drawLine(bx + bw // 2, by, bx + bw // 2, by + bh)
                right_reserve = pkg_sz + 8

            # Step badge (top-right, before bundle icon)
            badge_w = 0
            if e.step:
                sf = QtGui.QFont("Consolas", 7); sf.setBold(True)
                p.setFont(sf)
                fm = QtGui.QFontMetrics(sf)
                tw = fm.horizontalAdvance(e.step) + 10
                badge_x = r.right() - tw - 4 - right_reserve
                badge_r = QtCore.QRect(badge_x, r.top() + 4, tw, 15)
                badge_col = QtGui.QColor(e.color); badge_col.setAlpha(40)
                p.setPen(QtCore.Qt.NoPen); p.setBrush(badge_col)
                p.drawRoundedRect(badge_r, 3, 3)
                p.setPen(color); p.drawText(badge_r, QtCore.Qt.AlignCenter, e.step)
                badge_w = tw + 4 + right_reserve

            # Label (top half, clipped to avoid badge)
            lf = QtGui.QFont("Consolas", 8); lf.setStyleHint(QtGui.QFont.Monospace); lf.setBold(True)
            p.setFont(lf); p.setPen(color)
            label_r = r.adjusted(12, 2, -badge_w - 4, -r.height() // 2)
            p.drawText(label_r, QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter, e.label)

            # Hex (bottom half)
            vf = QtGui.QFont("Consolas", 8); vf.setStyleHint(QtGui.QFont.Monospace)
            p.setFont(vf); p.setPen(QtGui.QColor("#90a4ae"))
            p.drawText(r.adjusted(12, r.height() // 2, -8, -3),
                       QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter, _short(e.hexval, 24))

            # Hover glow
            if self._hover_index == i:
                p.setBrush(QtCore.Qt.NoBrush)
                for width, alpha in [(8, 30), (5, 60), (3, 100)]:
                    gc = QtGui.QColor(e.color); gc.setAlpha(alpha)
                    p.setPen(QtGui.QPen(gc, width))
                    p.drawRoundedRect(r.adjusted(-width // 2, -width // 2, width // 2, width // 2), 8, 8)
        p.end()


# ═══════════════════════════════════════════════════════════════════
# _PacketPanel — draggable "packet" showing queued items to transfer
# ═══════════════════════════════════════════════════════════════════

@dataclass
class PacketItem:
    label: str
    hexval: str
    color: str
    size_bytes: int  # original byte count for display


class _PacketPanel(QtWidgets.QFrame):
    """A compact panel showing items queued in a packet, draggable to a drop zone."""
    send_clicked = QtCore.Signal(str)

    def __init__(self, pal: dict, token_type: str = "", parent=None):
        super().__init__(parent)
        self._pal = pal
        self._token_type = token_type
        self._items: list[PacketItem] = []
        self._drag_start = None
        self._dragging = False
        self._drag_overlay: _DragOverlay | None = None
        self._poll_timer: QtCore.QTimer | None = None
        self._prev_left_down = False
        self.setCursor(QtCore.Qt.ArrowCursor)
        self.setMouseTracking(True)

        # Layout
        self._main_layout = QtWidgets.QVBoxLayout(self)
        self._main_layout.setContentsMargins(0, 0, 0, 0)
        self._main_layout.setSpacing(0)

        # Header
        self._header = QtWidgets.QWidget()
        self._header.setAttribute(QtCore.Qt.WA_TransparentForMouseEvents)
        hl = QtWidgets.QHBoxLayout(self._header)
        hl.setContentsMargins(12, 8, 12, 8)
        self._title = QtWidgets.QLabel("📦 PACKET")
        self._title.setAttribute(QtCore.Qt.WA_TransparentForMouseEvents)
        self._title.setStyleSheet(f"color:{pal['section_title']}; font-size:10px; font-weight:bold; letter-spacing:1px; background:transparent;")
        self._size_label = QtWidgets.QLabel("")
        self._size_label.setAttribute(QtCore.Qt.WA_TransparentForMouseEvents)
        self._size_label.setStyleSheet(f"color:{pal['read_muted_text']}; font-size:9px; background:transparent;")
        self._drag_hint = QtWidgets.QLabel("⟷ drag to send")
        self._drag_hint.setAttribute(QtCore.Qt.WA_TransparentForMouseEvents)
        self._drag_hint.setStyleSheet(f"color:{pal['read_muted_text']}; font-size:9px; background:transparent;")
        self._drag_hint.hide()
        hl.addWidget(self._title)
        hl.addStretch()
        hl.addWidget(self._size_label)
        hl.addWidget(self._drag_hint)
        self._main_layout.addWidget(self._header)

        # Items container
        self._items_container = QtWidgets.QWidget()
        self._items_container.setAttribute(QtCore.Qt.WA_TransparentForMouseEvents)
        self._items_layout = QtWidgets.QVBoxLayout(self._items_container)
        self._items_layout.setContentsMargins(8, 0, 8, 8)
        self._items_layout.setSpacing(3)
        self._main_layout.addWidget(self._items_container)

        self._restyle()
        self.setSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Maximum)
        self.hide()
        self._content_key = None  # tracks (title, item_hexvals) — data only

    def set_packet(self, title: str, token_type: str, items: list[PacketItem]):
        """Set packet contents and show. Skips widget rebuild if data unchanged."""
        content_key = (title, tuple(it.hexval for it in items))
        need_rebuild = (content_key != self._content_key)

        # Always update draggable state
        if token_type != self._token_type:
            self._token_type = token_type
            self._drag_hint.setVisible(bool(token_type))
            self.setCursor(QtCore.Qt.OpenHandCursor if token_type else QtCore.Qt.ArrowCursor)
            self._restyle()

        if not need_rebuild:
            self.show()
            return

        self._content_key = content_key
        self._items = items
        self._title.setText(f"📦 {title}")
        total = sum(it.size_bytes for it in items)
        self._size_label.setText(f"{total:,} bytes")

        # Clear old item rows
        while self._items_layout.count():
            w = self._items_layout.takeAt(0).widget()
            if w: w.deleteLater()

        # Add new item rows
        for it in items:
            row = self._make_item_row(it)
            self._items_layout.addWidget(row)

        self._restyle()
        self.show()

    def clear_packet(self):
        self._content_key = None
        self._token_type = ""
        self._items = []
        self._drag_hint.hide()
        self.setCursor(QtCore.Qt.ArrowCursor)
        while self._items_layout.count():
            w = self._items_layout.takeAt(0).widget()
            if w: w.deleteLater()
        self.hide()

    def _make_item_row(self, item: PacketItem) -> QtWidgets.QWidget:
        row = QtWidgets.QFrame()
        row.setAttribute(QtCore.Qt.WA_TransparentForMouseEvents)
        color = item.color
        row.setStyleSheet(f"QFrame{{ background:{self._pal['slot_filled_fill']}; "
                          f"border-left:3px solid {color}; border-radius:4px; }}")
        rl = QtWidgets.QHBoxLayout(row)
        rl.setContentsMargins(8, 4, 8, 4); rl.setSpacing(8)

        lbl = QtWidgets.QLabel(item.label)
        lbl.setAttribute(QtCore.Qt.WA_TransparentForMouseEvents)
        lbl.setStyleSheet(f"color:{color}; font-size:10px; font-weight:bold; "
                          f"font-family:'Consolas',monospace; background:transparent; border:none;")

        size_lbl = QtWidgets.QLabel(f"{item.size_bytes} B")
        size_lbl.setAttribute(QtCore.Qt.WA_TransparentForMouseEvents)
        size_lbl.setStyleSheet(f"color:{self._pal['read_muted_text']}; font-size:9px; "
                               f"background:transparent; border:none;")

        hex_lbl = QtWidgets.QLabel(_short(item.hexval, 28))
        hex_lbl.setAttribute(QtCore.Qt.WA_TransparentForMouseEvents)
        hex_lbl.setStyleSheet(f"color:#78909c; font-size:9px; font-family:'Consolas',monospace; "
                              f"background:transparent; border:none;")
        hex_lbl.setToolTip(item.hexval[:120])

        rl.addWidget(lbl)
        rl.addStretch()
        rl.addWidget(hex_lbl)
        rl.addWidget(size_lbl)
        return row

    def _restyle(self):
        pal = self._pal
        if self._token_type:
            self.setStyleSheet(f"_PacketPanel{{ background:{pal['section_bg']}; "
                               f"border:2px solid {pal['subtitle_color']}; border-radius:8px; }}")
        else:
            self.setStyleSheet(f"_PacketPanel{{ background:{pal['section_bg']}; "
                               f"border:1px solid {pal['slot_empty_border']}; border-radius:8px; }}")

    # ── Drag support (same polling approach as _KeyDisplay) ───

    def _find_drop_zone_at(self, global_pos):
        top = self.window()
        for dz in top.findChildren(_DropZone):
            if not dz._active:
                continue
            if dz._accept and self._token_type not in dz._accept:
                continue
            local = dz.mapFromGlobal(global_pos)
            if dz.rect().contains(local):
                return dz
        return None

    def _highlight_drop_zones(self, global_pos):
        top = self.window()
        for dz in top.findChildren(_DropZone):
            if not dz._active:
                continue
            if dz._accept and self._token_type not in dz._accept:
                continue
            local = dz.mapFromGlobal(global_pos)
            hovering = dz.rect().contains(local)
            if hovering != dz._hovering:
                dz._hovering = hovering
                dz._restyle()

    def _poll_drag(self):
        gpos = QtGui.QCursor.pos()
        if self._drag_overlay:
            self._drag_overlay.follow_cursor()
        self._highlight_drop_zones(gpos)
        buttons = QtWidgets.QApplication.mouseButtons()
        left_down = bool(buttons & QtCore.Qt.LeftButton)
        if self._prev_left_down and not left_down:
            tok = self._token_type
            dz = self._find_drop_zone_at(gpos)
            self._finish_drag()
            if dz:
                dz.dropped.emit(tok)
            return
        self._prev_left_down = left_down

    def _finish_drag(self):
        if self._poll_timer:
            self._poll_timer.stop(); self._poll_timer = None
        if self._drag_overlay:
            self._drag_overlay.close(); self._drag_overlay = None
        self._dragging = False; self._drag_start = None; self._prev_left_down = False
        self.setCursor(QtCore.Qt.OpenHandCursor if self._token_type else QtCore.Qt.ArrowCursor)
        top = self.window()
        for dz in top.findChildren(_DropZone):
            if dz._hovering:
                dz._hovering = False; dz._restyle()

    def mousePressEvent(self, ev):
        if ev.button() == QtCore.Qt.LeftButton and self._token_type:
            self._drag_start = ev.position().toPoint()
        super().mousePressEvent(ev)

    def mouseMoveEvent(self, ev):
        if self._drag_start and self._token_type and not self._dragging:
            if (ev.position().toPoint() - self._drag_start).manhattanLength() >= 12:
                self._dragging = True; self._prev_left_down = True
                pix = self.grab()
                scaled = pix.scaled(max(pix.width() // 2, 1), max(pix.height() // 2, 1),
                            QtCore.Qt.KeepAspectRatio, QtCore.Qt.SmoothTransformation)
                self._drag_overlay = _DragOverlay(scaled, self.window())
                self._drag_overlay.show()
                self.setCursor(QtCore.Qt.ClosedHandCursor)
                self._poll_timer = QtCore.QTimer(self)
                self._poll_timer.setInterval(16)
                self._poll_timer.timeout.connect(self._poll_drag)
                self._poll_timer.start()
                return
        super().mouseMoveEvent(ev)

    def mouseReleaseEvent(self, ev):
        if self._dragging:
            tok = self._token_type
            dz = self._find_drop_zone_at(QtGui.QCursor.pos())
            self._finish_drag()
            if dz:
                dz.dropped.emit(tok)
            return
        self._drag_start = None
        super().mouseReleaseEvent(ev)


# ═══════════════════════════════════════════════════════════════════
# Drop zone + draggable token (for interactive exchange)
# ═══════════════════════════════════════════════════════════════════

class _DropZone(QtWidgets.QFrame):
    dropped = QtCore.Signal(str)
    def __init__(self, pal, arrow_dir="ltr", parent=None):
        super().__init__(parent)
        self._active = False; self._hovering = False; self._accept = []; self._pal = pal
        self._arrow_dir = arrow_dir
        self._arrow_progress = 0.0
        self._arrow_color = "#4caf50"
        self.setAcceptDrops(True); self.setFixedHeight(80)
        lay = QtWidgets.QVBoxLayout(self); lay.setAlignment(QtCore.Qt.AlignCenter)
        self._label = QtWidgets.QLabel("Drop zone")
        self._label.setAlignment(QtCore.Qt.AlignCenter)
        self._label.setStyleSheet(f"color:{pal['read_muted_text']}; font-size:12px; background:transparent;")
        lay.addWidget(self._label); self._restyle()

        # Load arrow PNG
        _assets = QtCore.QFileInfo(__file__).absolutePath() + "/assets"
        self._arrow_pix = QtGui.QPixmap(QtCore.QDir(_assets).filePath("PQC_Hybrid_Arrow.png"))
        if arrow_dir == "rtl" and not self._arrow_pix.isNull():
            # Mirror horizontally
            self._arrow_pix = self._arrow_pix.transformed(
                QtGui.QTransform().scale(-1, 1))

        # Arrow animation
        self._anim = QtCore.QPropertyAnimation(self, b"arrowProgress", self)
        self._anim.setDuration(900)
        self._anim.setStartValue(0.0)
        self._anim.setEndValue(1.0)
        self._anim.setLoopCount(-1)
        self._anim.setEasingCurve(QtCore.QEasingCurve.Linear)

    @QtCore.Property(float)
    def arrowProgress(self):
        return self._arrow_progress

    @arrowProgress.setter
    def arrowProgress(self, val):
        self._arrow_progress = val
        self.update()

    def activate(self, active, label="", accept=None):
        self._active = active; self._accept = accept or self._accept
        self._label.setText(label if active else "Drop zone")
        self._restyle()

    def _restyle(self):
        pal = self._pal
        if self._hovering:
            ss = f"_DropZone{{ background:rgba(27,58,32,180); border:none; }}"
        elif self._active:
            ss = f"_DropZone{{ background:rgba(255,255,255,8); border:none; }}"
        else:
            ss = f"_DropZone{{ background:transparent; border:none; }}"
        self.setStyleSheet(ss)

    def _start_arrow(self):
        self._arrow_color = "#4caf50"
        self._anim.start()

    def _stop_arrow(self):
        self._anim.stop()
        self._arrow_progress = 0.0
        self.update()

    def dragEnterEvent(self, ev):
        if not self._active: return ev.ignore()
        if ev.mimeData().hasFormat(MIME_TOKEN):
            tok = ev.mimeData().data(MIME_TOKEN).data().decode()
            if not self._accept or tok in self._accept:
                self._hovering = True; self._restyle()
                self._start_arrow()
                return ev.acceptProposedAction()
        ev.ignore()

    def dragLeaveEvent(self, _):
        self._hovering = False; self._restyle()
        self._stop_arrow()

    def dropEvent(self, ev):
        self._hovering = False; self._restyle()
        self._stop_arrow()
        if ev.mimeData().hasFormat(MIME_TOKEN):
            self.dropped.emit(ev.mimeData().data(MIME_TOKEN).data().decode()); ev.acceptProposedAction()

    def paintEvent(self, event):
        super().paintEvent(event)
        p = QtGui.QPainter(self)
        p.setRenderHint(QtGui.QPainter.Antialiasing, True)
        p.setRenderHint(QtGui.QPainter.SmoothPixmapTransform, True)

        w = self.width(); h = self.height()

        if not self._arrow_pix.isNull():
            margin = 12
            avail_w = w - margin * 2
            avail_h = h - margin * 2
            scaled = self._arrow_pix.scaled(
                avail_w, avail_h,
                QtCore.Qt.KeepAspectRatio,
                QtCore.Qt.SmoothTransformation)
            x = (w - scaled.width()) // 2
            y = (h - scaled.height()) // 2

            if self._hovering:
                p.setOpacity(0.9)
            elif self._active:
                p.setOpacity(0.25)
            else:
                p.setOpacity(0.08)

            p.drawPixmap(x, y, scaled)
            p.setOpacity(1.0)

        # Animated dot when hovering
        if self._hovering:
            t = self._arrow_progress
            margin = 20
            color = QtGui.QColor(self._arrow_color)
            if self._arrow_dir == "ltr":
                dot_x = margin + (w - 2 * margin) * t
            else:
                dot_x = w - margin - (w - 2 * margin) * t
            dot_y = h / 2
            glow = QtGui.QColor(color); glow.setAlpha(50)
            p.setBrush(glow); p.setPen(QtCore.Qt.NoPen)
            p.drawEllipse(QtCore.QPointF(dot_x, dot_y), 10, 10)
            core = QtGui.QColor("#ffffff"); core.setAlpha(230)
            p.setBrush(core)
            p.drawEllipse(QtCore.QPointF(dot_x, dot_y), 4, 4)

        p.end()


class _DraggableToken(QtWidgets.QFrame):
    send_clicked = QtCore.Signal(str)
    def __init__(self, label, value, color, token_type, pal, parent=None):
        super().__init__(parent)
        self.token_type = token_type; self._drag_start = None
        self.setStyleSheet(f"_DraggableToken{{ background:{pal['slot_filled_fill']}; border:2px solid {color}; border-radius:8px; }}")
        self.setCursor(QtCore.Qt.OpenHandCursor)
        lay = QtWidgets.QHBoxLayout(self); lay.setContentsMargins(12, 6, 12, 6)
        left = QtWidgets.QVBoxLayout()
        lbl = QtWidgets.QLabel(f"● {label}")
        lbl.setStyleSheet(f"color:{color}; font-weight:bold; font-size:11px; background:transparent;")
        val = QtWidgets.QLabel(_short(value, 48))
        val.setStyleSheet(f"color:{pal['read_active_text']}; font-family:'Consolas',monospace; font-size:10px; background:transparent;")
        val.setWordWrap(True)
        left.addWidget(lbl); left.addWidget(val); lay.addLayout(left, 1)
        right = QtWidgets.QVBoxLayout(); right.setAlignment(QtCore.Qt.AlignCenter)
        hint = QtWidgets.QLabel("⟷ drag")
        hint.setStyleSheet(f"color:{pal['read_muted_text']}; font-size:9px; background:transparent;")
        btn = QtWidgets.QPushButton("Send")
        btn.setFixedSize(50, 24); btn.setCursor(QtCore.Qt.PointingHandCursor)
        btn.setStyleSheet(f"QPushButton{{background:{color};color:white;border:none;border-radius:4px;font-size:10px;font-weight:bold;}} QPushButton:hover{{background:#78909c;}}")
        btn.clicked.connect(lambda: self.send_clicked.emit(self.token_type))
        right.addWidget(hint); right.addWidget(btn); lay.addLayout(right)

    def mousePressEvent(self, ev):
        if ev.button() == QtCore.Qt.LeftButton: self._drag_start = ev.position().toPoint()
        super().mousePressEvent(ev)
    def mouseMoveEvent(self, ev):
        if self._drag_start is None: return
        if (ev.position().toPoint() - self._drag_start).manhattanLength() < 12: return
        src = self.grab()
        drag_pix = QtGui.QPixmap(src.size()); drag_pix.fill(QtCore.Qt.transparent)
        pp = QtGui.QPainter(drag_pix); pp.setOpacity(0.70); pp.drawPixmap(0, 0, src); pp.end()
        offset = ev.position().toPoint()
        self._overlay = _DragOverlay(drag_pix, QtCore.QPoint(offset.x(), offset.y()))
        self._overlay.show()
        self._dtimer = QtCore.QTimer(); self._dtimer.setInterval(16)
        self._dtimer.timeout.connect(lambda: self._overlay.move_to_cursor() if self._overlay else None)
        self._dtimer.start()
        drag = QtGui.QDrag(self); mime = QtCore.QMimeData()
        mime.setData(MIME_TOKEN, self.token_type.encode()); drag.setMimeData(mime)
        tiny = QtGui.QPixmap(1, 1); tiny.fill(QtCore.Qt.transparent); drag.setPixmap(tiny)
        drag.exec(QtCore.Qt.MoveAction)
        if hasattr(self, '_dtimer') and self._dtimer: self._dtimer.stop()
        if hasattr(self, '_overlay') and self._overlay: self._overlay.close(); self._overlay = None
        self._drag_start = None
    def mouseReleaseEvent(self, ev): self._drag_start = None; super().mouseReleaseEvent(ev)


# ═══════════════════════════════════════════════════════════════════
# BrokerPanel — narrow middle column showing relay activity
# ═══════════════════════════════════════════════════════════════════

class BrokerPanel(QtWidgets.QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        pal = _PALETTES["BROKER"]
        self._palette = pal

        main_layout = QtWidgets.QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0); main_layout.setSpacing(0)

        # Header
        header = QtWidgets.QWidget(); header.setFixedHeight(70)
        header.setStyleSheet(f"QWidget {{ background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 {pal['header_start']}, stop:0.5 {pal['header_mid']}, stop:1 {pal['header_end']}); }}")
        hl = QtWidgets.QHBoxLayout(header); hl.setContentsMargins(12, 10, 12, 10)
        text_col = QtWidgets.QVBoxLayout()
        title = QtWidgets.QLabel("BROKER")
        tf = title.font(); tf.setPointSize(14); tf.setBold(True); tf.setLetterSpacing(QtGui.QFont.AbsoluteSpacing, 2)
        title.setFont(tf); title.setStyleSheet(f"color:{pal['title_color']}; background:transparent;")
        sub = QtWidgets.QLabel("Relay • Middleware")
        sub.setStyleSheet(f"color:{pal['subtitle_color']}; font-size:10px; background:transparent; letter-spacing:1px;")
        text_col.addWidget(title, alignment=QtCore.Qt.AlignCenter)
        text_col.addWidget(sub, alignment=QtCore.Qt.AlignCenter)
        hl.addLayout(text_col)
        main_layout.addWidget(header)

        # Content — unified drop area with two halves
        content = QtWidgets.QWidget(); content.setStyleSheet(f"background-color:{pal['content_bg']};")
        cl = QtWidgets.QVBoxLayout(content); cl.setContentsMargins(8, 10, 8, 10); cl.setSpacing(0)

        # Single connected container holding both drop zones
        drop_container = QtWidgets.QFrame()
        drop_container.setObjectName("dropContainer")
        drop_container.setStyleSheet(
            "#dropContainer { background-color:#0d0d0d; border:2px solid #2a2a2a; border-radius:10px; }"
        )
        dc_lay = QtWidgets.QVBoxLayout(drop_container)
        dc_lay.setContentsMargins(0, 0, 0, 0); dc_lay.setSpacing(0)

        # Top half — Server → Vehicle (accepts server_keys)
        pal_a = _PALETTES["A"]
        self.drop_server_to_vehicle = _DropZone(pal_a, arrow_dir="ltr")
        self.drop_server_to_vehicle.setMinimumHeight(50)
        self.drop_server_to_vehicle.setMaximumHeight(16777215)
        self.drop_server_to_vehicle.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        self.drop_server_to_vehicle.setStyleSheet(
            "_DropZone { background:transparent; border:none; border-radius:0px; }"
        )
        dc_lay.addWidget(self.drop_server_to_vehicle, 1)

        # Divider line
        divider = QtWidgets.QFrame()
        divider.setFixedHeight(1)
        divider.setStyleSheet("background-color:#2a2a2a;")
        dc_lay.addWidget(divider)

        # Bottom half — Vehicle → Server (accepts client_bundle)
        pal_b = _PALETTES["B"]
        self.drop_vehicle_to_server = _DropZone(pal_b, arrow_dir="rtl")
        self.drop_vehicle_to_server.setMinimumHeight(50)
        self.drop_vehicle_to_server.setMaximumHeight(16777215)
        self.drop_vehicle_to_server.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        self.drop_vehicle_to_server.setStyleSheet(
            "_DropZone { background:transparent; border:none; border-radius:0px; }"
        )
        dc_lay.addWidget(self.drop_vehicle_to_server, 1)

        cl.addWidget(drop_container, 1)

        main_layout.addWidget(content)

        # BROKER LOG section
        log_section = QtWidgets.QWidget()
        log_section.setStyleSheet(f"QWidget{{ background-color:{pal['content_bg']}; border:none; }}")
        ll = QtWidgets.QVBoxLayout(log_section); ll.setContentsMargins(12, 8, 12, 12); ll.setSpacing(6)
        lt = QtWidgets.QLabel("BROKER LOG")
        lt.setStyleSheet(f"color:{pal['section_title']}; font-size:10px; font-weight:bold; background:transparent; letter-spacing:1px; border:none;")
        ll.addWidget(lt)
        self._log_text = QtWidgets.QTextEdit(); self._log_text.setReadOnly(True)
        self._log_text.setLineWrapMode(QtWidgets.QTextEdit.WidgetWidth)
        self._log_text.setStyleSheet(f"QTextEdit{{ background-color:{pal['read_bg']}; border:1px solid {pal['read_border']}; border-radius:6px; padding:6px; color:{pal['read_active_text']}; font-size:10px; font-family:'Consolas','Monaco',monospace; }}")
        ll.addWidget(self._log_text)
        log_section.setSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Expanding)
        self._log_section = log_section

        self.setStyleSheet(f"background-color:{pal['widget_bg']};")

    def log_relay(self, text, color=None):
        c = color or "#f9a825"
        self._log_text.append(f'<span style="color:{c};font-size:10px">► {text}</span>')
        self._log_text.ensureCursorVisible()

    def clear_log(self):
        self._log_text.clear()


# ═══════════════════════════════════════════════════════════════════
# _CableConnector — animated arrows between panels
# ═══════════════════════════════════════════════════════════════════

class _CableConnector(QtWidgets.QWidget):
    """Draws animated directional arrows between Server ↔ Broker ↔ Vehicle."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAttribute(QtCore.Qt.WA_TransparentForMouseEvents)
        self.setAttribute(QtCore.Qt.WA_TranslucentBackground)
        self._direction = ""   # "to_vehicle", "to_server", or ""
        self._color = "#f9a825"
        self._progress = 0.0   # 0..1 animated dot position
        self._anim = QtCore.QPropertyAnimation(self, b"progress", self)
        self._anim.setDuration(1200)
        self._anim.setStartValue(0.0)
        self._anim.setEndValue(1.0)
        self._anim.setLoopCount(-1)  # loop forever until stopped
        self._anim.setEasingCurve(QtCore.QEasingCurve.Linear)

    @QtCore.Property(float)
    def progress(self):
        return self._progress

    @progress.setter
    def progress(self, val):
        self._progress = val
        self.update()

    def show_arrow(self, direction: str, color: str = "#f9a825"):
        """Start showing an animated arrow. direction: 'to_vehicle' or 'to_server'."""
        self._direction = direction
        self._color = color
        self._anim.start()
        self.update()

    def hide_arrow(self):
        """Stop the arrow animation."""
        self._direction = ""
        self._anim.stop()
        self._progress = 0.0
        self.update()

    def resizeEvent(self, event):
        if self.parent():
            self.setGeometry(self.parent().rect())
        super().resizeEvent(event)

    def paintEvent(self, event):
        if not self._direction:
            return
        p = QtGui.QPainter(self)
        p.setRenderHint(QtGui.QPainter.Antialiasing, True)

        w = self.width()
        h = self.height()
        # Arrow runs at 40% from top (roughly through the middle of the panels)
        y_mid = int(h * 0.40)

        # Panel boundaries: Server is left 5/12, Broker middle 2/12, Vehicle right 5/12
        server_right = int(w * 5 / 12)
        vehicle_left = int(w * 7 / 12)
        broker_mid = w // 2

        if self._direction == "to_vehicle":
            x1, x2 = server_right - 30, vehicle_left + 30
        else:  # to_server
            x1, x2 = vehicle_left + 30, server_right - 30

        color = QtGui.QColor(self._color)

        # Draw line
        pen = QtGui.QPen(color, 3, QtCore.Qt.DashLine)
        pen.setDashPattern([6, 4])
        p.setPen(pen)
        p.drawLine(x1, y_mid, x2, y_mid)

        # Draw arrowhead at destination
        arrow_size = 14
        dest_x = x2
        if self._direction == "to_vehicle":
            # Arrow pointing right
            pts = [QtCore.QPointF(dest_x, y_mid),
                   QtCore.QPointF(dest_x - arrow_size, y_mid - arrow_size // 2),
                   QtCore.QPointF(dest_x - arrow_size, y_mid + arrow_size // 2)]
        else:
            # Arrow pointing left
            pts = [QtCore.QPointF(dest_x, y_mid),
                   QtCore.QPointF(dest_x + arrow_size, y_mid - arrow_size // 2),
                   QtCore.QPointF(dest_x + arrow_size, y_mid + arrow_size // 2)]
        p.setPen(QtCore.Qt.NoPen)
        p.setBrush(color)
        p.drawPolygon(pts)

        # Draw animated dot sliding along the line
        t = self._progress
        dot_x = x1 + (x2 - x1) * t
        dot_color = QtGui.QColor(color)
        dot_color.setAlpha(220)
        # Glow
        for radius, alpha in [(12, 40), (8, 80)]:
            gc = QtGui.QColor(color)
            gc.setAlpha(alpha)
            p.setBrush(gc)
            p.setPen(QtCore.Qt.NoPen)
            p.drawEllipse(QtCore.QPointF(dot_x, y_mid), radius, radius)
        # Core dot
        p.setBrush(dot_color)
        p.drawEllipse(QtCore.QPointF(dot_x, y_mid), 5, 5)

        # Label above the line
        p.setPen(color)
        f = QtGui.QFont("Consolas", 9)
        f.setBold(True)
        p.setFont(f)
        label = "Server \u2192 Vehicle" if self._direction == "to_vehicle" else "Vehicle \u2192 Server"
        p.drawText(QtCore.QRect(min(x1, x2), y_mid - 28, abs(x2 - x1), 20),
                   QtCore.Qt.AlignCenter, label)

        p.end()


# ═══════════════════════════════════════════════════════════════════
# _InstantToolTipStyle — kept from original
# ═══════════════════════════════════════════════════════════════════

class _InstantToolTipStyle(QtWidgets.QProxyStyle):
    def styleHint(self, hint, option=None, widget=None, returnData=None):
        if hint == QtWidgets.QStyle.SH_ToolTip_WakeUpDelay: return 0
        return super().styleHint(hint, option, widget, returnData)


# ═══════════════════════════════════════════════════════════════════
# _SlideToggle — kept from original (animated mode switch)
# ═══════════════════════════════════════════════════════════════════

class _SlideToggle(QtWidgets.QAbstractButton):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setCheckable(True); self.setCursor(QtCore.Qt.PointingHandCursor); self.setFixedSize(60, 28)
        self.__thumb_pos = 0.0
        self._anim = QtCore.QPropertyAnimation(self, b"thumb_pos", self)
        self._anim.setDuration(200); self._anim.setEasingCurve(QtCore.QEasingCurve.InOutQuad)
        self.toggled.connect(self._start_anim)
    def _start_anim(self, checked):
        self._anim.setStartValue(self.thumb_pos); self._anim.setEndValue(1.0 if checked else 0.0); self._anim.start()
    @QtCore.Property(float)
    def thumb_pos(self): return getattr(self, '_SlideToggle__thumb_pos', 0.0)
    @thumb_pos.setter
    def thumb_pos(self, val): self.__thumb_pos = val; self.update()
    def paintEvent(self, _event):
        p = QtGui.QPainter(self); p.setRenderHint(QtGui.QPainter.Antialiasing)
        r = self.rect()
        track_color = QtGui.QColor("#eb0a1e") if self.isChecked() else QtGui.QColor("#3a3a3a")
        p.setBrush(track_color); p.setPen(QtCore.Qt.NoPen)
        p.drawRoundedRect(r, r.height()/2, r.height()/2)
        margin = 3; thumb_d = r.height() - 2*margin; travel = r.width() - thumb_d - 2*margin
        tx = margin + self.__thumb_pos * travel
        p.setBrush(QtGui.QColor("#ffffff"))
        p.drawEllipse(QtCore.QRectF(tx, margin, thumb_d, thumb_d)); p.end()
    def sizeHint(self): return QtCore.QSize(60, 28)


# ═══════════════════════════════════════════════════════════════════
# _MessageDialog — modal popup for plaintext input before encryption
# ═══════════════════════════════════════════════════════════════════

class _MessageDialog(QtWidgets.QDialog):
    """Styled frameless modal that asks the user for a plaintext message."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Enter Message")
        self.setWindowFlags(QtCore.Qt.Dialog | QtCore.Qt.FramelessWindowHint)
        self.setAttribute(QtCore.Qt.WA_TranslucentBackground)
        self.setFixedSize(560, 320)
        self.setModal(True)

        # Outer frame for rounded border + background
        self._frame = QtWidgets.QFrame(self)
        self._frame.setObjectName("dlgFrame")
        self._frame.setGeometry(10, 10, 540, 300)
        self._frame.setStyleSheet(
            "#dlgFrame { background-color:#111111; border:2px solid #58595b; border-radius:14px; }"
        )
        shadow = QtWidgets.QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(30); shadow.setOffset(0, 6)
        shadow.setColor(QtGui.QColor(0, 0, 0, 200))
        self._frame.setGraphicsEffect(shadow)

        lay = QtWidgets.QVBoxLayout(self._frame)
        lay.setContentsMargins(32, 28, 32, 24); lay.setSpacing(12)

        title = QtWidgets.QLabel("Enter a message to encrypt")
        title.setStyleSheet("color:#ffffff; font-size:15px; font-weight:bold; background:transparent; border:none;")
        lay.addWidget(title)

        sub = QtWidgets.QLabel(
            "The vehicle will encrypt this plaintext using the hybrid\n"
            "PQC key (ECDH + Kyber-768) and transmit it to the server."
        )
        sub.setWordWrap(True)
        sub.setStyleSheet("color:#888888; font-size:11px; background:transparent; border:none; line-height:1.4;")
        lay.addWidget(sub)

        lay.addSpacing(4)

        # Preset message buttons
        presets = [
            "Hello from Vehicle!",
            "Engine start authorized",
            "OTA update v2.4.1",
            "Unlock doors",
        ]
        preset_row = QtWidgets.QHBoxLayout(); preset_row.setSpacing(6)
        for txt in presets:
            btn = QtWidgets.QPushButton(txt)
            btn.setCursor(QtCore.Qt.PointingHandCursor)
            btn.setFixedHeight(28)
            btn.setStyleSheet(
                "QPushButton { background:#1a1a1a; border:1px solid #3a3a3a; border-radius:5px;"
                "  color:#90a4ae; font-size:10px; padding:0 10px; font-family:'Consolas',monospace; }"
                "QPushButton:hover { background:#252525; color:#ffffff; border-color:#58595b; }"
            )
            btn.clicked.connect(lambda checked, t=txt: self._use_preset(t))
            preset_row.addWidget(btn)
        preset_row.addStretch()
        lay.addLayout(preset_row)

        lay.addSpacing(4)

        self._input = QtWidgets.QLineEdit()
        self._input.setPlaceholderText("Type your secret message here\u2026")
        self._input.setFixedHeight(40)
        self._input.setStyleSheet(
            "QLineEdit { background:#1a1a1a; border:1px solid #3a3a3a; border-radius:8px;"
            "  color:#ffffff; font-size:14px; padding:4px 14px; font-family:'Consolas',monospace; }"
            "QLineEdit:focus { border-color:#58595b; background:#1e1e1e; }"
        )
        self._input.returnPressed.connect(self.accept)
        lay.addWidget(self._input)

        lay.addSpacing(6)

        btn_row = QtWidgets.QHBoxLayout(); btn_row.addStretch()
        cancel = QtWidgets.QPushButton("Cancel")
        cancel.setFixedHeight(36); cancel.setCursor(QtCore.Qt.PointingHandCursor)
        cancel.setStyleSheet(
            "QPushButton { background:#1a1a1a; border:1px solid #3a3a3a; border-radius:6px;"
            "  color:#aaaaaa; font-size:12px; padding:0 22px; }"
            "QPushButton:hover { background:#252525; color:#e0e0e0; }"
        )
        cancel.clicked.connect(self.reject)

        ok = QtWidgets.QPushButton("Confirm")
        ok.setFixedHeight(36); ok.setCursor(QtCore.Qt.PointingHandCursor)
        ok.setStyleSheet(
            "QPushButton { background:qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            "  stop:0 #c40918, stop:1 #eb0a1e); border:none; border-radius:6px;"
            "  color:white; font-size:12px; font-weight:bold; padding:0 26px; }"
            "QPushButton:hover { background:qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            "  stop:0 #d60b1f, stop:1 #ff0d24); }"
        )
        ok.clicked.connect(self.accept)

        btn_row.addWidget(cancel); btn_row.addSpacing(10); btn_row.addWidget(ok)
        lay.addLayout(btn_row)

    def get_message(self) -> str:
        return self._input.text().strip()

    def _use_preset(self, text: str):
        self._input.setText(text)
        self._input.setFocus()


# ═══════════════════════════════════════════════════════════════════
# _LogPanel — kept from original (right-side overlay)
# ═══════════════════════════════════════════════════════════════════

class _LogPanel(QtWidgets.QFrame):
    closed = QtCore.Signal()
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet("QFrame { background-color: #0a0a0a; border: none; }")
        effect = QtWidgets.QGraphicsDropShadowEffect(self)
        effect.setBlurRadius(20); effect.setOffset(-4, 0); effect.setColor(QtGui.QColor(0, 0, 0, 160))
        self.setGraphicsEffect(effect)
        layout = QtWidgets.QVBoxLayout(self); layout.setContentsMargins(12, 12, 12, 12); layout.setSpacing(8)
        header_row = QtWidgets.QHBoxLayout()
        title = QtWidgets.QLabel("PROTOCOL LOG")
        title.setStyleSheet("color: #eb0a1e; font-size: 11px; font-weight: bold; letter-spacing: 1px;")
        close_btn = QtWidgets.QPushButton("✕")
        close_btn.setFixedSize(24, 24); close_btn.setCursor(QtCore.Qt.PointingHandCursor)
        close_btn.setStyleSheet("QPushButton { background:transparent; color:#888; border:none; font-size:14px; } QPushButton:hover { color:#fff; }")
        close_btn.clicked.connect(self.closed)
        header_row.addWidget(title); header_row.addStretch(); header_row.addWidget(close_btn)
        layout.addLayout(header_row)
        self._table = QtWidgets.QTableWidget(0, 3)
        self._table.setHorizontalHeaderLabels(["Time", "Side", "Step"])
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.setStyleSheet("""
            QTableWidget { background-color:#080808; color:#e0e0e0; border:none; font-size:11px; font-family:'Consolas','Monaco',monospace; gridline-color:#2a2a2a; }
            QTableWidget::item { padding: 4px 8px; }
            QHeaderView::section { background-color:#1a1a1a; color:#888888; border:none; border-bottom:1px solid #3a3a3a; padding:4px 8px; font-size:10px; font-weight:bold; }
        """)
        self._table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self._table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self._table.verticalHeader().setVisible(False)
        self._table.setColumnWidth(0, 76); self._table.setColumnWidth(1, 70)
        layout.addWidget(self._table)

    def add_entry(self, side: str, step: str, detail: str):
        row = self._table.rowCount(); self._table.insertRow(row)
        ts = datetime.now().strftime("%H:%M:%S")
        is_vehicle = (side == "Vehicle")
        row_color = QtGui.QColor("#2a1518") if is_vehicle else QtGui.QColor("#0f1f35")
        text_color = QtGui.QColor("#eb0a1e") if is_vehicle else QtGui.QColor("#4db8ff")
        for col, text in enumerate([ts, side, step]):
            item = QtWidgets.QTableWidgetItem(text)
            item.setForeground(text_color); item.setBackground(row_color)
            self._table.setItem(row, col, item)
        self._table.scrollToBottom()
        if self._table.rowCount() > 200: self._table.removeRow(0)


# ══════════════════════════════════════════════════════════════════
# BoardPanel — same skeleton, PQC content inside
# ══════════════════════════════════════════════════════════════════

class BoardPanel(QtWidgets.QWidget):
    token_sent = QtCore.Signal(str)
    logEntry = QtCore.Signal(str, str, str)  # side, step, detail

    def __init__(self, board: str, parent=None):
        super().__init__(parent)
        self.board = board
        is_vehicle = (board == "A")
        self.side_name = "Vehicle" if is_vehicle else "Server"
        pal = _PALETTES[board]; self._palette = pal

        main_layout = QtWidgets.QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0); main_layout.setSpacing(0)

        # ── Header (same as original + asset icon) ─────────────
        header = QtWidgets.QWidget(); header.setFixedHeight(70)
        header.setStyleSheet(f"QWidget {{ background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 {pal['header_start']}, stop:0.5 {pal['header_mid']}, stop:1 {pal['header_end']}); }}")
        hl = QtWidgets.QHBoxLayout(header); hl.setContentsMargins(20, 10, 20, 10)
        _assets_dir = QtCore.QFileInfo(__file__).absolutePath() + "/assets"
        icon_file = "3d-car.png" if is_vehicle else "cloud-server.png"
        icon_path = QtCore.QDir(_assets_dir).filePath(icon_file)
        icon_pix = QtGui.QPixmap(icon_path)
        if not icon_pix.isNull():
            icon_pix = icon_pix.scaled(50, 50, QtCore.Qt.KeepAspectRatio, QtCore.Qt.SmoothTransformation)
        icon_lbl = QtWidgets.QLabel()
        icon_lbl.setPixmap(icon_pix); icon_lbl.setStyleSheet("background:transparent;")
        hl.addWidget(icon_lbl); hl.addSpacing(12)
        text_col = QtWidgets.QVBoxLayout()
        title = QtWidgets.QLabel(self.side_name.upper())
        tf = title.font(); tf.setPointSize(20); tf.setBold(True); tf.setLetterSpacing(QtGui.QFont.AbsoluteSpacing, 2)
        title.setFont(tf); title.setStyleSheet(f"color:{pal['title_color']}; background:transparent;")
        sub = QtWidgets.QLabel("Client / S4SK • Sender" if is_vehicle else "Server / Host • Receiver")
        sub.setStyleSheet(f"color:{pal['subtitle_color']}; font-size:10px; background:transparent; letter-spacing:1px;")
        text_col.addWidget(title); text_col.addWidget(sub)
        hl.addLayout(text_col); hl.addStretch()
        main_layout.addWidget(header)

        # ── Content ───────────────────────────────────────────
        content = QtWidgets.QWidget(); content.setStyleSheet(f"background-color:{pal['content_bg']};")
        cl = QtWidgets.QVBoxLayout(content); cl.setContentsMargins(20, 15, 20, 15); cl.setSpacing(12)

        # Status bar (flat, no container)
        status_bar = QtWidgets.QWidget()
        status_bar.setStyleSheet("QWidget{ background:transparent; border:none; }")
        sl = QtWidgets.QHBoxLayout(status_bar); sl.setContentsMargins(4, 4, 4, 4)
        self._status_label = QtWidgets.QLabel("● IDLE")
        self._status_label.setStyleSheet(f"color:{pal['read_muted_text']}; font-weight:bold; font-size:11px; background:transparent; border:none;")
        self._total_time_label = QtWidgets.QLabel("")
        self._total_time_label.setStyleSheet(f"color:{pal['counter_color']}; font-size:11px; font-family:'Consolas','Monaco',monospace; background:transparent; border:none;")
        self._phase_label = QtWidgets.QLabel("")
        self._phase_label.setStyleSheet(f"color:{pal['counter_color']}; font-size:11px; background:transparent; border:none;")
        sl.addWidget(self._status_label); sl.addStretch(); sl.addWidget(self._total_time_label); sl.addSpacing(10); sl.addWidget(self._phase_label)
        cl.addWidget(status_bar)

        # Step indicator bar
        self._step_bar = QtWidgets.QWidget()
        self._step_bar.setFixedHeight(28)
        self._step_bar.setStyleSheet(f"QWidget{{ background-color:{pal['section_bg']}; border-radius:6px; }}")
        sbl = QtWidgets.QHBoxLayout(self._step_bar)
        sbl.setContentsMargins(12, 2, 12, 2); sbl.setSpacing(0)
        self._step_indicator = QtWidgets.QLabel("")
        self._step_indicator.setStyleSheet(f"color:{pal['counter_color']}; font-size:11px; font-weight:bold; background:transparent; font-family:'Consolas',monospace;")
        self._step_indicator.setAlignment(QtCore.Qt.AlignCenter)
        sbl.addWidget(self._step_indicator)
        self._step_bar.hide()
        cl.addWidget(self._step_bar)

        # KEY MATERIAL section
        key_section = QtWidgets.QWidget()
        key_section.setStyleSheet(f"QWidget{{ background-color:{pal['section_bg']}; border:none; }}")
        kl = QtWidgets.QVBoxLayout(key_section); kl.setContentsMargins(20, 12, 20, 20)
        kt = QtWidgets.QLabel("KEY MATERIAL")
        kt.setStyleSheet(f"color:{pal['section_title']}; font-size:10px; font-weight:bold; background:transparent; letter-spacing:1px; border:none;")
        kl.addWidget(kt)
        self._key_display = _KeyDisplay(self)
        self._key_display.setMinimumHeight(80)
        self._key_display.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        kl.addWidget(self._key_display)
        key_section.setSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Expanding)

        # BUNDLE COLLECTOR (square, centred)
        self._bundle_collector = _BundleCollector(pal)
        self._bundle_collector.hide()
        bc_row = QtWidgets.QHBoxLayout()
        bc_row.setContentsMargins(0, 4, 0, 4)
        bc_row.addStretch()
        bc_row.addWidget(self._bundle_collector)
        bc_row.addStretch()

        if is_vehicle:
            self._message_input = None
            cl.addWidget(key_section)
            cl.addLayout(bc_row)
        else:
            self._message_input = None
            cl.addLayout(bc_row)
            cl.addWidget(key_section)

        # OPERATION LOG section
        log_section = QtWidgets.QWidget()
        log_section.setStyleSheet(f"QWidget{{ background-color:{pal['content_bg']}; border:none; }}")
        ll = QtWidgets.QVBoxLayout(log_section); ll.setContentsMargins(12, 8, 12, 12); ll.setSpacing(6)
        lt = QtWidgets.QLabel("OPERATION LOG")
        lt.setStyleSheet(f"color:{pal['section_title']}; font-size:10px; font-weight:bold; background:transparent; letter-spacing:1px; border:none;")
        ll.addWidget(lt)
        self._log = QtWidgets.QTextEdit(); self._log.setReadOnly(True)
        self._log.setLineWrapMode(QtWidgets.QTextEdit.WidgetWidth)
        self._log.setStyleSheet(f"QTextEdit{{ background-color:{pal['read_bg']}; border:2px solid {pal['read_border']}; border-radius:8px; padding:10px; color:{pal['read_active_text']}; font-size:13px; font-family:'Consolas','Monaco',monospace; }}")
        ll.addWidget(self._log)
        if not is_vehicle:
            # Decrypted message display
            self._dec_display = QtWidgets.QTextEdit(); self._dec_display.setReadOnly(True)
            self._dec_display.setPlaceholderText("Decrypted message will appear here…")
            self._dec_display.setFixedHeight(55)
            self._dec_display.setStyleSheet(f"QTextEdit{{ background-color:{pal['read_bg']}; border:2px solid {pal['read_border']}; border-radius:8px; padding:10px; color:#4caf50; font-size:13px; font-family:'Consolas','Monaco',monospace; }}")
            ll.addWidget(self._dec_display)
        log_section.setSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Expanding)
        self._log_section = log_section
        cl.addWidget(log_section)
        self._bottom_section = log_section

        main_layout.addWidget(content)
        self.setMinimumWidth(450); self.setStyleSheet(f"background-color:{pal['widget_bg']};")

    # ── helpers ───────────────────────────────────────────────

    def set_status(self, text, color=None):
        c = color or self._palette['read_muted_text']
        self._status_label.setText(f"● {text}")
        self._status_label.setStyleSheet(f"color:{c}; font-weight:bold; font-size:11px; background:transparent;")

    def set_phase(self, text):
        self._phase_label.setText(text)

    def set_total_time_ms(self, time_ms: float | None):
        if time_ms in (None, ""):
            self._total_time_label.setText("")
            return
        self._total_time_label.setText(f"TOTAL: {_format_duration_us(time_ms)}")

    def set_step(self, step_num: int, total: int, label: str, color: str):
        """Show step indicator like 'Step 2/5: KDF Step-1 — ECDH Shared Secret'."""
        self._step_indicator.setText(f"Step {step_num}/{total}:  {label}")
        self._step_indicator.setStyleSheet(f"color:{color}; font-size:11px; font-weight:bold; background:transparent; font-family:'Consolas',monospace;")
        self._step_bar.show()

    def clear_step(self):
        self._step_indicator.setText("")
        self._step_bar.hide()

    def set_keys(self, entries: list[KeyEntry]):
        self._key_display.set_entries(entries)

    def set_draggable(self, token_type: str):
        self._key_display.set_draggable(token_type)

    def set_packet(self, title: str, token_type: str, items: list):
        # No longer used — bundle collector handles this
        pass

    def clear_packet(self):
        self._bundle_collector.clear()

    def show_decrypted(self, text):
        if hasattr(self, '_dec_display'):
            self._dec_display.setPlainText(text)
            self._dec_display.setStyleSheet(f"QTextEdit{{ background-color:{self._palette['read_bg']}; border:2px solid #4caf50; border-radius:8px; padding:10px; color:#4caf50; font-size:13px; font-family:'Consolas','Monaco',monospace; }}")

    def log_step(self, text, color):
        self._log.append(f'<span style="color:{color};font-weight:bold">► {text}</span>')
        self._log.ensureCursorVisible()
        self.logEntry.emit(self.side_name, text, "")

    def log_val(self, label, value, color=None):
        c = color or "#78909c"
        self._log.append(f'  <span style="color:#546e7a">{label}:</span> <span style="color:{c};font-family:monospace">{_short(value,48)}</span>')
        self._log.ensureCursorVisible()

    def log_msg(self, text, color="#90a4ae"):
        self._log.append(f'<span style="color:{color}">{text}</span>')
        self._log.ensureCursorVisible()

    def clear_log(self):
        self._log.clear()
        self.clear_step()
        self._bundle_collector.clear()
        if hasattr(self, '_dec_display'):
            self._dec_display.clear()
            self._dec_display.setStyleSheet(f"QTextEdit{{ background-color:{self._palette['read_bg']}; border:2px solid {self._palette['read_border']}; border-radius:8px; padding:10px; color:#4caf50; font-size:13px; font-family:'Consolas','Monaco',monospace; }}")

    def _switch_to_autonomous(self):
        pass

    def _switch_to_interactive(self):
        pass


# ══════════════════════════════════════════════════════════════════
# MainWindow — same skeleton as original
# ══════════════════════════════════════════════════════════════════

class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PQC Hybrid Key Exchange Demo v1.0")
        self.resize(1600, 900)
        self.setStyleSheet("background-color: #000000;")
        self.proto = Proto()

        root = QtWidgets.QWidget(); self.setCentralWidget(root)
        main_layout = QtWidgets.QVBoxLayout(root); main_layout.setContentsMargins(0,0,0,0); main_layout.setSpacing(0)

        # ── Banner (same as original) ─────────────────────────
        banner = QtWidgets.QWidget(); banner.setFixedHeight(60)
        banner.setStyleSheet("QWidget { background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #000000, stop:0.35 #1a1a1a, stop:0.5 #58595b, stop:0.65 #1a1a1a, stop:1 #000000); border-bottom: 2px solid #58595b; }")
        bl = QtWidgets.QHBoxLayout(banner); bl.setContentsMargins(30, 0, 30, 0)
        _assets_dir = QtCore.QFileInfo(__file__).absolutePath() + "/assets"
        logo_path = QtCore.QDir(_assets_dir).filePath("toyota-tile.svg")
        logo = QtSvgWidgets.QSvgWidget(logo_path); logo.setFixedSize(35, 35)
        logo.setStyleSheet("background:transparent; border:none;")
        bl.addWidget(logo); bl.addSpacing(15)
        title = QtWidgets.QLabel("PQC HYBRID KEY EXCHANGE DEMO")
        tf = title.font(); tf.setPointSize(16); tf.setBold(True); tf.setLetterSpacing(QtGui.QFont.AbsoluteSpacing, 2)
        title.setFont(tf); title.setStyleSheet("color:#ffffff; background:transparent;")
        self._version_label = QtWidgets.QLabel("v1.0 • Live Mode")
        self._version_label.setStyleSheet("color:#4caf50; background:transparent; font-size:11px;")
        version = self._version_label

        self._selected_kex_mode = None
        self._active_kex_mode = None
        self._kex_combo = QtWidgets.QComboBox()
        self._kex_combo.addItem("Select KEX mode...", None)
        self._kex_combo.addItem("ECDH-only", MODE_ECDH)
        self._kex_combo.addItem("PQC-only", MODE_PQC)
        self._kex_combo.addItem("Hybrid", MODE_HYBRID)
        self._kex_combo.setCurrentIndex(0)
        self._kex_combo.setFixedHeight(30)
        self._kex_combo.setStyleSheet(
            "QComboBox { background:#1a1a1a; border:1px solid #58595b; border-radius:6px; color:#e0e0e0; font-size:10px; font-weight:bold; padding:0 8px; min-width:120px; }"
            " QComboBox::drop-down { border:none; width:18px; }"
            " QComboBox QAbstractItemView { background:#111; color:#ddd; selection-background-color:#2a2a2a; border:1px solid #333; }")
        self._kex_combo.currentIndexChanged.connect(self._on_kex_mode_changed)

        # Mode toggle
        mc = QtWidgets.QWidget(); mc.setStyleSheet("background:transparent;")
        ml = QtWidgets.QHBoxLayout(mc); ml.setContentsMargins(0,0,0,0); ml.setSpacing(8)
        self._lbl_interactive = QtWidgets.QLabel("INTERACTIVE")
        self._lbl_interactive.setStyleSheet("color:#e0e0e0; font-size:10px; font-weight:bold; background:transparent;")
        self._mode_toggle = _SlideToggle()
        self._mode_toggle.toggled.connect(self._on_mode_toggle)
        self._lbl_autonomous = QtWidgets.QLabel("AUTONOMOUS")
        self._lbl_autonomous.setStyleSheet("color:#888888; font-size:10px; font-weight:bold; background:transparent;")
        ml.addWidget(self._lbl_interactive); ml.addWidget(self._mode_toggle); ml.addWidget(self._lbl_autonomous)

        _btn_ss = "QPushButton { background-color:#1a1a1a; border:1px solid #58595b; border-radius:6px; color:#e0e0e0; font-size:10px; font-weight:bold; letter-spacing:1px; padding:0 15px; } QPushButton:hover { background-color:#252525; color:#ffffff; } QPushButton:pressed { background-color:#121212; }"
        self._reset_btn = QtWidgets.QPushButton("RESET"); self._reset_btn.setFixedHeight(35)
        self._reset_btn.setCursor(QtCore.Qt.PointingHandCursor); self._reset_btn.setStyleSheet(_btn_ss)
        self._reset_btn.clicked.connect(self._on_reset)
        self._clear_logs_btn = QtWidgets.QPushButton("CLEAR LOGS"); self._clear_logs_btn.setFixedHeight(35)
        self._clear_logs_btn.setCursor(QtCore.Qt.PointingHandCursor); self._clear_logs_btn.setStyleSheet(_btn_ss)
        self._clear_logs_btn.clicked.connect(self._on_clear_logs)

        # Auto-run controls (in banner, shared between panels)
        self._auto_start_btn = QtWidgets.QPushButton("▶  RUN EXCHANGE")
        self._auto_start_btn.setFixedHeight(35)
        self._auto_start_btn.setCursor(QtCore.Qt.PointingHandCursor)
        self._auto_start_btn.setStyleSheet(
            "QPushButton { background:qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #c40918, stop:1 #eb0a1e); border:none; border-radius:6px; color:white; font-size:10px; font-weight:bold; letter-spacing:1px; padding:0 15px; }"
            " QPushButton:hover { background:qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #d60b1f, stop:1 #ff0d24); }"
            " QPushButton:disabled { background:#2a2a2a; color:#666; }")
        self._auto_start_btn.clicked.connect(self._on_auto_start)
        self._auto_start_btn.setVisible(False)

        self._delay_spin = QtWidgets.QDoubleSpinBox()
        self._delay_spin.setRange(0.1, 10.0); self._delay_spin.setValue(0.8)
        self._delay_spin.setSingleStep(0.1); self._delay_spin.setDecimals(1); self._delay_spin.setSuffix(" s")
        self._delay_spin.setFixedHeight(35); self._delay_spin.setFixedWidth(80)
        self._delay_spin.setStyleSheet("QDoubleSpinBox{ background-color:#1a1a1a; border:1px solid #58595b; border-radius:6px; padding:0 6px; color:#e0e0e0; font-size:11px; }")
        self._delay_spin.setToolTip("Delay between each protocol step reveal")

        self._delay_label = QtWidgets.QLabel("Step delay:")
        self._delay_label.setStyleSheet("color:#888; font-size:10px; font-weight:bold; background:transparent;")

        self._hamburger_btn = QtWidgets.QPushButton("☰"); self._hamburger_btn.setFixedSize(35, 35)
        self._hamburger_btn.setCursor(QtCore.Qt.PointingHandCursor); self._hamburger_btn.setCheckable(True)
        self._hamburger_btn.setStyleSheet("QPushButton { background-color:#1a1a1a; border:1px solid #58595b; border-radius:6px; color:#e0e0e0; font-size:18px; } QPushButton:hover { background-color:#252525; color:#ffffff; } QPushButton:checked { background-color:#2a1518; border:1px solid #eb0a1e; color:#eb0a1e; }")
        self._hamburger_btn.clicked.connect(self._on_hamburger_clicked)

        # Color legend
        legend = QtWidgets.QWidget(); legend.setStyleSheet("background:transparent;")
        legl = QtWidgets.QHBoxLayout(legend); legl.setContentsMargins(0,0,0,0); legl.setSpacing(8)
        for txt, clr in [("ECDH", CLR_ECDH), ("Kyber", CLR_KYBER), ("Hybrid", CLR_HYBRID)]:
            d = QtWidgets.QLabel(f"● {txt}"); d.setStyleSheet(f"color:{clr}; font-size:9px; font-weight:bold; background:transparent;")
            legl.addWidget(d)

        kex_lbl = QtWidgets.QLabel("KEX:")
        kex_lbl.setStyleSheet("color:#888; font-size:10px; font-weight:bold; background:transparent;")

        bl.addWidget(title); bl.addStretch(); bl.addWidget(version); bl.addSpacing(10)
        bl.addWidget(kex_lbl); bl.addSpacing(4)
        bl.addWidget(self._kex_combo); bl.addSpacing(10)
        bl.addWidget(legend); bl.addSpacing(10)
        bl.addWidget(self._clear_logs_btn); bl.addSpacing(8); bl.addWidget(self._reset_btn); bl.addSpacing(8)
        bl.addWidget(self._delay_label); bl.addSpacing(4); bl.addWidget(self._delay_spin); bl.addSpacing(4)
        bl.addWidget(self._auto_start_btn); bl.addSpacing(8)
        bl.addWidget(mc); bl.addSpacing(12); bl.addWidget(self._hamburger_btn)
        main_layout.addWidget(banner)

        # ── Panels (Server | Broker | Vehicle) ────────────────
        self.panelA = BoardPanel("A"); self.panelB = BoardPanel("B")
        self.broker = BrokerPanel()

        # Connect bundle_ready signals so broker drop zones activate
        self.panelA._bundle_collector.bundle_ready.connect(self._refresh)
        self.panelB._bundle_collector.bundle_ready.connect(self._refresh)

        self._log_panel = _LogPanel(root); self._log_panel.hide()
        self._log_panel.closed.connect(self._on_log_panel_close)
        self.panelA.logEntry.connect(self._log_panel.add_entry)
        self.panelB.logEntry.connect(self._log_panel.add_entry)

        # Server 5/12 | Broker 1/6 (=2/12) | Vehicle 5/12

        # Pull log sections out of panels into a shared bottom row
        log_a = self.panelA._log_section
        log_b = self.panelB._log_section
        log_broker = self.broker._log_section
        log_a.setParent(None)
        log_b.setParent(None)
        log_broker.setParent(None)

        # Top row: Server panel | Broker panel | Vehicle panel
        top_row = QtWidgets.QWidget()
        top_row.setStyleSheet("background-color:#0a0a0a;")
        tl = QtWidgets.QHBoxLayout(top_row); tl.setContentsMargins(0,0,0,0); tl.setSpacing(1)
        tl.addWidget(self.panelB, 5)
        tl.addWidget(self.broker, 2)
        tl.addWidget(self.panelA, 5)

        # Bottom row: collapsible log area
        self._log_content = QtWidgets.QWidget()
        self._log_content.setStyleSheet("background-color:#0a0a0a;")
        bl_row = QtWidgets.QHBoxLayout(self._log_content)
        bl_row.setContentsMargins(0, 0, 0, 0); bl_row.setSpacing(1)
        bl_row.addWidget(log_b, 5)
        bl_row.addWidget(log_broker, 2)
        bl_row.addWidget(log_a, 5)

        self._log_toggle_btn = QtWidgets.QPushButton("\u25b6  LOGS")
        self._log_toggle_btn.setFixedHeight(22)
        self._log_toggle_btn.setCursor(QtCore.Qt.PointingHandCursor)
        self._log_toggle_btn.setStyleSheet(
            "QPushButton{ background:#111; color:#78909c; border:none; "
            "font-size:11px; font-family:Consolas,monospace; letter-spacing:1px; }"
            "QPushButton:hover{ color:#b0bec5; }")
        self._log_toggle_btn.clicked.connect(self._toggle_logs)
        self._logs_visible = False
        self._log_content.hide()

        bottom_row = QtWidgets.QWidget()
        bottom_row.setStyleSheet("background-color:#0a0a0a;")
        bv = QtWidgets.QVBoxLayout(bottom_row)
        bv.setContentsMargins(0, 0, 0, 0); bv.setSpacing(0)
        bv.addWidget(self._log_toggle_btn)
        bv.addWidget(self._log_content)

        # Single vertical splitter keeps all logs aligned
        self._splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)
        self._splitter.setStyleSheet("QSplitter::handle { background:#1a1a1a; height:2px; }")
        self._splitter.addWidget(top_row)
        self._splitter.addWidget(bottom_row)
        self._splitter.setStretchFactor(0, 1)
        self._splitter.setStretchFactor(1, 0)
        self._splitter.setCollapsible(1, False)

        # Outer wrapper
        outer = QtWidgets.QWidget()
        outer_l = QtWidgets.QHBoxLayout(outer); outer_l.setContentsMargins(0,0,0,0); outer_l.setSpacing(0)
        outer_l.addWidget(self._splitter)

        self._cable_overlay = _CableConnector(outer); self._cable_overlay.raise_()
        main_layout.addWidget(outer)

        self._status_label = QtWidgets.QLabel()

        outer.resizeEvent = lambda event: (
            self._cable_overlay.setGeometry(outer.rect()),
            QtWidgets.QWidget.resizeEvent(outer, event)
        )

        self._auto_exchange_count = 0
        self._auto_running = False
        self._exchange_phase = "IDLE"  # IDLE, KEYS_READY, CLIENT_RUNNING, BUNDLE_READY, PROCESSING, COMPLETE
        self._server_bundle_ready = False
        self._process_requested = False
        self._server_processing_started = False
        self._process_retry_timer: QtCore.QTimer | None = None
        self._process_retry_count = 0
        self._next_retry_timer: QtCore.QTimer | None = None
        self._next_retry_count = 0

        # ── Staged reveal: queue JSON events, pop one at a time ──
        self._event_queue: list[tuple[str, dict]] = []   # ("server"|"client", evt)
        self._reveal_timer = QtCore.QTimer(self)
        self._reveal_timer.setSingleShot(True)
        self._reveal_timer.timeout.connect(self._reveal_next_event)
        self._instant_count = 0  # number of queued events to show without delay

        # Wire interactive drag-and-drop (broker drop zones)
        self.broker.drop_server_to_vehicle.dropped.connect(self._on_vehicle_drop)
        self.broker.drop_vehicle_to_server.dropped.connect(self._on_server_drop)
        self.panelA.token_sent.connect(self._on_token_send)
        self.panelB.token_sent.connect(self._on_token_send)

        # ── Live mode — spawn server and connect ──────────────
        self._live_proto: LiveProto | None = None
        self._start_live()

        self._refresh()

    # ── mode toggle ───────────────────────────────────────────

    def _on_mode_toggle(self, checked):
        if checked:
            self._lbl_autonomous.setStyleSheet("color:#eb0a1e; font-size:10px; font-weight:bold; background:transparent;")
            self._lbl_interactive.setStyleSheet("color:#888888; font-size:10px; font-weight:bold; background:transparent;")
            self.panelA._switch_to_autonomous()
            self._auto_start_btn.setVisible(True)
        else:
            self._lbl_interactive.setStyleSheet("color:#e0e0e0; font-size:10px; font-weight:bold; background:transparent;")
            self._lbl_autonomous.setStyleSheet("color:#888888; font-size:10px; font-weight:bold; background:transparent;")
            self.panelA._switch_to_interactive()
            self._auto_start_btn.setVisible(False)

    def _is_interactive(self):
        return not self._mode_toggle.isChecked()

    def _on_kex_mode_changed(self, _index):
        self._selected_kex_mode = self._kex_combo.currentData()
        # When an exchange is not actively running, apply the choice immediately
        # so bundle validation and slot expectations reflect the selected config.
        if self._exchange_phase in ("IDLE", "KEYS_READY", "COMPLETE"):
            self._active_kex_mode = self._selected_kex_mode
            # Force bundle slot schemas to be rebuilt for the new mode.
            self.panelA._bundle_collector.clear()
            self.panelB._bundle_collector.clear()
        if self._selected_kex_mode:
            self.broker.log_relay(f"KEX mode selected: {self._selected_kex_mode.upper()}", "#90a4ae")
        else:
            self.broker.log_relay("Select a KEX mode to enable key-material flow", "#90a4ae")
        self._refresh()

    def _effective_mode(self):
        # During an active run, lock display/validation to the negotiated mode.
        if self._exchange_phase in ("CLIENT_RUNNING", "BUNDLE_READY", "PROCESSING"):
            return self._active_kex_mode or self._selected_kex_mode
        # Otherwise, reflect the latest UI selection.
        return self._selected_kex_mode or self._active_kex_mode

    def _mode_is_selected(self):
        return self._effective_mode() in (MODE_ECDH, MODE_PQC, MODE_HYBRID)

    def _mode_label(self, mode: str | None = None) -> str:
        selected = mode or self._effective_mode()
        return selected.upper() if selected else "UNSELECTED"

    def _uses_ecdh(self):
        return self._effective_mode() in (MODE_ECDH, MODE_HYBRID)

    def _uses_kyber(self):
        return self._effective_mode() in (MODE_PQC, MODE_HYBRID)

    def _client_total_steps(self):
        mode = self._effective_mode()
        if mode == MODE_PQC:
            return 3
        if mode == MODE_ECDH:
            return 4
        if mode == MODE_HYBRID:
            return 5
        return 0

    def _server_total_steps(self):
        mode = self._effective_mode()
        if mode == MODE_HYBRID:
            return 4
        if mode in (MODE_ECDH, MODE_PQC):
            return 3
        return 0

    def _client_step_index(self, event_name: str):
        mode = self._effective_mode()
        if mode == MODE_ECDH:
            mapping = {"ecdh_keygen": 1, "ecdh_derive": 2, "hybrid_key": 3, "encrypt": 4}
        elif mode == MODE_PQC:
            mapping = {"kyber_encap": 1, "hybrid_key": 2, "encrypt": 3}
        else:
            mapping = {"ecdh_keygen": 1, "ecdh_derive": 2, "kyber_encap": 3, "hybrid_key": 4, "encrypt": 5}
        return mapping.get(event_name, 0)

    def _server_step_index(self, event_name: str):
        mode = self._effective_mode()
        if mode == MODE_ECDH:
            mapping = {"ecdh_derive": 1, "hybrid_key": 2, "decrypt": 3}
        elif mode == MODE_PQC:
            mapping = {"kyber_decap": 1, "hybrid_key": 2, "decrypt": 3}
        else:
            mapping = {"ecdh_derive": 1, "kyber_decap": 2, "hybrid_key": 3, "decrypt": 4}
        return mapping.get(event_name, 0)

    # ── live server management ────────────────────────────────

    def _start_live(self):
        _log_app.info("_start_live: creating new LiveProto (old=%s)", self._live_proto is not None)
        if self._live_proto is not None:
            self._live_proto.stop()
        self._live_proto = LiveProto(self)
        self._live_proto.server_event.connect(self._on_server_json)
        self._live_proto.client_event.connect(self._on_client_json)
        self._live_proto.status_msg.connect(self._on_live_status)
        self._live_proto.exchange_done.connect(self._on_live_exchange_done)
        self._live_proto.start_server()
        _log_app.info("_start_live: server start requested")

    # ── live JSON event handlers ──────────────────────────────

    def _on_live_status(self, msg):
        if msg.startswith("[DIAG]"):
            self.broker.log_relay(msg, "#ef5350")
            print(msg, flush=True)  # also to terminal
        self.panelB.set_phase(msg)

    def _recover_control_channel(self, reason: str):
        # Control socket is broken; restart live stack to get a fresh GUI/server channel.
        _log_app.error("RECOVER: %s  phase=%s srv_bundle=%s proc_req=%s srv_started=%s",
                       reason, self._exchange_phase, self._server_bundle_ready,
                       self._process_requested, self._server_processing_started)
        self._flush_event_queue()
        self.broker.log_relay(f"Control channel lost: {reason}", "#ef5350")
        self._stop_process_retry()
        self._stop_next_retry()
        self._auto_running = False
        self._auto_start_btn.setEnabled(True)
        self._auto_start_btn.setText("▶  RUN EXCHANGE")
        self._exchange_phase = "IDLE"
        self._server_bundle_ready = False
        self._process_requested = False
        self._server_processing_started = False
        self.proto.reset()
        self.panelA.clear_log(); self.panelB.clear_log()
        self.panelA.set_status("IDLE"); self.panelB.set_status("RECONNECTING", "#ef5350")
        self.panelA.set_phase(""); self.panelB.set_phase("Restarting server channel...")
        self._refresh()
        self._start_live()

    def _on_server_json(self, evt):
        """Receive server JSON — immediate or queued depending on event type."""
        event = evt.get("event", "")
        # Control/lifecycle events: process immediately (no staged delay)
        if event in ("gui_connected", "listening", "error", "phase"):
            self._handle_server_event(evt)
            return
        # Everything else: queue for staged reveal
        self._event_queue.append(("server", evt))
        self._kick_reveal()

    def _on_client_json(self, evt):
        """Receive client JSON — queue for staged reveal."""
        self._event_queue.append(("client", evt))
        self._kick_reveal()

    # ── staged reveal engine ──────────────────────────────────

    def _kick_reveal(self):
        """Start the reveal timer if it's not already running."""
        if not self._reveal_timer.isActive() and self._event_queue:
            self._reveal_next_event()

    def _reveal_next_event(self):
        """Pop one event from the queue, process it, schedule the next."""
        if not self._event_queue:
            return
        source, evt = self._event_queue.pop(0)
        if source == "server":
            self._handle_server_event(evt)
        else:
            self._handle_client_event(evt)
        # ALWAYS start timer after processing — creates a cooldown window
        # so events arriving in the next delay_ms are queued, not instant.
        if self._instant_count > 0:
            self._instant_count -= 1
            delay_ms = 0
        else:
            delay_ms = int(self._delay_spin.value() * 1000)
        self._reveal_timer.start(delay_ms)

    def _flush_event_queue(self):
        """Process all remaining queued events instantly (used by reset)."""
        self._reveal_timer.stop()
        while self._event_queue:
            source, evt = self._event_queue.pop(0)
            if source == "server":
                self._handle_server_event(evt)
            else:
                self._handle_client_event(evt)

    # ── actual event processing (unchanged logic) ─────────────

    def _handle_server_event(self, evt):
        """Process one server JSON event."""
        event = evt.get("event", "")
        _log_app.info("SRV_EVT: %s  (phase=%s)", event, self._exchange_phase)
        p = self.proto

        if event == "gui_connected":
            self.panelB.set_status("CONNECTED", "#4caf50")
            self.panelB.set_phase("Waiting for client...")

        elif event == "listening":
            self.panelB.log_step(f"Listening on port {evt.get('port', '?')}", CLR_ECDH)

        elif event == "keysizes":
            self.panelB.log_step("Key Sizes", "#90a4ae")
            self.panelB.log_val("kyber_variant", str(evt.get("kyber_variant", "?")), "#90a4ae")
            self.panelB.log_val("kyber_pk", str(evt.get("kyber_pk", "?")), "#90a4ae")
            self.panelB.log_val("ecdh_pk", str(evt.get("ecdh_pk", "?")), "#90a4ae")
            self.panelB.log_val("kyber_sk", str(evt.get("kyber_sk", "?")), "#90a4ae")
            self.panelB.log_val("ecdh_sk", str(evt.get("ecdh_sk", "?")), "#90a4ae")
            self.panelB.log_val("kyber_ss", str(evt.get("kyber_ss", "?")), "#90a4ae")
            self.panelB.log_val("ecdh_ss", str(evt.get("ecdh_ss", "?")), "#90a4ae")
            self.panelB.log_val("kyber_ct", str(evt.get("kyber_ct", "?")), "#90a4ae")
            self.panelB.log_val("hybrid_key", str(evt.get("hybrid_key", "?")), "#90a4ae")
            self.panelB.log_val("nonce", str(evt.get("nonce", "?")), "#90a4ae")

        elif event == "client_connected":
            self.panelB.log_step(f"Client connected from {evt.get('from', '?')}", CLR_ECDH)
            self.panelB.set_status("PROCESSING", CLR_ECDH)

        elif event == "ecdh_keygen":
            # Detect start of new exchange round — clear vehicle side
            if self._exchange_phase in ("IDLE",):
                self.panelA.clear_log()
                self.panelA.set_status("IDLE"); self.panelA.set_phase("")
            self.panelB.set_status("GENERATING KEYS", CLR_ECDH)
            pk = evt.get("pk", "")
            t = evt.get("time_ms", 0)
            p.s_ecdh_pk = pk
            p.s_ecdh_pk_time_ms = t
            self.panelB.log_step(f"ECDH Keygen ({t:.3f} ms)", CLR_ECDH)
            self.panelB.log_val("s_ecdh_pk", pk, CLR_ECDH)
            self._refresh()

        elif event == "kyber_pk_loaded":
            pk = evt.get("pk", "")
            t = evt.get("time_ms", 0)
            p.s_kyber_pk = pk
            p.s_kyber_pk_time_ms = t
            self.panelB.log_step(f"Kyber Keygen ({t:.3f} ms)", CLR_KYBER)
            self.panelB.log_val("s_kyber_pk", pk, CLR_KYBER)
            self._refresh()

        elif event == "keys_sent":
            self.panelB.log_step("Public keys sent to client", CLR_ECDH)
            self.panelB.set_phase("Keys sent")

        elif event == "client_data_received":
            self._active_kex_mode = evt.get("mode", self._active_kex_mode)
            has_ecdh = evt.get("has_ecdh", True)
            has_kyber = evt.get("has_kyber", True)
            c_pk = evt.get("ecdh_pk", "") if has_ecdh else ""
            ct = evt.get("kyber_ct", "") if has_kyber else ""
            p.c_ecdh_pk = c_pk
            p.kyber_ct = ct
            self.panelB.log_step(f"Received client bundle ({self._mode_label(self._active_kex_mode)})", CLR_ECDH)
            if c_pk:
                self.panelB.log_val("c_ecdh_pk", c_pk, CLR_ECDH)
            if ct:
                self.panelB.log_val("kyber_ct", ct, CLR_KYBER)
            self._refresh()

        elif event == "ecdh_derive":
            self._server_processing_started = True
            self._stop_process_retry()
            ss = evt.get("shared", "")
            t = evt.get("time_ms", 0)
            p.ecdh_ss_s = ss
            p.ecdh_ss_s_time_ms = t
            step_idx = self._server_step_index("ecdh_derive")
            step_total = self._server_total_steps()
            self.panelB.set_step(step_idx, step_total, "KDF Step \u2014 ECDH Shared Secret", CLR_ECDH)
            self.panelB.log_step(f"ECDH Shared Secret ({_format_duration_us(t)})", CLR_ECDH)
            self.panelB.log_val("ecdh_shared", ss, CLR_ECDH)
            self._refresh()

        elif event == "kyber_decap":
            self._server_processing_started = True
            ss = evt.get("shared", "")
            t = evt.get("time_ms", 0)
            p.kyber_ss_s = ss
            p.kyber_ss_s_time_ms = t
            step_idx = self._server_step_index("kyber_decap")
            step_total = self._server_total_steps()
            self.panelB.set_step(step_idx, step_total, "KDF Step \u2014 Kyber Decapsulation", CLR_KYBER)
            self.panelB.log_step(f"Kyber Decapsulation ({_format_duration_us(t)})", CLR_KYBER)
            self.panelB.log_val("kyber_ss", ss, CLR_KYBER)
            self._refresh()

        elif event == "hybrid_key":
            self._active_kex_mode = evt.get("mode", self._active_kex_mode)
            key = evt.get("key", "")
            t = evt.get("time_ms", 0)
            p.hybrid_s = key
            p.hybrid_s_time_ms = t
            step_idx = self._server_step_index("hybrid_key")
            step_total = self._server_total_steps()
            self.panelB.set_step(step_idx, step_total, "Session KDF \u2014 SHA-256(selected secret(s))", CLR_HYBRID)
            self.panelB.log_step(f"Session KDF ({self._active_kex_mode.upper()}) ({_format_duration_us(t)})", CLR_HYBRID)
            self.panelB.log_val("hybrid_key", key, CLR_HYBRID)
            self._refresh()

        elif event == "decrypt":
            self._server_processing_started = True
            pt = evt.get("plaintext", "")
            t = evt.get("time_ms", 0)
            p.decrypted = pt
            p.decrypt_time_ms = t
            step_idx = self._server_step_index("decrypt")
            step_total = self._server_total_steps()
            self.panelB.set_step(step_idx, step_total, "Decrypt \u2014 Message Recovered", "#4caf50")
            self.panelB.log_step(f"Decrypt ({_format_duration_us(t)})", "#4caf50")
            self.panelB.log_val("message", pt, "#4caf50")
            self.panelB.show_decrypted(pt)
            self._refresh()

        elif event == "complete":
            self._server_processing_started = True
            self._stop_process_retry()
            self._stop_next_retry()
            self._exchange_phase = "COMPLETE"
            self._auto_exchange_count += 1
            status = evt.get("status", "")
            self.panelB.set_status("COMPLETE" if status == "SUCCESS" else "ERROR",
                                   "#39ff14" if status == "SUCCESS" else "#ef5350")
            self.panelB.set_phase("Decrypted!" if status == "SUCCESS" else "Failed")
            self.broker.log_relay("Exchange " + ("\u2713 SUCCESS" if status == "SUCCESS" else "\u2717 FAILED"),
                                  "#39ff14" if status == "SUCCESS" else "#ef5350")
            # Re-enable the auto start button for next run
            self._auto_running = False
            self._auto_start_btn.setEnabled(True)
            self._auto_start_btn.setText("\u25b6  RUN EXCHANGE")
            self._refresh()

        elif event == "phase":
            phase_name = evt.get("phase", "")
            _log_app.info("PHASE event: %s  (current exchange_phase=%s)", phase_name, self._exchange_phase)
            if phase_name == "keys_ready":
                self._active_kex_mode = self._selected_kex_mode
                self._stop_next_retry()
                self._server_bundle_ready = False
                self._process_requested = False
                self._server_processing_started = False
                self._exchange_phase = "KEYS_READY"
                self.panelB.set_status("KEYS READY", "#4caf50")
                if self._mode_is_selected():
                    self.panelB.set_phase(f"Drag keys to Vehicle \u2192 ({self._mode_label(self._active_kex_mode)})")
                else:
                    self.panelB.set_phase("Select KEX mode to display key material")
                self._refresh()
                if not self._is_interactive() and self._auto_running:
                    delay = int(self._delay_spin.value() * 1000)
                    QtCore.QTimer.singleShot(delay, self._auto_advance_client)
            elif phase_name == "bundle_received":
                self._server_bundle_ready = True
                self.panelB.set_status("BUNDLE RECEIVED", CLR_KYBER)
                if self._process_requested:
                    self._commit_process()
                else:
                    self._exchange_phase = "BUNDLE_READY"
                    self.panelB.set_phase("\u2190 Drag bundle to Server")
                    self._refresh()
                    if not self._is_interactive() and self._auto_running:
                        delay = int(self._delay_spin.value() * 1000)
                        QtCore.QTimer.singleShot(delay, self._auto_advance_process)

        elif event == "error":
            self._stop_process_retry()
            self.panelB.log_step(f"Error: {evt.get('msg', '?')}", "#ef5350")
            self.panelB.set_status("ERROR", "#ef5350")

        elif event == "phase" and evt.get("phase") == "reset":
            # Server acknowledged RESET and is about to regenerate keys.
            # The GUI already cleared state in _on_reset; just update status.
            self.panelB.set_status("CONNECTED", "#4caf50")
            self.panelB.set_phase("Generating keys...")

    def _handle_client_event(self, evt):
        """Process one client JSON event."""
        event = evt.get("event", "")
        _log_app.info("CLI_EVT: %s  (phase=%s)", event, self._exchange_phase)
        p = self.proto

        if event == "connected":
            self.panelA.set_status("CONNECTED", "#4caf50")
            self.panelA.log_step(f"Connected to {evt.get('server', '?')}", CLR_ECDH)

        elif event == "keysizes":
            self.panelA.log_step("Key Sizes", "#90a4ae")
            self.panelA.log_val("kyber_variant", str(evt.get("kyber_variant", "?")), "#90a4ae")
            self.panelA.log_val("kyber_pk", str(evt.get("kyber_pk", "?")), "#90a4ae")
            self.panelA.log_val("ecdh_pk", str(evt.get("ecdh_pk", "?")), "#90a4ae")
            self.panelA.log_val("kyber_sk", str(evt.get("kyber_sk", "?")), "#90a4ae")
            self.panelA.log_val("ecdh_sk", str(evt.get("ecdh_sk", "?")), "#90a4ae")
            self.panelA.log_val("kyber_ss", str(evt.get("kyber_ss", "?")), "#90a4ae")
            self.panelA.log_val("ecdh_ss", str(evt.get("ecdh_ss", "?")), "#90a4ae")
            self.panelA.log_val("kyber_ct", str(evt.get("kyber_ct", "?")), "#90a4ae")
            self.panelA.log_val("hybrid_key", str(evt.get("hybrid_key", "?")), "#90a4ae")
            self.panelA.log_val("nonce", str(evt.get("nonce", "?")), "#90a4ae")

        elif event == "kex_mode_selected":
            self._active_kex_mode = evt.get("mode", self._active_kex_mode)
            self.panelA.log_step(f"KEX mode: {self._mode_label(self._active_kex_mode)}", "#90a4ae")
            self._refresh()

        elif event == "server_keys_received":
            ecdh_pk = evt.get("ecdh_pk", "")
            kyber_pk = evt.get("kyber_pk", "")
            self.panelA.log_step("Received server public keys", CLR_ECDH)
            self.panelA.log_val("s_ecdh_pk", ecdh_pk, CLR_ECDH)
            self.panelA.log_val("s_kyber_pk", kyber_pk, CLR_KYBER)

        elif event == "ecdh_keygen":
            pk = evt.get("pk", "")
            t = evt.get("time_ms", 0)
            p.c_ecdh_pk = pk
            p.c_ecdh_pk_time_ms = t
            step_idx = self._client_step_index("ecdh_keygen")
            step_total = self._client_total_steps()
            self.panelA.set_step(step_idx, step_total, "ECDH Keygen", CLR_ECDH)
            self.panelA.log_step(f"Client ECDH Keygen ({_format_duration_us(t)})", CLR_ECDH)
            self.panelA.log_val("c_ecdh_pk", pk, CLR_ECDH)
            self.panelA.set_status("PROCESSING", CLR_ECDH)
            self._refresh()

        elif event == "ecdh_derive":
            ss = evt.get("shared", "")
            t = evt.get("time_ms", 0)
            p.ecdh_ss_c = ss
            p.ecdh_ss_c_time_ms = t
            step_idx = self._client_step_index("ecdh_derive")
            step_total = self._client_total_steps()
            self.panelA.set_step(step_idx, step_total, "KDF Step \u2014 ECDH Shared Secret", CLR_ECDH)
            self.panelA.log_step(f"ECDH Shared Secret ({_format_duration_us(t)})", CLR_ECDH)
            self.panelA.log_val("ecdh_shared", ss, CLR_ECDH)
            self._refresh()

        elif event == "kyber_encap":
            ct = evt.get("ct", "")
            ss = evt.get("shared", "")
            t = evt.get("time_ms", 0)
            p.kyber_ct = ct
            p.kyber_ss_c = ss
            p.kyber_ss_c_time_ms = t
            step_idx = self._client_step_index("kyber_encap")
            step_total = self._client_total_steps()
            self.panelA.set_step(step_idx, step_total, "KDF Step \u2014 Kyber Encapsulation", CLR_KYBER)
            self.panelA.log_step(f"Kyber Encapsulation ({_format_duration_us(t)})", CLR_KYBER)
            self.panelA.log_val("kyber_ct", ct, CLR_KYBER)
            self.panelA.log_val("kyber_ss", ss, CLR_KYBER)
            self._refresh()

        elif event == "hybrid_key":
            self._active_kex_mode = evt.get("mode", self._active_kex_mode)
            key = evt.get("key", "")
            t = evt.get("time_ms", 0)
            p.hybrid_c = key
            p.hybrid_c_time_ms = t
            step_idx = self._client_step_index("hybrid_key")
            step_total = self._client_total_steps()
            self.panelA.set_step(step_idx, step_total, "Session KDF \u2014 SHA-256(selected secret(s))", CLR_HYBRID)
            self.panelA.log_step(f"Session KDF ({self._active_kex_mode.upper()}) ({_format_duration_us(t)})", CLR_HYBRID)
            self.panelA.log_val("hybrid_key", key, CLR_HYBRID)
            self._refresh()

        elif event == "encrypt":
            ct = evt.get("ciphertext", "")
            nonce = evt.get("nonce", "")
            t = evt.get("time_ms", 0)
            p.enc_msg = ct
            p.nonce = nonce
            p.encrypt_time_ms = t
            step_idx = self._client_step_index("encrypt")
            step_total = self._client_total_steps()
            self.panelA.set_step(step_idx, step_total, "Encrypt \u2014 Message Sealed", CLR_CIPHER)
            self.panelA.log_step(f"Encrypt ({_format_duration_us(t)})", CLR_CIPHER)
            self.panelA.log_val("ciphertext", ct, CLR_CIPHER)
            self._refresh()

        elif event == "data_sent":
            self.panelA.log_step("Bundle sent to server", CLR_ECDH)
            self.panelA.set_phase("Data sent")
            self._refresh()

        elif event == "complete":
            resp = evt.get("response", "")
            self.panelA.set_status("COMPLETE" if resp == "SUCCESS" else "ERROR",
                                   "#39ff14" if resp == "SUCCESS" else "#ef5350")
            self.panelA.set_phase("Done" if resp == "SUCCESS" else "Failed")

    def _on_live_exchange_done(self):
        """Called when the client process exits (exchange finished)."""
        _log_app.info("exchange_done signal: phase=%s", self._exchange_phase)
        pass  # Server auto-loops; phases drive the flow.

    # ── phase-driven exchange flow ────────────────────────────

    def _client_bundle_complete(self) -> bool:
        p = self.proto
        has_ecdh = (not self._uses_ecdh()) or bool(p.c_ecdh_pk)
        has_kyber = (not self._uses_kyber()) or bool(p.kyber_ct)
        return bool(has_ecdh and has_kyber and p.nonce and p.enc_msg)

    def _on_vehicle_drop(self, token_type):
        """Server keys dropped on broker top zone → start client."""
        _log_app.info("DROP vehicle: token=%s phase=%s", token_type, self._exchange_phase)
        if token_type == "server_keys" and self._exchange_phase == "KEYS_READY":
            if not self._mode_is_selected():
                self.broker.log_relay("Select KEX mode first", "#ef5350")
                return
            mode_label = self._effective_mode().upper()
            self.broker.log_relay(f"Server Keys \u2192 Vehicle ({mode_label})")
            # Show connected + server_keys_received + ecdh_keygen instantly
            self._instant_count = 3
            self._advance_to_client()

    def _on_server_drop(self, token_type):
        """Client bundle dropped on broker bottom zone → send PROCESS."""
        _log_app.info("DROP server: token=%s phase=%s bundle_complete=%s",
                     token_type, self._exchange_phase, self._client_bundle_complete())
        if token_type == "client_bundle" and self._client_bundle_complete():
            mode_label = self._effective_mode().upper()
            self.broker.log_relay(f"Client Bundle → Server ({mode_label} + Nonce + Enc Msg)")
            # Show server_keys_received instantly
            self._instant_count = 1
            self._advance_to_process()

    def _on_token_send(self, token_type):
        """Send button clicked on a token."""
        if token_type == "server_keys" and self._exchange_phase == "KEYS_READY":
            if not self._mode_is_selected():
                self.broker.log_relay("Select KEX mode first", "#ef5350")
                return
            mode_label = self._effective_mode().upper()
            self.broker.log_relay(f"Server Keys → Vehicle ({mode_label})")
            self._advance_to_client()
        elif token_type == "client_bundle" and self._client_bundle_complete():
            mode_label = self._effective_mode().upper()
            self.broker.log_relay(f"Client Bundle → Server ({mode_label} + Nonce + Enc Msg)")
            self._advance_to_process()

    def _advance_to_client(self):
        """Start the client on the board."""
        _log_app.info("_advance_to_client: phase=%s", self._exchange_phase)
        if not self._selected_kex_mode:
            self.panelA.set_status("ERROR", "#ef5350")
            self.panelA.set_phase("Select KEX mode first")
            self.broker.log_relay("Select KEX mode before starting client", "#ef5350")
            return
        msg = ""
        if self._is_interactive():
            # Prompt right before client start (after bundle drop from broker).
            dlg = _MessageDialog(self)
            if dlg.exec() != QtWidgets.QDialog.Accepted:
                _log_app.info("_advance_to_client: user cancelled message dialog")
                return
            msg = dlg.get_message()
        else:
            msg = "Hello from Vehicle — PQC secured!"
        if not msg:
            self.panelA.set_status("ERROR", "#ef5350")
            self.panelA.set_phase("Enter a message first!")
            self._exchange_phase = "KEYS_READY"  # stay in this phase
            self._auto_start_btn.setEnabled(True)
            self._auto_start_btn.setText("\u25b6  RUN EXCHANGE")
            return
        self._exchange_phase = "CLIENT_RUNNING"
        self._active_kex_mode = self._selected_kex_mode
        self.panelA.set_status("CONNECTING", CLR_ECDH)
        self.panelA.set_phase(f"Running client on board ({self._active_kex_mode.upper()})...")
        self.panelA.log_step(f"Message: \"{msg}\"", "#90a4ae")
        self._refresh()
        if self._live_proto:
            self._live_proto.run_client(msg, self._active_kex_mode)

    def _advance_to_process(self):
        """Queue/signal server-side processing of the received bundle."""
        _log_app.info("_advance_to_process: phase=%s srv_bundle=%s",
                     self._exchange_phase, self._server_bundle_ready)
        self._process_requested = True
        self._commit_process()

    def _commit_process(self):
        _log_app.info("_commit_process: phase=%s srv_bundle=%s proc_req=%s srv_started=%s",
                     self._exchange_phase, self._server_bundle_ready,
                     self._process_requested, self._server_processing_started)
        if self._exchange_phase == "PROCESSING":
            _log_app.info("_commit_process: already PROCESSING, resending")
            if self._live_proto and not self._live_proto.send_command("PROCESS"):
                _log_app.error("PROCESS resend failed (socket dead)")
                self.broker.log_relay("PROCESS send failed — socket dead", "#ef5350")
            if not self._process_retry_timer:
                self._start_process_retry()
            return
        self._server_processing_started = False
        self._exchange_phase = "PROCESSING"
        self.panelB.set_status("PROCESSING", CLR_ECDH)
        self.panelB.set_phase("Decrypting...")
        self._refresh()
        if self._live_proto and not self._live_proto.send_command("PROCESS"):
            _log_app.error("PROCESS send failed (socket dead)")
            self.broker.log_relay("PROCESS send failed — socket dead", "#ef5350")
        self._start_process_retry()

    def _start_process_retry(self):
        self._stop_process_retry()
        self._process_retry_count = 0
        self._process_retry_timer = QtCore.QTimer(self)
        self._process_retry_timer.setInterval(300)
        self._process_retry_timer.timeout.connect(self._retry_process_command)
        self._process_retry_timer.start()

    def _retry_process_command(self):
        if not self._process_requested:
            self._stop_process_retry()
            return
        if self._server_processing_started:
            self._process_requested = False
            self._stop_process_retry()
            return
        self._process_retry_count += 1
        if self._process_retry_count > 40:
            self._stop_process_retry()
            return
        if self._live_proto and not self._live_proto.send_command("PROCESS"):
            _log_app.error("PROCESS retry #%d send failed", self._process_retry_count)

    def _stop_process_retry(self):
        if self._process_retry_timer:
            self._process_retry_timer.stop()
            self._process_retry_timer.deleteLater()
            self._process_retry_timer = None

    def _start_next_retry(self):
        self._stop_next_retry()
        self._next_retry_count = 0
        self._next_retry_timer = QtCore.QTimer(self)
        self._next_retry_timer.setInterval(300)
        self._next_retry_timer.timeout.connect(self._retry_next_command)
        self._next_retry_timer.start()

    def _retry_next_command(self):
        if self._exchange_phase != "IDLE":
            self._stop_next_retry()
            return
        self._next_retry_count += 1
        if self._next_retry_count > 8:
            self._stop_next_retry()
            return
        if self._live_proto:
            self._live_proto.send_command("NEXT")

    def _stop_next_retry(self):
        if self._next_retry_timer:
            self._next_retry_timer.stop()
            self._next_retry_timer.deleteLater()
            self._next_retry_timer = None

    def _auto_advance_client(self):
        if self._exchange_phase == "KEYS_READY" and not self._is_interactive():
            self.panelB._bundle_collector.auto_fill_all()
            self._refresh()
            self._advance_to_client()

    def _auto_advance_process(self):
        if self._exchange_phase == "BUNDLE_READY" and not self._is_interactive():
            self.panelA._bundle_collector.auto_fill_all()
            self._refresh()
            self._advance_to_process()

    def _live_run_exchange(self):
        """Reset proto & logs, then trigger a real exchange via SSH."""
        if not self._live_proto:
            return
        if not self._selected_kex_mode:
            self.broker.log_relay("Select KEX mode before running exchange", "#ef5350")
            return
        self.proto.reset()
        self.panelA.clear_log(); self.panelB.clear_log()
        self.panelA.set_status("CONNECTING", CLR_ECDH)
        self.panelB.set_status("LISTENING", CLR_ECDH)
        self._live_proto.run_client(kex_mode=self._selected_kex_mode)

    # ── actions ───────────────────────────────────────────────

    def _on_reset(self):
        _log_app.info("_on_reset: phase=%s srv_bundle=%s proc_req=%s",
                     self._exchange_phase, self._server_bundle_ready, self._process_requested)
        self._flush_event_queue()
        # Determine what command to send the server based on current phase:
        #  COMPLETE        → NEXT  (server is blocking in gui_wait_command("NEXT"))
        #  KEYS_READY /    → RESET (server is blocking in accept_or_reset or
        #  BUNDLE_READY         gui_wait_command("PROCESS"); RESET causes it to
        #                       regenerate keys and re-emit key events)
        need_next  = (self._exchange_phase == "COMPLETE")
        need_reset = (self._exchange_phase in ("KEYS_READY", "BUNDLE_READY"))
        _log_app.info("_on_reset: need_next=%s need_reset=%s", need_next, need_reset)
        self._stop_process_retry()
        self._stop_next_retry()
        self._server_bundle_ready = False
        self._process_requested = False
        self._server_processing_started = False
        self.proto.reset()
        self._exchange_phase = "IDLE"
        self.panelA.clear_log(); self.panelB.clear_log()
        self.broker.clear_log()
        self._active_kex_mode = self._selected_kex_mode
        self.panelA._bundle_collector.clear()
        self.panelB._bundle_collector.clear()
        self.panelA.set_status("IDLE"); self.panelB.set_status("IDLE")
        self.panelA.set_phase("")
        self.panelB.set_phase("")
        self._auto_exchange_count = 0
        self._auto_running = False
        self._auto_start_btn.setEnabled(True)
        self._auto_start_btn.setText("▶  RUN EXCHANGE")
        self._refresh()
        if self._live_proto and need_next:
            _log_app.info("_on_reset: sending NEXT + starting retry")
            self._live_proto.send_command("NEXT")
            self._start_next_retry()
            self.panelB.set_status("CONNECTED", "#4caf50")
            self.panelB.set_phase("Generating keys...")
        elif self._live_proto and need_reset:
            _log_app.info("_on_reset: sending RESET — server will regenerate keys")
            self._live_proto.send_command("RESET")
            self._start_next_retry()
            self.panelB.set_status("CONNECTED", "#4caf50")
            self.panelB.set_phase("Generating keys...")

    def _on_clear_logs(self):
        self.panelA.clear_log(); self.panelB.clear_log()

    # ── autonomous mode ───────────────────────────────────────

    def _on_auto_start(self):
        """Single autonomous exchange: advance through all phases automatically."""
        self._auto_start_btn.setEnabled(False)
        self._auto_start_btn.setText("⏳  RUNNING...")
        self._auto_running = True
        self._auto_exchange_count = 0
        # If exchange hasn't started yet (IDLE/COMPLETE), reset first
        if self._exchange_phase in ("IDLE", "COMPLETE"):
            self._on_reset()
        # Kick off from whatever phase we're in
        delay = int(self._delay_spin.value() * 1000)
        if self._exchange_phase == "KEYS_READY":
            QtCore.QTimer.singleShot(delay, self._auto_advance_client)
        elif self._exchange_phase == "BUNDLE_READY":
            QtCore.QTimer.singleShot(delay, self._auto_advance_process)

    # ── hamburger / log panel ─────────────────────────────────

    def resizeEvent(self, event):
        super().resizeEvent(event); self._reposition_log_panel()

    def _reposition_log_panel(self):
        if not hasattr(self, '_log_panel'): return
        cw = self.centralWidget()
        pw = max(520, cw.width() * 2 // 5)
        self._log_panel.setGeometry(cw.width() - pw, 0, pw, cw.height())

    def _on_hamburger_clicked(self, checked):
        if checked:
            self._reposition_log_panel(); self._log_panel.show(); self._log_panel.raise_()
        else:
            self._log_panel.hide()

    def _on_log_panel_close(self):
        self._log_panel.hide(); self._hamburger_btn.setChecked(False)

    def _toggle_logs(self):
        self._logs_visible = not self._logs_visible
        self._log_content.setVisible(self._logs_visible)
        self._log_toggle_btn.setText(
            "\u25bc  LOGS" if self._logs_visible else "\u25b6  LOGS")
        # Resize splitter so top row claims the freed space
        total = sum(self._splitter.sizes())
        if self._logs_visible:
            btn_h = self._log_toggle_btn.height()
            log_h = max(total // 5, 120)
            self._splitter.setSizes([total - log_h, log_h])
        else:
            btn_h = self._log_toggle_btn.height() + 4
            self._splitter.setSizes([total - btn_h, btn_h])

    # ── refresh UI ────────────────────────────────────────────

    def _refresh(self):
        p = self.proto
        bundle_complete = self._client_bundle_complete()
        phase = self._exchange_phase
        mode_selected = self._mode_is_selected()
        use_ecdh = self._uses_ecdh()
        use_kyber = self._uses_kyber()
        client_steps = self._client_total_steps()
        server_steps = self._server_total_steps()

        # ── Server keys ───────────────────────────────────────
        s_keys = []
        if mode_selected and use_ecdh and p.s_ecdh_pk: s_keys.append(KeyEntry("Server ECDH Public Key (X25519)", p.s_ecdh_pk, CLR_ECDH, _step_with_duration("Keygen", p.s_ecdh_pk_time_ms),
                                                 bundle_key="s_ecdh_pk" if phase == "KEYS_READY" else "", size_bytes=32, flow_slot="ecdh_1"))
        if mode_selected and use_kyber and p.s_kyber_pk: s_keys.append(KeyEntry("Server Kyber-768 Public Key", p.s_kyber_pk, CLR_KYBER, _step_with_duration("Keygen", p.s_kyber_pk_time_ms),
                                                  bundle_key="s_kyber_pk" if phase == "KEYS_READY" else "", size_bytes=1184, flow_slot="kyber_1"))
        if mode_selected and use_ecdh and p.ecdh_ss_s: s_keys.append(KeyEntry("ECDH Shared Secret", p.ecdh_ss_s, CLR_ECDH, _step_with_duration(f"Step {self._server_step_index('ecdh_derive')}/{server_steps}", p.ecdh_ss_s_time_ms), flow_slot="ecdh_2"))
        if mode_selected and use_kyber and p.kyber_ss_s: s_keys.append(KeyEntry("Kyber Shared Secret", p.kyber_ss_s, CLR_KYBER, _step_with_duration(f"Step {self._server_step_index('kyber_decap')}/{server_steps}", p.kyber_ss_s_time_ms), flow_slot="kyber_2"))
        if mode_selected and p.hybrid_s: s_keys.append(KeyEntry("Session Key", p.hybrid_s, CLR_HYBRID, _step_with_duration(f"Step {self._server_step_index('hybrid_key')}/{server_steps}", p.hybrid_s_time_ms), flow_slot="hybrid"))
        if mode_selected and p.decrypted: s_keys.append(KeyEntry("Decrypted Message", p.decrypted, "#4caf50", _step_with_duration(f"Step {self._server_step_index('decrypt')}/{server_steps}", p.decrypt_time_ms), flow_slot="decrypt"))
        self.panelB.set_keys(s_keys)

        server_total_ms = _sum_times_ms([
            p.s_ecdh_pk_time_ms if use_ecdh else None,
            p.s_kyber_pk_time_ms if use_kyber else None,
            p.ecdh_ss_s_time_ms if use_ecdh else None,
            p.kyber_ss_s_time_ms if use_kyber else None,
            p.hybrid_s_time_ms,
            p.decrypt_time_ms,
        ])
        self.panelB.set_total_time_ms(server_total_ms if mode_selected else None)

        # Server bundle collector — show during KEYS_READY phase
        s_bc = self.panelB._bundle_collector
        server_ready = (not use_ecdh or p.s_ecdh_pk) and (not use_kyber or p.s_kyber_pk)
        if mode_selected and phase == "KEYS_READY" and server_ready and (use_ecdh or use_kyber):
            slots = []
            if use_ecdh:
                slots.append(_BundleSlot("s_ecdh_pk", "ECDH PK", CLR_ECDH, size_bytes=32))
            if use_kyber:
                slots.append(_BundleSlot("s_kyber_pk", "Kyber PK", CLR_KYBER, size_bytes=1184))
            expected = [s.key for s in slots]
            current = [s.key for s in s_bc._slots]
            if s_bc._token_type != "server_keys" or current != expected:
                s_bc.configure("server_keys", slots)
        else:
            if s_bc._slots or s_bc._token_type:
                s_bc.clear()

        # ── Vehicle keys ──────────────────────────────────────
        can_bundle = bundle_complete and phase not in ("PROCESSING", "COMPLETE")
        v_keys = []
        if mode_selected and use_ecdh and p.c_ecdh_pk: v_keys.append(KeyEntry("Vehicle ECDH Public Key (X25519)", p.c_ecdh_pk, CLR_ECDH, _step_with_duration(f"Step {self._client_step_index('ecdh_keygen')}/{client_steps}", p.c_ecdh_pk_time_ms),
                                                 bundle_key="c_ecdh_pk" if can_bundle else "", size_bytes=32, flow_slot="ecdh_1"))
        if mode_selected and use_ecdh and p.ecdh_ss_c: v_keys.append(KeyEntry("ECDH Shared Secret", p.ecdh_ss_c, CLR_ECDH, _step_with_duration(f"Step {self._client_step_index('ecdh_derive')}/{client_steps}", p.ecdh_ss_c_time_ms), flow_slot="ecdh_2"))
        if mode_selected and use_kyber and p.kyber_ct: v_keys.append(KeyEntry("Vehicle Kyber Ciphertext", p.kyber_ct, CLR_KYBER, _step_with_duration(f"Step {self._client_step_index('kyber_encap')}/{client_steps}", p.kyber_ss_c_time_ms),
                                               bundle_key="kyber_ct" if can_bundle else "", size_bytes=1088, flow_slot="kyber_1"))
        if mode_selected and use_kyber and p.kyber_ss_c: v_keys.append(KeyEntry("Kyber Shared Secret", p.kyber_ss_c, CLR_KYBER, _step_with_duration(f"Step {self._client_step_index('kyber_encap')}/{client_steps}", p.kyber_ss_c_time_ms), flow_slot="kyber_2"))
        if mode_selected and p.hybrid_c: v_keys.append(KeyEntry("Session Key", p.hybrid_c, CLR_HYBRID, _step_with_duration(f"Step {self._client_step_index('hybrid_key')}/{client_steps}", p.hybrid_c_time_ms), flow_slot="hybrid"))
        if mode_selected and p.enc_msg:
            enc_bytes = len(p.enc_msg) // 2
            v_keys.append(KeyEntry("Encrypted Message", p.enc_msg, CLR_CIPHER, _step_with_duration(f"Step {self._client_step_index('encrypt')}/{client_steps}", p.encrypt_time_ms),
                                    bundle_key="enc_msg" if can_bundle else "", size_bytes=enc_bytes, flow_slot="encrypt_1"))
        if mode_selected and p.nonce: v_keys.append(KeyEntry("Nonce", p.nonce, CLR_CIPHER, _step_with_duration(f"Step {self._client_step_index('encrypt')}/{client_steps}", p.encrypt_time_ms),
                                            bundle_key="nonce" if can_bundle else "", size_bytes=24, flow_slot="encrypt_2"))
        self.panelA.set_keys(v_keys)

        client_total_ms = _sum_times_ms([
            p.c_ecdh_pk_time_ms if use_ecdh else None,
            p.ecdh_ss_c_time_ms if use_ecdh else None,
            p.kyber_ss_c_time_ms if use_kyber else None,
            p.hybrid_c_time_ms,
            p.encrypt_time_ms,
        ])
        self.panelA.set_total_time_ms(client_total_ms if mode_selected else None)

        # Vehicle bundle collector — show once we have bundle items
        v_bc = self.panelA._bundle_collector
        if mode_selected and can_bundle and (use_ecdh or use_kyber):
            slots = []
            if use_ecdh:
                slots.append(_BundleSlot("c_ecdh_pk", "ECDH PK", CLR_ECDH, size_bytes=32))
            if use_kyber:
                slots.append(_BundleSlot("kyber_ct", "Kyber CT", CLR_KYBER, size_bytes=1088))
            slots.extend([
                _BundleSlot("nonce", "Nonce", CLR_CIPHER, size_bytes=24),
                _BundleSlot("enc_msg", "Enc Msg", CLR_CIPHER, size_bytes=0),
            ])
            expected = [s.key for s in slots]
            current = [s.key for s in v_bc._slots]
            if v_bc._token_type != "client_bundle" or current != expected:
                v_bc.configure("client_bundle", slots)
        else:
            if v_bc._slots or v_bc._token_type:
                v_bc.clear()

        # Drop zones on broker — active when corresponding bundle is complete
        if mode_selected and s_bc.is_complete() and phase == "KEYS_READY":
            self.broker.drop_server_to_vehicle.activate(True, "⟵ Drop Server Keys\nServer → Vehicle", ["server_keys"])
            self.broker.drop_vehicle_to_server.activate(False)
        elif mode_selected and v_bc.is_complete() and phase not in ("PROCESSING", "COMPLETE"):
            self.broker.drop_vehicle_to_server.activate(True, "⟵ Drop Client Bundle\nVehicle → Server", ["client_bundle"])
            self.broker.drop_server_to_vehicle.activate(False)
        else:
            self.broker.drop_server_to_vehicle.activate(False)
            self.broker.drop_vehicle_to_server.activate(False)


def main():
    _log_app.info("=" * 60)
    _log_app.info("PQC DEMO starting")
    _log_app.info("SERVER_BIN  = %s", _SERVER_BIN)
    _log_app.info("LOCAL_CLIENT= %s", _LOCAL_CLIENT)
    _log_app.info("PQC_PORT    = %s", _PQC_PORT)
    _log_app.info("GUI_PORT    = %s", _GUI_PORT)
    _log_app.info("LOG_DIR     = %s", _LOG_DIR)
    _log_app.info("=" * 60)
    app = QtWidgets.QApplication(sys.argv)
    app.setStyle(_InstantToolTipStyle())
    app.setStyleSheet(app.styleSheet() + """
        QToolTip {
            background-color: #1a1a1a; color: #e0e0e0;
            border: 1px solid #3a3a3a; border-radius: 4px;
            padding: 4px 8px; font-size: 11px;
            font-family: 'Consolas', 'Monaco', monospace;
        }
    """)
    w = MainWindow()
    w.show()
    ret = app.exec()
    # Cleanup live server on exit
    _log_app.info("App exiting (ret=%d), cleaning up...", ret)
    if w._live_proto:
        w._live_proto.stop()
    _log_app.info("Goodbye")
    sys.exit(ret)


if __name__ == "__main__":
    main()
