import sys
import json
import subprocess
import socket
import threading
import logging
import traceback
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
CLR_ECDH = "#42a5f5"; CLR_KYBER = "#ab47bc"; CLR_HYBRID = "#ffa726"; CLR_CIPHER = "#ef5350"

def _short(h, n=32): return h if len(h) <= n else h[:n] + "…"


@dataclass
class KeyEntry:
    label: str
    hexval: str
    color: str


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
_SERVER_IP = _CFG.get("SERVER_IP", "192.168.0.101")
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
        """Spawn the C server with --gui PORT and connect to its report socket."""
        if self._server_proc is not None:
            _log_srv.warning("start_server called but already running (pid %s)", self._server_proc.pid)
            return  # already running

        _log_srv.info("Spawning: %s --gui %s --port %s --debug", _SERVER_BIN, _GUI_PORT, _PQC_PORT)
        self.status_msg.emit("Starting server...")

        srv_log_path = _LOG_DIR / "server_stderr.log"
        self._srv_log_fh = open(srv_log_path, "a")
        self._srv_log_fh.write(f"\n--- Server start {datetime.now()} ---\n")
        self._srv_log_fh.flush()

        self._server_proc = subprocess.Popen(
            [_SERVER_BIN, "--gui", str(_GUI_PORT), "--port", str(_PQC_PORT), "--debug"],
            stdout=subprocess.DEVNULL,
            stderr=self._srv_log_fh,
        )
        _log_srv.info("Server spawned pid=%d", self._server_proc.pid)

        # Give server a moment to bind, then connect
        QtCore.QTimer.singleShot(500, self._connect_gui_socket)

    def _connect_gui_socket(self):
        """Connect to the server's GUI report port (single persistent TCP)."""
        if self._server_proc:
            rc = self._server_proc.poll()
            if rc is not None:
                _log_gui.error("Server already DEAD (rc=%s) before GUI connect!", rc)
                self.status_msg.emit(f"Server died before connect (rc={rc})")
                return
        _log_gui.info("Connecting GUI socket to 127.0.0.1:%d ...", _GUI_PORT)
        try:
            self._gui_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._gui_sock.settimeout(5)
            self._gui_sock.connect(("127.0.0.1", _GUI_PORT))
            self._gui_sock.settimeout(None)
            self._running = True
            _log_gui.info("GUI socket connected (fd=%s)", self._gui_sock.fileno())
            self._reader_thread = threading.Thread(
                target=self._read_server_events, daemon=True
            )
            self._reader_thread.start()
            self.status_msg.emit("Server ready")
        except OSError as e:
            _log_gui.error("GUI connect FAILED: %s", e)
            self.status_msg.emit(f"GUI connect failed: {e}")

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
                        evt_name = evt.get("event", "?")
                        _log_srv.debug("← %s", evt_name)
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

    def run_client(self, message=""):
        """Run the client locally or via SSH to the board."""
        self._client_message = message
        _log_cli.info("run_client(msg=%r)", message[:60] if message else "")
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
        else:
            remote_cmd = f"{_BOARD_CLIENT} {_SERVER_IP} --json --port {_PQC_PORT}"
            if self._client_message:
                escaped = self._client_message.replace("'", "'\\''")
                remote_cmd += f" --msg '{escaped}'"
            cmd = [
                "ssh", "-o", "ConnectTimeout=5",
                "-o", "StrictHostKeyChecking=no",
                f"{_BOARD_USER}@{_BOARD_IP}",
                remote_cmd,
            ]
        _log_cli.info("Spawning: %s", " ".join(cmd))
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                close_fds=True
            )
            _log_cli.info("Client spawned pid=%d", proc.pid)
            for raw_line in proc.stdout:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    evt = json.loads(line.decode("utf-8", errors="replace"))
                    _log_cli.debug("← %s", json.dumps(evt, separators=(',', ':')))
                    self.client_event.emit(evt)
                except json.JSONDecodeError:
                    _log_cli.warning("non-JSON stdout: %s", line[:200])
            rc = proc.wait()
            stderr_out = proc.stderr.read().decode("utf-8", errors="replace").strip()
            _log_cli.info("Client exited rc=%d stderr=%r", rc, stderr_out[:500] if stderr_out else "")
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
        self._drag_token_type: str = ""  # e.g. "server_keys" or "client_bundle"
        self._drag_start = None
        self._drag_overlay: _DragOverlay | None = None
        self._dragging = False
        self._poll_timer: QtCore.QTimer | None = None  # polls cursor pos during drag
        self._prev_left_down = False  # track button state via polling

    def set_entries(self, entries: list[KeyEntry]):
        self._entries = list(entries)
        self.update()

    def set_draggable(self, token_type: str):
        self._drag_token_type = token_type
        self.setCursor(QtCore.Qt.OpenHandCursor if token_type else QtCore.Qt.ArrowCursor)
        self.update()

    def _entry_rects(self) -> list[QtCore.QRect]:
        pad = 8; gap = 6; cols = 2
        total_w = max(1, self.width() - pad * 2)
        col_w = (total_w - gap * (cols - 1)) // cols
        n = len(self._entries)
        rows = (n + cols - 1) // cols if n else 1
        entry_h = min(50, max(34, (self.height() - pad * 2 - gap * (rows - 1)) // rows))
        rects = []
        for i in range(n):
            r = i // cols
            c = i % cols
            x = pad + c * (col_w + gap)
            y = pad + r * (entry_h + gap)
            rects.append(QtCore.QRect(x, y, col_w, entry_h))
        return rects

    def _make_drag_pixmap(self) -> QtGui.QPixmap:
        src = self.grab()
        pix = QtGui.QPixmap(src.size())
        pix.fill(QtCore.Qt.transparent)
        pp = QtGui.QPainter(pix)
        pp.setOpacity(0.70)
        pp.drawPixmap(0, 0, src)
        pp.end()
        half_w = max(pix.width() // 2, 1)
        half_h = max(pix.height() // 2, 1)
        return pix.scaled(half_w, half_h,
                    QtCore.Qt.KeepAspectRatio, QtCore.Qt.SmoothTransformation)

    def _find_drop_zone_at(self, global_pos: QtCore.QPoint):
        top = self.window()
        for dz in top.findChildren(_DropZone):
            if not dz._active:
                continue
            if dz._accept and self._drag_token_type not in dz._accept:
                continue
            local = dz.mapFromGlobal(global_pos)
            if dz.rect().contains(local):
                return dz
        return None

    def _highlight_drop_zones(self, global_pos: QtCore.QPoint):
        top = self.window()
        for dz in top.findChildren(_DropZone):
            if not dz._active:
                continue
            if dz._accept and self._drag_token_type not in dz._accept:
                continue
            local = dz.mapFromGlobal(global_pos)
            hovering = dz.rect().contains(local)
            if hovering != dz._hovering:
                dz._hovering = hovering
                dz._restyle()

    def _poll_drag(self):
        """Timer callback: move overlay, highlight zones, detect mouse-up."""
        gpos = QtGui.QCursor.pos()
        # Move overlay
        if self._drag_overlay:
            self._drag_overlay.follow_cursor()
        # Highlight drop zones
        self._highlight_drop_zones(gpos)
        # Detect mouse button release by polling button state
        buttons = QtWidgets.QApplication.mouseButtons()
        left_down = bool(buttons & QtCore.Qt.LeftButton)
        if self._prev_left_down and not left_down:
            # Mouse was released — finish drag
            dz = self._find_drop_zone_at(gpos)
            self._finish_drag()
            if dz:
                dz.dropped.emit(self._drag_token_type)
            return
        self._prev_left_down = left_down

    def _finish_drag(self):
        if self._poll_timer:
            self._poll_timer.stop()
            self._poll_timer = None
        if self._drag_overlay:
            self._drag_overlay.close()
            self._drag_overlay = None
        self._dragging = False
        self._drag_start = None
        self._prev_left_down = False
        self.setCursor(QtCore.Qt.OpenHandCursor if self._drag_token_type else QtCore.Qt.ArrowCursor)
        # Reset all drop zone hover states
        top = self.window()
        for dz in top.findChildren(_DropZone):
            if dz._hovering:
                dz._hovering = False
                dz._restyle()

    def mousePressEvent(self, ev):
        if ev.button() == QtCore.Qt.LeftButton and self._drag_token_type:
            self._drag_start = ev.position().toPoint()
        super().mousePressEvent(ev)

    def mouseMoveEvent(self, event):
        # Initiate drag (only once)
        if self._drag_start and self._drag_token_type and not self._dragging:
            if (event.position().toPoint() - self._drag_start).manhattanLength() >= 12:
                self._dragging = True
                self._prev_left_down = True
                pix = self._make_drag_pixmap()
                self._drag_overlay = _DragOverlay(pix, self.window())
                self._drag_overlay.show()
                self.setCursor(QtCore.Qt.ClosedHandCursor)
                # Start polling timer — works even when cursor leaves widget
                self._poll_timer = QtCore.QTimer(self)
                self._poll_timer.setInterval(16)  # ~60 fps
                self._poll_timer.timeout.connect(self._poll_drag)
                self._poll_timer.start()
                return
        # Hover tracking (normal, not dragging)
        if not self._dragging:
            pos = event.position().toPoint()
            old = self._hover_index; self._hover_index = None
            for i, r in enumerate(self._entry_rects()):
                if r.contains(pos):
                    self._hover_index = i
                    e = self._entries[i]
                    QtWidgets.QToolTip.showText(event.globalPosition().toPoint(),
                        f"{e.label}\n{e.hexval[:80]}", self)
                    break
            else:
                QtWidgets.QToolTip.hideText()
            if old != self._hover_index: self.update()
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, ev):
        # If dragging, the poll timer handles release detection — but as a safety net:
        if self._dragging:
            gpos = QtGui.QCursor.pos()
            dz = self._find_drop_zone_at(gpos)
            self._finish_drag()
            if dz:
                dz.dropped.emit(self._drag_token_type)
            return
        self._drag_start = None
        super().mouseReleaseEvent(ev)

    def paintEvent(self, _event):
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

        rects = self._entry_rects()
        for i, r in enumerate(rects):
            e = self._entries[i]
            color = QtGui.QColor(e.color)
            fill = QtGui.QColor(pal['slot_filled_fill'])
            border = color

            # shadow
            sr = r.adjusted(2, 2, 2, 2)
            p.setPen(QtCore.Qt.NoPen)
            p.setBrush(QtGui.QBrush(QtGui.QColor(0, 0, 0, 80)))
            p.drawRoundedRect(sr, 6, 6)
            # fill
            p.setBrush(QtGui.QBrush(fill))
            p.drawRoundedRect(r, 6, 6)
            # left accent bar
            bar = QtCore.QRect(r.x(), r.y() + 4, 4, r.height() - 8)
            p.setBrush(QtGui.QBrush(color))
            p.drawRoundedRect(bar, 2, 2)
            # border gradient
            gradient = QtGui.QLinearGradient(r.topLeft(), r.bottomRight())
            gradient.setColorAt(0, border); gradient.setColorAt(1, border.darker(120))
            p.setPen(QtGui.QPen(QtGui.QBrush(gradient), 2))
            p.setBrush(QtCore.Qt.NoBrush)
            p.drawRoundedRect(r.adjusted(1, 1, -1, -1), 5, 5)
            # label
            lf = QtGui.QFont("Consolas", 9); lf.setStyleHint(QtGui.QFont.Monospace); lf.setBold(True)
            p.setFont(lf); p.setPen(color)
            p.drawText(r.adjusted(14, 3, 0, -r.height()//2), QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter, e.label)
            # hex
            vf = QtGui.QFont("Consolas", 8); vf.setStyleHint(QtGui.QFont.Monospace)
            p.setFont(vf); p.setPen(QtGui.QColor("#90a4ae"))
            p.drawText(r.adjusted(14, r.height()//2, -8, -3), QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter, _short(e.hexval, 24))
            # hover glow
            if self._hover_index == i:
                p.setBrush(QtCore.Qt.NoBrush)
                for width, alpha in [(8, 30), (5, 60), (3, 100)]:
                    gc = QtGui.QColor(e.color); gc.setAlpha(alpha)
                    p.setPen(QtGui.QPen(gc, width))
                    p.drawRoundedRect(r.adjusted(-width//2, -width//2, width//2, width//2), 8, 8)
        # Draw drag hint if draggable
        if self._drag_token_type and self._entries:
            p.setPen(QtGui.QColor("#90a4ae"))
            hf = QtGui.QFont(); hf.setPointSize(9)
            p.setFont(hf)
            p.drawText(self.rect().adjusted(0, 0, -12, -4), QtCore.Qt.AlignRight | QtCore.Qt.AlignBottom, "⟷ drag to send")
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
    def __init__(self, pal, parent=None):
        super().__init__(parent)
        self._active = False; self._hovering = False; self._accept = []; self._pal = pal
        self.setAcceptDrops(True); self.setFixedHeight(80)
        lay = QtWidgets.QVBoxLayout(self); lay.setAlignment(QtCore.Qt.AlignCenter)
        self._label = QtWidgets.QLabel("Drop zone")
        self._label.setAlignment(QtCore.Qt.AlignCenter)
        self._label.setStyleSheet(f"color:{pal['read_muted_text']}; font-size:12px; background:transparent;")
        lay.addWidget(self._label); self._restyle()

    def activate(self, active, label="", accept=None):
        self._active = active; self._accept = accept or self._accept
        self._label.setText(label if active else "Drop zone")
        self._restyle()

    def _restyle(self):
        pal = self._pal
        if self._hovering:
            ss = f"_DropZone{{ background:#1b3a20; border:2px dashed #4caf50; border-radius:10px; }}"
        elif self._active:
            ss = f"_DropZone{{ background:{pal['section_bg']}; border:2px dashed {pal['subtitle_color']}; border-radius:10px; }}"
        else:
            ss = f"_DropZone{{ background:{pal['section_bg']}; border:2px solid {pal['slot_empty_border']}; border-radius:10px; }}"
        self.setStyleSheet(ss)

    def dragEnterEvent(self, ev):
        if not self._active: return ev.ignore()
        if ev.mimeData().hasFormat(MIME_TOKEN):
            tok = ev.mimeData().data(MIME_TOKEN).data().decode()
            if not self._accept or tok in self._accept:
                self._hovering = True; self._restyle(); return ev.acceptProposedAction()
        ev.ignore()
    def dragLeaveEvent(self, _): self._hovering = False; self._restyle()
    def dropEvent(self, ev):
        self._hovering = False; self._restyle()
        if ev.mimeData().hasFormat(MIME_TOKEN):
            self.dropped.emit(ev.mimeData().data(MIME_TOKEN).data().decode()); ev.acceptProposedAction()


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

        # Content — two drop zones
        content = QtWidgets.QWidget(); content.setStyleSheet(f"background-color:{pal['content_bg']};")
        cl = QtWidgets.QVBoxLayout(content); cl.setContentsMargins(8, 10, 8, 10); cl.setSpacing(8)

        # Top drop zone — RED — Server → Vehicle (accepts server_keys)
        pal_a = _PALETTES["A"]
        self.drop_server_to_vehicle = _DropZone(pal_a)
        self.drop_server_to_vehicle.setMinimumHeight(60)
        self.drop_server_to_vehicle.setMaximumHeight(16777215)
        self.drop_server_to_vehicle.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        cl.addWidget(self.drop_server_to_vehicle, 1)

        # Bottom drop zone — BLUE — Vehicle → Server (accepts client_bundle)
        pal_b = _PALETTES["B"]
        self.drop_vehicle_to_server = _DropZone(pal_b)
        self.drop_vehicle_to_server.setMinimumHeight(60)
        self.drop_vehicle_to_server.setMaximumHeight(16777215)
        self.drop_vehicle_to_server.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        cl.addWidget(self.drop_vehicle_to_server, 1)

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
# _CableConnector — kept from original
# ═══════════════════════════════════════════════════════════════════

class _CableConnector(QtWidgets.QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAttribute(QtCore.Qt.WA_TransparentForMouseEvents)
        self.setAttribute(QtCore.Qt.WA_TranslucentBackground)
    def resizeEvent(self, event):
        if self.parent(): self.setGeometry(self.parent().rect())
        super().resizeEvent(event)
    def paintEvent(self, event):
        pass


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
        self.setWindowTitle("Secret Message")
        self.setWindowFlags(QtCore.Qt.Dialog | QtCore.Qt.FramelessWindowHint)
        self.setAttribute(QtCore.Qt.WA_TranslucentBackground)
        self.setFixedSize(540, 240)
        self.setModal(True)

        # Outer frame handles the rounded border + background
        self._frame = QtWidgets.QFrame(self)
        self._frame.setGeometry(10, 10, 520, 220)
        self._frame.setStyleSheet(
            "QFrame { background-color:#0d0d0d; border:2px solid #eb0a1e; border-radius:12px; }"
        )
        shadow = QtWidgets.QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(20); shadow.setOffset(0, 4)
        shadow.setColor(QtGui.QColor(0, 0, 0, 180))
        self._frame.setGraphicsEffect(shadow)

        lay = QtWidgets.QVBoxLayout(self._frame)
        lay.setContentsMargins(28, 24, 28, 24); lay.setSpacing(14)

        title = QtWidgets.QLabel("\U0001f510  Think of a secret message")
        title.setStyleSheet("color:#ffffff; font-size:16px; font-weight:bold; background:transparent;")
        lay.addWidget(title)

        sub = QtWidgets.QLabel(
            "This plaintext will be encrypted with the hybrid PQC key\n"
            "derived from ECDH \u00d7 Kyber-768 and sent to the server."
        )
        sub.setWordWrap(True)
        sub.setStyleSheet("color:#888888; font-size:11px; background:transparent;")
        lay.addWidget(sub)

        self._input = QtWidgets.QLineEdit("Hello from Vehicle \u2014 PQC secured!")
        self._input.setFixedHeight(38)
        self._input.setStyleSheet(
            "QLineEdit { background:#1a1a1a; border:2px solid #58595b; border-radius:8px;"
            "  color:#ffffff; font-size:14px; padding:4px 12px; font-family:'Consolas',monospace; }"
            "QLineEdit:focus { border-color:#eb0a1e; background:#1f1215; }"
        )
        self._input.selectAll()
        self._input.returnPressed.connect(self.accept)
        lay.addWidget(self._input)

        btn_row = QtWidgets.QHBoxLayout(); btn_row.addStretch()
        cancel = QtWidgets.QPushButton("Cancel")
        cancel.setFixedHeight(34); cancel.setCursor(QtCore.Qt.PointingHandCursor)
        cancel.setStyleSheet(
            "QPushButton { background:#1a1a1a; border:1px solid #58595b; border-radius:6px;"
            "  color:#e0e0e0; font-size:11px; padding:0 20px; }"
            "QPushButton:hover { background:#252525; }"
        )
        cancel.clicked.connect(self.reject)

        ok = QtWidgets.QPushButton("Encrypt & Send  \u25b6")
        ok.setFixedHeight(34); ok.setCursor(QtCore.Qt.PointingHandCursor)
        ok.setStyleSheet(
            "QPushButton { background:qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            "  stop:0 #c40918, stop:1 #eb0a1e); border:none; border-radius:6px;"
            "  color:white; font-size:11px; font-weight:bold; padding:0 24px; }"
            "QPushButton:hover { background:qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            "  stop:0 #d60b1f, stop:1 #ff0d24); }"
        )
        ok.clicked.connect(self.accept)

        btn_row.addWidget(cancel); btn_row.addSpacing(8); btn_row.addWidget(ok)
        lay.addLayout(btn_row)

    def get_message(self) -> str:
        return self._input.text().strip()


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

        # Status bar
        status_bar = QtWidgets.QWidget()
        status_bar.setStyleSheet(f"QWidget{{ background-color:{pal['status_bg']}; border-radius:8px; border:1px solid {pal['status_border']}; }}")
        sl = QtWidgets.QHBoxLayout(status_bar); sl.setContentsMargins(15, 10, 15, 10)
        self._status_label = QtWidgets.QLabel("● IDLE")
        self._status_label.setStyleSheet(f"color:{pal['read_muted_text']}; font-weight:bold; font-size:11px; background:transparent;")
        self._phase_label = QtWidgets.QLabel("")
        self._phase_label.setStyleSheet(f"color:{pal['counter_color']}; font-size:11px; background:transparent;")
        sl.addWidget(self._status_label); sl.addStretch(); sl.addWidget(self._phase_label)
        cl.addWidget(status_bar)

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

        # BUNDLE section (packet panel only)
        self._packet_panel = _PacketPanel(pal)
        bundle_section = QtWidgets.QWidget()
        bundle_section.setStyleSheet(f"QWidget{{ background-color:{pal['section_bg']}; border:none; }}")
        bl = QtWidgets.QVBoxLayout(bundle_section); bl.setContentsMargins(20, 12, 20, 20); bl.setSpacing(8)
        bt = QtWidgets.QLabel("BUNDLE")
        bt.setStyleSheet(f"color:{pal['section_title']}; font-size:10px; font-weight:bold; background:transparent; letter-spacing:1px; border:none;")
        bl.addWidget(bt)
        bl.addWidget(self._packet_panel)
        bundle_section.setSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Maximum)
        self._bundle_section = bundle_section

        # EXCHANGE section (Vehicle only — drop zone + message input)
        if is_vehicle:
            ex_section = QtWidgets.QWidget()
            ex_section.setStyleSheet(f"QWidget{{ background-color:{pal['section_bg']}; border:none; }}")
            el = QtWidgets.QVBoxLayout(ex_section); el.setContentsMargins(20, 12, 20, 20); el.setSpacing(10)
            et = QtWidgets.QLabel("EXCHANGE")
            et.setStyleSheet(f"color:{pal['section_title']}; font-size:10px; font-weight:bold; background:transparent; letter-spacing:1px; border:none;")
            el.addWidget(et)

            # Interactive widget — plaintext input
            self._interactive_widget = QtWidgets.QWidget()
            il = QtWidgets.QVBoxLayout(self._interactive_widget); il.setContentsMargins(0,0,0,0); il.setSpacing(8)
            msg_row = QtWidgets.QHBoxLayout(); msg_row.setSpacing(6)
            self._message_input = QtWidgets.QLineEdit("Hello from Vehicle — PQC secured!")
            self._message_input.setFixedHeight(28)
            self._message_input.setStyleSheet(f"QLineEdit{{ background:{pal['input_bg']}; border:1px solid {pal['input_border']}; border-radius:6px; color:{pal['input_text']}; font-size:12px; padding:0 8px; }} QLineEdit:focus{{ border-color:{pal['input_focus_border']}; background:{pal['input_focus_bg']}; }}")
            self._message_input.setPlaceholderText("Plaintext message to encrypt…")
            msg_row.addWidget(self._message_input)
            il.addLayout(msg_row)

            # Autonomous widget — message input
            self._autonomous_widget = QtWidgets.QWidget()
            al = QtWidgets.QVBoxLayout(self._autonomous_widget); al.setContentsMargins(0,0,0,0); al.setSpacing(8)
            self._auto_msg_input = QtWidgets.QLineEdit("Hello from Vehicle — PQC secured!")
            self._auto_msg_input.setFixedHeight(28)
            self._auto_msg_input.setStyleSheet(f"QLineEdit{{ background:{pal['input_bg']}; border:1px solid {pal['input_border']}; border-radius:6px; color:{pal['input_text']}; font-size:12px; padding:0 8px; }} QLineEdit:focus{{ border-color:{pal['input_focus_border']}; background:{pal['input_focus_bg']}; }}")
            self._auto_msg_input.setPlaceholderText("Plaintext message to encrypt…")
            al.addWidget(self._auto_msg_input)
            self._metrics_label = QtWidgets.QLabel("Ready")
            self._metrics_label.setStyleSheet(f"color:{pal['counter_color']}; font-size:10px; background:transparent;")
            self._metrics_label.setAlignment(QtCore.Qt.AlignCenter)
            al.addWidget(self._metrics_label)

            self._mode_stack = QtWidgets.QStackedWidget()
            self._mode_stack.addWidget(self._interactive_widget)
            self._mode_stack.addWidget(self._autonomous_widget)
            self._mode_stack.setCurrentIndex(0)
            el.addWidget(self._mode_stack)
            ex_section.setSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Maximum)
            self._bottom_section = ex_section
            # Vehicle: exchange → key material → bundle (above logs)
            cl.addWidget(ex_section)
            cl.addWidget(key_section)
            cl.addWidget(bundle_section)
        else:
            # Server: bundle (top) → key material
            self._message_input = None
            cl.addWidget(bundle_section)
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
        if not is_vehicle:
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

    def set_keys(self, entries: list[KeyEntry]):
        self._key_display.set_entries(entries)

    def set_draggable(self, token_type: str):
        self._key_display.set_draggable(token_type)

    def set_packet(self, title: str, token_type: str, items: list):
        self._packet_panel.set_packet(title, token_type, items)

    def clear_packet(self):
        self._packet_panel.clear_packet()

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
        if hasattr(self, '_dec_display'):
            self._dec_display.clear()
            self._dec_display.setStyleSheet(f"QTextEdit{{ background-color:{self._palette['read_bg']}; border:2px solid {self._palette['read_border']}; border-radius:8px; padding:10px; color:#4caf50; font-size:13px; font-family:'Consolas','Monaco',monospace; }}")

    def _switch_to_autonomous(self):
        if hasattr(self, '_mode_stack'): self._mode_stack.setCurrentIndex(1)

    def _switch_to_interactive(self):
        if hasattr(self, '_mode_stack'):
            self._mode_stack.setCurrentIndex(0)
            if hasattr(self, '_auto_button') and self._auto_button.isChecked():
                self._auto_button.setChecked(False); self._auto_button.setText("▶  START")


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

        bl.addWidget(title); bl.addStretch(); bl.addWidget(version); bl.addSpacing(10)
        bl.addWidget(legend); bl.addSpacing(10)
        bl.addWidget(self._clear_logs_btn); bl.addSpacing(8); bl.addWidget(self._reset_btn); bl.addSpacing(8)
        bl.addWidget(self._delay_label); bl.addSpacing(4); bl.addWidget(self._delay_spin); bl.addSpacing(4)
        bl.addWidget(self._auto_start_btn); bl.addSpacing(8)
        bl.addWidget(mc); bl.addSpacing(12); bl.addWidget(self._hamburger_btn)
        main_layout.addWidget(banner)

        # ── Panels (Server | Broker | Vehicle) ────────────────
        self.panelA = BoardPanel("A"); self.panelB = BoardPanel("B")
        self.broker = BrokerPanel()

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

        # Bottom row: Server log | Broker log | Vehicle log
        bottom_row = QtWidgets.QWidget()
        bottom_row.setStyleSheet("background-color:#0a0a0a;")
        bl_row = QtWidgets.QHBoxLayout(bottom_row)
        bl_row.setContentsMargins(0, 0, 0, 0); bl_row.setSpacing(1)
        bl_row.addWidget(log_b, 5)
        bl_row.addWidget(log_broker, 2)
        bl_row.addWidget(log_a, 5)

        # Single vertical splitter keeps all logs aligned
        splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)
        splitter.setStyleSheet("QSplitter::handle { background:#1a1a1a; height:2px; }")
        splitter.addWidget(top_row)
        splitter.addWidget(bottom_row)
        splitter.setStretchFactor(0, 4)
        splitter.setStretchFactor(1, 1)

        # Outer wrapper
        outer = QtWidgets.QWidget()
        outer_l = QtWidgets.QHBoxLayout(outer); outer_l.setContentsMargins(0,0,0,0); outer_l.setSpacing(0)
        outer_l.addWidget(splitter)

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
        self._pending_message = ""  # message from popup, consumed by _advance_to_client
        self._process_retry_timer: QtCore.QTimer | None = None
        self._process_retry_count = 0
        self._next_retry_timer: QtCore.QTimer | None = None
        self._next_retry_count = 0

        # ── Staged reveal: queue JSON events, pop one at a time ──
        self._event_queue: list[tuple[str, dict]] = []   # ("server"|"client", evt)
        self._reveal_timer = QtCore.QTimer(self)
        self._reveal_timer.setSingleShot(True)
        self._reveal_timer.timeout.connect(self._reveal_next_event)

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
            self.panelB.log_step(f"ECDH Keygen ({t:.3f} ms)", CLR_ECDH)
            self.panelB.log_val("s_ecdh_pk", pk, CLR_ECDH)
            self._refresh()

        elif event == "kyber_pk_loaded":
            pk = evt.get("pk", "")
            p.s_kyber_pk = pk
            self.panelB.log_step("Static Kyber-768 keypair loaded", CLR_KYBER)
            self.panelB.log_val("s_kyber_pk", pk, CLR_KYBER)
            self._refresh()

        elif event == "keys_sent":
            self.panelB.log_step("Public keys sent to client", CLR_ECDH)
            self.panelB.set_phase("Keys sent")

        elif event == "client_data_received":
            c_pk = evt.get("ecdh_pk", "")
            ct = evt.get("kyber_ct", "")
            p.c_ecdh_pk = c_pk
            p.kyber_ct = ct
            self.panelB.log_step("Received client bundle", CLR_ECDH)
            self.panelB.log_val("c_ecdh_pk", c_pk, CLR_ECDH)
            self.panelB.log_val("kyber_ct", ct, CLR_KYBER)
            self._refresh()

        elif event == "ecdh_derive":
            self._server_processing_started = True
            self._stop_process_retry()
            ss = evt.get("shared", "")
            t = evt.get("time_ms", 0)
            p.ecdh_ss_s = ss
            self.panelB.log_step(f"KDF Step-1: ECDH Shared Secret ({t:.3f} ms)", CLR_ECDH)
            self.panelB.log_val("ecdh_shared", ss, CLR_ECDH)
            self._refresh()

        elif event == "kyber_decap":
            self._server_processing_started = True
            ss = evt.get("shared", "")
            t = evt.get("time_ms", 0)
            p.kyber_ss_s = ss
            self.panelB.log_step(f"KDF Step-2: Kyber Decapsulation ({t:.3f} ms)", CLR_KYBER)
            self.panelB.log_val("kyber_ss", ss, CLR_KYBER)
            self._refresh()

        elif event == "hybrid_key":
            key = evt.get("key", "")
            t = evt.get("time_ms", 0)
            p.hybrid_s = key
            self.panelB.log_step(f"Hybrid KDF: BLAKE2b(ecdh || kyber) ({t:.3f} ms)", CLR_HYBRID)
            self.panelB.log_val("hybrid_key", key, CLR_HYBRID)
            self._refresh()

        elif event == "decrypt":
            self._server_processing_started = True
            pt = evt.get("plaintext", "")
            t = evt.get("time_ms", 0)
            p.decrypted = pt
            self.panelB.log_step(f"Decrypt ({t:.3f} ms)", "#4caf50")
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
            self.broker.log_relay("Exchange " + ("✓ SUCCESS" if status == "SUCCESS" else "✗ FAILED"),
                                  "#39ff14" if status == "SUCCESS" else "#ef5350")
            if hasattr(self.panelA, '_metrics_label'):
                self.panelA._metrics_label.setText(f"Exchanges: {self._auto_exchange_count}")
            # Re-enable the auto start button for next run
            self._auto_running = False
            self._auto_start_btn.setEnabled(True)
            self._auto_start_btn.setText("▶  RUN EXCHANGE")
            self._refresh()

        elif event == "phase":
            phase_name = evt.get("phase", "")
            _log_app.info("PHASE event: %s  (current exchange_phase=%s)", phase_name, self._exchange_phase)
            if phase_name == "keys_ready":
                self._stop_next_retry()
                self._server_bundle_ready = False
                self._process_requested = False
                self._server_processing_started = False
                self._exchange_phase = "KEYS_READY"
                self.panelB.set_status("KEYS READY", "#4caf50")
                self.panelB.set_phase("Drag keys to Vehicle →")
                self._refresh()
                if self._is_interactive():
                    # Show message popup as soon as keys are ready
                    QtCore.QTimer.singleShot(300, self._prompt_message)
                elif self._auto_running:
                    delay = int(self._delay_spin.value() * 1000)
                    QtCore.QTimer.singleShot(delay, self._auto_advance_client)
            elif phase_name == "bundle_received":
                self._server_bundle_ready = True
                self.panelB.set_status("BUNDLE RECEIVED", CLR_KYBER)
                if self._process_requested:
                    self._commit_process()
                else:
                    self._exchange_phase = "BUNDLE_READY"
                    self.panelB.set_phase("← Drag bundle to Server")
                    self._refresh()
                    if not self._is_interactive() and self._auto_running:
                        delay = int(self._delay_spin.value() * 1000)
                        QtCore.QTimer.singleShot(delay, self._auto_advance_process)

        elif event == "error":
            self._stop_process_retry()
            self.panelB.log_step(f"Error: {evt.get('msg', '?')}", "#ef5350")
            self.panelB.set_status("ERROR", "#ef5350")

    def _handle_client_event(self, evt):
        """Process one client JSON event."""
        event = evt.get("event", "")
        _log_app.info("CLI_EVT: %s  (phase=%s)", event, self._exchange_phase)
        p = self.proto

        if event == "connected":
            self.panelA.set_status("CONNECTED", "#4caf50")
            self.panelA.log_step(f"Connected to {evt.get('server', '?')}", CLR_ECDH)

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
            self.panelA.log_step(f"Client ECDH Keygen ({t:.3f} ms)", CLR_ECDH)
            self.panelA.log_val("c_ecdh_pk", pk, CLR_ECDH)
            self.panelA.set_status("PROCESSING", CLR_ECDH)
            self._refresh()

        elif event == "ecdh_derive":
            ss = evt.get("shared", "")
            t = evt.get("time_ms", 0)
            p.ecdh_ss_c = ss
            self.panelA.log_step(f"KDF Step-1: ECDH Shared Secret ({t:.3f} ms)", CLR_ECDH)
            self.panelA.log_val("ecdh_shared", ss, CLR_ECDH)
            self._refresh()

        elif event == "kyber_encap":
            ct = evt.get("ct", "")
            ss = evt.get("shared", "")
            t = evt.get("time_ms", 0)
            p.kyber_ct = ct
            p.kyber_ss_c = ss
            self.panelA.log_step(f"KDF Step-2: Kyber Encapsulation ({t:.3f} ms)", CLR_KYBER)
            self.panelA.log_val("kyber_ct", ct, CLR_KYBER)
            self.panelA.log_val("kyber_ss", ss, CLR_KYBER)
            self._refresh()

        elif event == "hybrid_key":
            key = evt.get("key", "")
            t = evt.get("time_ms", 0)
            p.hybrid_c = key
            self.panelA.log_step(f"Hybrid KDF ({t:.3f} ms)", CLR_HYBRID)
            self.panelA.log_val("hybrid_key", key, CLR_HYBRID)
            self._refresh()

        elif event == "encrypt":
            ct = evt.get("ciphertext", "")
            nonce = evt.get("nonce", "")
            t = evt.get("time_ms", 0)
            p.enc_msg = ct
            p.nonce = nonce
            self.panelA.log_step(f"Encrypt ({t:.3f} ms)", CLR_CIPHER)
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
        return bool(p.kyber_ct and p.nonce and p.enc_msg)

    def _on_vehicle_drop(self, token_type):
        """Server keys dropped on broker top zone → start client."""
        _log_app.info("DROP vehicle: token=%s phase=%s", token_type, self._exchange_phase)
        if token_type == "server_keys" and self._exchange_phase == "KEYS_READY":
            self.broker.log_relay("Server Keys → Vehicle (ECDH PK + Kyber PK)")
            self._advance_to_client()

    def _on_server_drop(self, token_type):
        """Client bundle dropped on broker bottom zone → send PROCESS."""
        _log_app.info("DROP server: token=%s phase=%s bundle_complete=%s",
                     token_type, self._exchange_phase, self._client_bundle_complete())
        if token_type == "client_bundle" and self._client_bundle_complete():
            self.broker.log_relay("Client Bundle → Server (ECDH PK + Kyber CT + Nonce + Enc Msg)")
            self._advance_to_process()

    def _on_token_send(self, token_type):
        """Send button clicked on a token."""
        if token_type == "server_keys" and self._exchange_phase == "KEYS_READY":
            self.broker.log_relay("Server Keys → Vehicle (ECDH PK + Kyber PK)")
            self._advance_to_client()
        elif token_type == "client_bundle" and self._client_bundle_complete():
            self.broker.log_relay("Client Bundle → Server (ECDH PK + Kyber CT + Nonce + Enc Msg)")
            self._advance_to_process()

    def _prompt_message(self):
        """Show message input dialog (interactive mode, called when keys are ready)."""
        if self._exchange_phase != "KEYS_READY" or not self._is_interactive():
            return
        dlg = _MessageDialog(self)
        if dlg.exec() == QtWidgets.QDialog.Accepted:
            msg = dlg.get_message()
            if msg:
                self._pending_message = msg
                self.panelA.log_step(f"Secret message: \"{msg}\"", "#90a4ae")
                self.panelA.set_phase("Message ready \u2014 drag keys to Vehicle")

    def _advance_to_client(self):
        """Start the client on the board."""
        _log_app.info("_advance_to_client: phase=%s", self._exchange_phase)
        msg = ""
        if self._is_interactive():
            # Use message from earlier popup, or prompt now as fallback
            msg = getattr(self, '_pending_message', '')
            if not msg:
                dlg = _MessageDialog(self)
                if dlg.exec() != QtWidgets.QDialog.Accepted:
                    _log_app.info("_advance_to_client: user cancelled message dialog")
                    return
                msg = dlg.get_message()
            self._pending_message = ''  # consume it
        else:
            if hasattr(self.panelA, '_auto_msg_input'):
                msg = self.panelA._auto_msg_input.text().strip()
        if not msg:
            self.panelA.set_status("ERROR", "#ef5350")
            self.panelA.set_phase("Enter a message first!")
            self._exchange_phase = "KEYS_READY"  # stay in this phase
            self._auto_start_btn.setEnabled(True)
            self._auto_start_btn.setText("\u25b6  RUN EXCHANGE")
            return
        self._exchange_phase = "CLIENT_RUNNING"
        self.panelA.set_status("CONNECTING", CLR_ECDH)
        self.panelA.set_phase("Running client on board...")
        self.panelA.log_step(f"Message: \"{msg}\"", "#90a4ae")
        self._refresh()
        if self._live_proto:
            self._live_proto.run_client(msg)

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
            self._advance_to_client()

    def _auto_advance_process(self):
        if self._exchange_phase == "BUNDLE_READY" and not self._is_interactive():
            self._advance_to_process()

    def _live_run_exchange(self):
        """Reset proto & logs, then trigger a real exchange via SSH."""
        if not self._live_proto:
            return
        self.proto.reset()
        self.panelA.clear_log(); self.panelB.clear_log()
        self.panelA.set_status("CONNECTING", CLR_ECDH)
        self.panelB.set_status("LISTENING", CLR_ECDH)
        self._live_proto.run_client()

    # ── actions ───────────────────────────────────────────────

    def _on_reset(self):
        _log_app.info("_on_reset: phase=%s srv_bundle=%s proc_req=%s",
                     self._exchange_phase, self._server_bundle_ready, self._process_requested)
        self._flush_event_queue()
        need_next = (self._exchange_phase == "COMPLETE")
        _log_app.info("_on_reset: need_next=%s", need_next)
        self._stop_process_retry()
        self._stop_next_retry()
        self._server_bundle_ready = False
        self._process_requested = False
        self._server_processing_started = False
        self._pending_message = ""
        # Preserve server keys if they exist and we're not cycling (COMPLETE→NEXT)
        saved_ecdh = self.proto.s_ecdh_pk
        saved_kyber = self.proto.s_kyber_pk
        self.proto.reset()
        if not need_next and saved_ecdh:
            # Server still has these keys — keep them visible
            self.proto.s_ecdh_pk = saved_ecdh
            self.proto.s_kyber_pk = saved_kyber
            self._exchange_phase = "KEYS_READY"
        else:
            self._exchange_phase = "IDLE"
        self.panelA.clear_log(); self.panelB.clear_log()
        self.broker.clear_log()
        self.panelA.set_status("IDLE"); self.panelB.set_status("IDLE" if need_next else "KEYS READY")
        self.panelA.set_phase(""); self.panelB.set_phase("" if need_next else "Drag keys to Vehicle →")
        self._auto_exchange_count = 0
        if hasattr(self.panelA, '_metrics_label'): self.panelA._metrics_label.setText("Ready")
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

    # ── refresh UI ────────────────────────────────────────────

    def _refresh(self):
        p = self.proto
        bundle_complete = self._client_bundle_complete()

        s_keys = []
        if p.s_ecdh_pk: s_keys.append(KeyEntry("ECDH Public Key (X25519)", p.s_ecdh_pk, CLR_ECDH))
        if p.s_kyber_pk: s_keys.append(KeyEntry("Kyber-768 Public Key (static)", p.s_kyber_pk, CLR_KYBER))
        if p.ecdh_ss_s: s_keys.append(KeyEntry("ECDH Shared Secret", p.ecdh_ss_s, CLR_ECDH))
        if p.kyber_ss_s: s_keys.append(KeyEntry("Kyber Shared Secret", p.kyber_ss_s, CLR_KYBER))
        if p.hybrid_s: s_keys.append(KeyEntry("Hybrid Key", p.hybrid_s, CLR_HYBRID))
        self.panelB.set_keys(s_keys)

        v_keys = []
        if p.c_ecdh_pk: v_keys.append(KeyEntry("ECDH Public Key (X25519)", p.c_ecdh_pk, CLR_ECDH))
        if p.ecdh_ss_c: v_keys.append(KeyEntry("ECDH Shared Secret", p.ecdh_ss_c, CLR_ECDH))
        if p.kyber_ct: v_keys.append(KeyEntry("Kyber Ciphertext", p.kyber_ct, CLR_KYBER))
        if p.kyber_ss_c: v_keys.append(KeyEntry("Kyber Shared Secret", p.kyber_ss_c, CLR_KYBER))
        if p.hybrid_c: v_keys.append(KeyEntry("Hybrid Key", p.hybrid_c, CLR_HYBRID))
        self.panelA.set_keys(v_keys)

        # Phase-driven packet panels and drop zones
        phase = self._exchange_phase

        # Server keys packet — show from KEYS_READY onward (non-draggable after send)
        if p.s_ecdh_pk:
            s_items = []
            s_items.append(PacketItem("ECDH Public Key (X25519)", p.s_ecdh_pk, CLR_ECDH, 32))
            if p.s_kyber_pk:
                s_items.append(PacketItem("Kyber-768 Public Key", p.s_kyber_pk, CLR_KYBER, 1184))
            draggable = "server_keys" if phase == "KEYS_READY" else ""
            self.panelB.set_packet("SERVER KEYS", draggable, s_items)
        else:
            self.panelB.clear_packet()

        # Client bundle packet — show from BUNDLE_READY onward (non-draggable after send)
        if p.kyber_ct:
            c_items = []
            if p.c_ecdh_pk:
                c_items.append(PacketItem("Client ECDH PK", p.c_ecdh_pk, CLR_ECDH, 32))
            c_items.append(PacketItem("Kyber Ciphertext", p.kyber_ct, CLR_KYBER, 1088))
            if p.nonce:
                c_items.append(PacketItem("Nonce", p.nonce, CLR_CIPHER, 24))
            if p.enc_msg:
                enc_bytes = len(p.enc_msg) // 2
                c_items.append(PacketItem("Encrypted Message", p.enc_msg, CLR_CIPHER, enc_bytes))
            draggable = "client_bundle" if bundle_complete and phase not in ("PROCESSING", "COMPLETE") else ""
            self.panelA.set_packet("CLIENT BUNDLE", draggable, c_items)
        else:
            self.panelA.clear_packet()

        # Drop zones on broker — only active during the appropriate phase
        if phase == "KEYS_READY" and p.s_ecdh_pk:
            self.broker.drop_server_to_vehicle.activate(True, "⟵ Drop Server Keys\nServer → Vehicle", ["server_keys"])
            self.broker.drop_vehicle_to_server.activate(False)
        elif bundle_complete and phase not in ("PROCESSING", "COMPLETE"):
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
