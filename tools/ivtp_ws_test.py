#!/usr/bin/env python3
"""IVTP over WebSocket — full live test through the on-card kvmproxy :5900.
Does: web login -> jnlp token -> WS handshake -> IVTP session -> video frames.
"""
import socket, struct, sys, time, re, base64, os, urllib.request, urllib.parse

BMC = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.160"
USER = "admin"; PW = "password"
WS_PORT = 5900

def web_login():
    data = urllib.parse.urlencode({"WEBVAR_USERNAME": USER, "WEBVAR_PASSWORD": PW}).encode()
    r = urllib.request.urlopen(urllib.request.Request(f"http://{BMC}/rpc/WEBSES/create.asp", data=data), timeout=10).read().decode("latin1")
    m = re.search(r"SESSION_COOKIE' : '([A-Za-z0-9]+)'", r)
    if not m or "Failure" in r: raise SystemExit("web login failed")
    return m.group(1)

def get_jnlp_args(cookie):
    s = socket.create_connection((BMC, 80), timeout=15)
    s.sendall((f"GET /Java/jviewer.jnlp?EXTRNIP={BMC}&JNLPSTR=JViewer HTTP/1.0\r\n"
               f"Host: {BMC}\r\nCookie: SessionCookie={cookie}\r\n"
               f"User-Agent: curl/8.0\r\n\r\n").encode())
    raw = b""
    while True:
        try: c = s.recv(8192)
        except OSError: break
        if not c: break
        raw += c
    s.close()
    return re.findall(r"<argument>([^<]*)</argument>", raw.decode("latin1", "replace"))

class WSSock:
    """Minimal client-side WS over TCP — send masked, recv unmasked binary."""
    def __init__(self, host, port):
        self.s = socket.create_connection((host, port), timeout=15)
        key = base64.b64encode(os.urandom(16)).decode()
        self.s.sendall((f"GET / HTTP/1.1\r\nHost: {host}:{port}\r\n"
                        "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                        f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            c = self.s.recv(4096)
            if not c: raise ConnectionError("handshake eof")
            buf += c
        hdr, _, rest = buf.partition(b"\r\n\r\n")
        if b"101" not in hdr.split(b"\r\n", 1)[0]:
            raise ConnectionError(f"handshake failed: {hdr[:80]}")
        self.buf = rest
        print("[+] WS handshake OK")
    def _fill(self, n):
        while len(self.buf) < n:
            c = self.s.recv(65536)
            if not c: raise ConnectionError("ws eof")
            self.buf += c
    def recvmsg(self):
        """Return next binary message payload."""
        while True:
            self._fill(2)
            b0, b1 = self.buf[0], self.buf[1]
            ln = b1 & 0x7F; o = 2
            if ln == 126:
                self._fill(4); ln = struct.unpack(">H", self.buf[2:4])[0]; o = 4
            elif ln == 127:
                self._fill(10); ln = struct.unpack(">Q", self.buf[2:10])[0]; o = 10
            masked = b1 & 0x80
            if masked: self._fill(o+4); mask = self.buf[o:o+4]; o += 4
            self._fill(o+ln)
            pl = self.buf[o:o+ln]; self.buf = self.buf[o+ln:]
            if masked: pl = bytes(b ^ mask[i & 3] for i, b in enumerate(pl))
            op = b0 & 0x0F
            if op == 0x9:   # ping -> pong
                self.sendmsg(pl, 0xA); continue
            if op == 0x8: raise ConnectionError("ws close")
            if op in (0x2, 0x0): return pl
    def sendmsg(self, data, op=0x2):
        mask = os.urandom(4)
        ln = len(data)
        if ln < 126: h = struct.pack("BB", 0x80 | op, 0x80 | ln)
        elif ln < 65536: h = struct.pack(">BBH", 0x80 | op, 0x80 | 126, ln)
        else: h = struct.pack(">BBQ", 0x80 | op, 0x80 | 127, ln)
        self.s.sendall(h + mask + bytes(b ^ mask[i & 3] for i, b in enumerate(data)))

def hdr(t, size, status=0): return struct.pack("<BIH", t, size, status)

def main():
    ck = web_login(); print(f"[+] web session: {ck}")
    args = get_jnlp_args(ck); print(f"[+] jnlp args: {args}")
    token = args[2] if len(args) > 2 else args[-1]
    webtok = args[3] if len(args) > 3 else "0"

    s = WSSock(BMC, WS_PORT)
    s.sendmsg(hdr(34, 16) + token.encode()[:16].ljust(16, b"\0"))
    s.sendmsg(hdr(52, len(webtok)) + webtok.encode())
    print(f"[+] sent session token + web token via WS")

    stream = bytearray()   # reassemble IVTP byte stream from WS messages
    frame = bytearray(); frames = 0
    t0 = time.time()
    def need(n):
        while len(stream) < n:
            stream.extend(s.recvmsg())
    while True:
        need(7); b = bytes(stream[:7]); del stream[:7]
        ptype, size, status = struct.unpack("<BIH", b)
        if ptype == 5:
            need(2); fragnum = struct.unpack("<H", stream[:2])[0]; del stream[:2]
            need(size - 2); payload = bytes(stream[:size-2]); del stream[:size-2]
            if (fragnum & 0x7FFF) == 0: frame = bytearray()
            frame += payload
            if fragnum & 0x8000:
                frames += 1
                sig = bytes(frame[19:27])
                x, y = struct.unpack("<HH", frame[43:47])
                print(f"*** FRAME {frames}: {len(frame)}B sig={sig} res={x}x{y}")
                if frames == 1: open("frame1_ws.bin", "wb").write(frame)
                if frames >= 3:
                    print("[+] 3 frames over WebSocket — ON-CARD PROXY WORKS")
                    return
        else:
            need(size); ctrl = bytes(stream[:size]); del stream[:size]
            print(f"[ctrl] type={ptype} size={size} status={status}")
            if ptype == 35:
                if ctrl and ctrl[0] == 0: raise SystemExit("session rejected")
                print("[+] session VALID — video config")
                s.sendmsg(hdr(7, 4) + struct.pack("<I", 0xC80000))
                s.sendmsg(hdr(12, 0))
        if time.time() - t0 > 60: print("timeout"); return

if __name__ == "__main__":
    main()
