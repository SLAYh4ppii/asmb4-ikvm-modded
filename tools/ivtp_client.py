#!/usr/bin/env python3
"""IVTP client for ASUS ASMB4 (AMI MegaRAC Aster / AST2050) — stage 1:
connect, session validate, reassemble ASP-2000 video frames.

Protocol (from JViewer.jar decompile):
  TCP 7578, all little-endian.
  Packet = [type:u8][pktSize:u32][status:u16] + payload
  Login:  send type=34 + 16B session token, then type=52 + web token
          server replies type=35 with status byte (0 = valid)
  Video:  type=5 packets; after hdr a u16 fragNum (bit15 = last frag),
          payload = pktSize-2 bytes. Concatenate until last frag -> frame.
  Frame:  VideoHdr(39B: sig "ASP-2000") + ASP2000ImgHdr(84B) + comp data
"""
import socket, struct, sys, time, re, urllib.request, urllib.parse

BMC = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.160"
USER = "admin"; PW = "password"
KVM_PORT = 7578

def web_login():
    data = urllib.parse.urlencode({"WEBVAR_USERNAME": USER, "WEBVAR_PASSWORD": PW}).encode()
    r = urllib.request.urlopen(urllib.request.Request(f"http://{BMC}/rpc/WEBSES/create.asp", data=data), timeout=10).read().decode("latin1")
    m = re.search(r"SESSION_COOKIE' : '([A-Za-z0-9]+)'", r)
    if not m or "Failure" in r:
        raise SystemExit("web login failed")
    return m.group(1)

def get_jnlp_args(cookie):
    url = f"http://{BMC}/Java/jviewer.jnlp?EXTRNIP={BMC}&JNLPSTR=JViewer"
    req = urllib.request.Request(url, headers={"Cookie": f"SessionCookie={cookie}"})
    # GoAhead-Webs (HTTP/1.0) mishandles http.client — use a raw socket
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
    txt = raw.decode("latin1", "replace")
    return re.findall(r"<argument>([^<]*)</argument>", txt)

def recvn(sock, n):
    b = b""
    while len(b) < n:
        c = sock.recv(n - len(b))
        if not c: raise ConnectionError("closed")
        b += c
    return b

def hdr(t, size, status=0):
    return struct.pack("<BIH", t, size, status)

def main():
    ck = web_login(); print(f"[+] web session: {ck}")
    args = get_jnlp_args(ck); print(f"[+] jnlp args: {args}")
    token = args[2] if len(args) > 2 else args[-1]
    webtok = args[3] if len(args) > 3 else "0"

    s = socket.create_connection((BMC, KVM_PORT), timeout=15)
    s.sendall(hdr(34, 16) + token.encode()[:16].ljust(16, b"\0"))   # video session token
    s.sendall(hdr(52, len(webtok)) + webtok.encode())              # web session token
    print(f"[+] sent session token ({token!r}) + web token ({webtok!r})")

    frame = bytearray(); frames = 0
    t0 = time.time()
    while True:
        b = recvn(s, 7)
        ptype, size, status = struct.unpack("<BIH", b)
        if ptype == 5:  # video fragment
            fragnum = struct.unpack("<H", recvn(s, 2))[0]
            payload = recvn(s, size - 2)
            if (fragnum & 0x7FFF) == 0:
                frame = bytearray()
            frame += payload
            if fragnum & 0x8000:
                frames += 1
                sig = bytes(frame[19:27])
                x, y = struct.unpack("<HH", frame[39+4:39+8])
                csize = struct.unpack("<I", frame[39+70:39+74])[0]
                print(f"[frame {frames}] {len(frame)}B sig={sig} res={x}x{y} csize={csize}")
                if frames == 1:
                    open("frame1.bin", "wb").write(frame)
                    print("[+] frame1.bin saved")
                if frames >= 3:
                    print("[+] got 3 frames — protocol works"); return
        else:
            ctrl = recvn(s, size) if size else b""
            print(f"[ctrl] type={ptype} size={size} status={status} data={ctrl[:32]!r}")
            if ptype == 35:  # session validation: 0=INVALID, nonzero=valid
                if ctrl and ctrl[0] == 0:
                    raise SystemExit("session rejected (code=0)")
                print("[+] session VALID — configuring video engine")
                s.sendall(hdr(7, 4) + struct.pack("<I", 0xC80000))   # CfgBandwidth 100Mbps
                s.sendall(hdr(12, 0))                                # REFRESH_VIDEO_SCREEN
        if time.time() - t0 > 60:
            print("timeout"); return

if __name__ == "__main__":
    main()
