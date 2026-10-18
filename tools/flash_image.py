#!/usr/bin/env python3
"""Flash .ima to ASMB4 over the network — mirrors the stock browser flow exactly.
Raw-socket HTTP/1.0, one request at a time, waits for real responses.

Flow: WEBSES/create -> setTimeEEPROM -> prepflash -> upload -> verifyimage -> startflash

Do NOT interrupt — GoAhead is single-threaded; an aborted request wedges the card.

Usage: flash_image.py <bmc-ip> <image.ima> [port] [--flash]
  port: stock firmware -> 80 ; with the new firmware running -> 8080
  BMC_USER / BMC_PW env vars override the default admin/password login.
"""
import os, re, socket, sys, time

BMC = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.160"
IMG = sys.argv[2] if len(sys.argv) > 2 else "ASMB4_FW214_KCMA-D8/KCMA-D8/KCMA8214.ima"
PORT = int(sys.argv[3]) if len(sys.argv) > 3 and sys.argv[3].isdigit() else 80
DO_FLASH = "--flash" in sys.argv
USER, PW = os.environ.get("BMC_USER", "admin"), os.environ.get("BMC_PW", "password")
CK = None

def http(method, path, body=b"", ctype=None, timeout=120, max_retry=0):
    """One raw HTTP/1.0 request, Connection: close. Returns full response bytes."""
    global CK
    hdr = (f"{method} {path} HTTP/1.0\r\nHost: {BMC}\r\n"
           + (f"Cookie: SessionCookie={CK}\r\n" if CK else "")
           + "User-Agent: Mozilla/4.0 (compatible)\r\nConnection: close\r\n")
    if body:
        hdr += f"Content-Type: {ctype}\r\nContent-Length: {len(body)}\r\n"
    hdr += "\r\n"
    s = socket.create_connection((BMC, PORT), timeout=20)
    s.settimeout(timeout)
    s.sendall(hdr.encode() + body)
    resp = b""
    while True:
        try:
            c = s.recv(65536)
        except socket.timeout:
            s.close()
            raise TimeoutError(f"no response within {timeout}s")
        if not c:
            break
        resp += c
    s.close()
    return resp

def rpc(name, timeout=120):
    return http("GET", f"/rpc/{name}.asp", timeout=timeout)

def hapi(resp):
    m = re.search(rb"HAPI_STATUS\s*:\s*(-?\d+)", resp)
    return int(m.group(1)) if m else None

# --- 0. readiness: card must answer a cheap RPC first -------------------------
print("[0] waiting for web+RPC readiness ...", flush=True)
while True:
    try:
        # login
        b = urllib_body = (f"WEBVAR_USERNAME={USER}&WEBVAR_PASSWORD={PW}").encode()
        r = http("POST", "/rpc/WEBSES/create.asp", b,
                 "application/x-www-form-urlencoded", timeout=30)
        m = re.search(rb"SESSION_COOKIE' : '([A-Za-z0-9]+)'", r)
        if m:
            CK = m.group(1).decode()
            break
    except Exception:
        pass
    time.sleep(10)
print(f"[+] session {CK[:16]}...", flush=True)

# quick sanity — card should answer fast now
r = rpc("getbldtime", 30)
print(f"[+] getbldtime: {r[ :160].decode('latin1','replace').strip()[:120]}", flush=True)

# --- 1. setTimeEEPROM (fire-and-forget; UI ignores its body) -------------------
for attempt in range(3):
    try:
        r = rpc("setTimeEEPROM", 90)
        if b"200" in r.split(b"\r\n", 1)[0]:
            print("[+] setTimeEEPROM answered", flush=True)
            break
    except TimeoutError:
        print(f"    setTimeEEPROM timeout (try {attempt+1})", flush=True)
else:
    sys.exit("[!] setTimeEEPROM never answered — abort")

time.sleep(3)

# --- 2. prepflash — the long one ----------------------------------------------
print("[+] prepflash (can take ~2 min; card stops services) ...", flush=True)
ok = False
try:
    r = rpc("prepflash", 240)
    st = hapi(r)
    print(f"[+] prepflash HAPI_STATUS={st}", flush=True)
    ok = (st == 0)
except TimeoutError:
    # prep may have succeeded but the response got lost — check for the
    # prep-mode signal: adviserd (7578) going away.
    print("    prepflash no response — checking prep-mode signal ...", flush=True)

time.sleep(10)
try:
    s = socket.create_connection((BMC, 7578), timeout=3)
    s.close()
    p7578 = "open"
except Exception:
    p7578 = "closed"
print(f"[i] port 7578 now: {p7578}", flush=True)
if not ok:
    if p7578 == "closed":
        # card is already in upgrade mode (e.g. resumed session) — proceed
        print("[i] prepflash nonzero but card already in upgrade mode — continuing", flush=True)
    else:
        sys.exit("[!] prepflash failed and card not in upgrade mode — abort before upload")

# --- 3. upload ----------------------------------------------------------------
img = open(IMG, "rb").read()
print(f"[+] uploading {len(img)} bytes — single POST, do not interrupt ...", flush=True)
boundary = b"----ikvmBoundary42"
body = (b"--" + boundary + b'\r\nContent-Disposition: form-data; name="'
        + b"/mnt/rom.ima?12582912" + b'"; filename="fw.ima"\r\n'
        + b"Content-Type: application/octet-stream\r\n\r\n"
        + img + b"\r\n--" + boundary + b"--\r\n")
try:
    r = http("POST", "/page/UI_fwverify.html", body,
             f"multipart/form-data; boundary={boundary.decode()}", timeout=600)
    print(f"[+] upload answered ({len(r)} bytes) — verify page reached", flush=True)
except TimeoutError as e:
    sys.exit(f"[!] upload timed out: {e} — card may be busy; check state before retry")

# --- 4. verifyimage — poll until HAPI_STATUS -----------------------------------
print("[+] verifyimage — CRC of 10 MiB on ARMv5, takes several minutes ...", flush=True)
result = None
deadline = time.time() + 1200
while time.time() < deadline:
    try:
        r = rpc("verifyimage", 180)
        st = hapi(r)
        if st is not None:
            result = r
            break
    except Exception:
        pass
    print("    ... still verifying", flush=True)
    time.sleep(15)

if result is None:
    sys.exit("[!] no verify response in 20 min — card likely busy/rebooting; check manually")

txt = result.decode("latin1", "replace")
print(txt[:1500], flush=True)
st = hapi(result)
if st != 0:
    sys.exit(f"[!] verifyimage HAPI_STATUS={st} — image REJECTED, nothing written")

name = re.search(r"NEWIMGNAME'?\s*:\s*'([^']*)'", txt)
cver = re.search(r"CURIMGVERSION'?\s*:\s*'([^']*)'", txt)
nver = re.search(r"NEWIMGVERSION'?\s*:\s*'([^']*)'", txt)
print(f"[+] VERIFIED: {name and name.group(1)} cur={cver and cver.group(1)} "
      f"new={nver and nver.group(1)}", flush=True)

if not DO_FLASH:
    print("[=] dry-run ok — image accepted. Re-run with --flash to write.", flush=True)
    sys.exit(0)

# --- 5. startflash --------------------------------------------------------------
print("[+] startflash PRESERVECFG=1 — WRITING TO FLASH ...", flush=True)
try:
    r = http("GET", "/rpc/startflash.asp?WEBVAR_PRESERVECFG=1", timeout=120)
    print(f"[+] startflash: {r[:160]}", flush=True)
except TimeoutError:
    print("    startflash no answer — flash may still run; polling status", flush=True)

for i in range(60):
    time.sleep(15)
    try:
        r = rpc("flashstatus", 15).decode("latin1", "replace")
        print(f"    flashstatus: {r.strip()[:140]}", flush=True)
        if re.search(r"100|COMPLETE|DONE", r, re.I):
            break
    except Exception:
        print("    ... (web busy — probably writing or rebooting)", flush=True)

print("[+] waiting for BMC to come back ...", flush=True)
for i in range(40):
    try:
        s = socket.create_connection((BMC, PORT), timeout=4)
        s.close()
        print(f"[+] BMC web port back after ~{i*15}s", flush=True)
        break
    except Exception:
        time.sleep(15)
