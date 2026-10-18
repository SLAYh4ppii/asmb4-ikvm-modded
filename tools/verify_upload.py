#!/usr/bin/env python3
"""Upload .ima to ASMB4 /mnt/rom.ima + run the card's own verifyimage check.
NO FLASH — verification only. Mirrors the stock UI flow:
  WEBSES/create -> setTimeEEPROM -> prepflash -> POST file -> verifyimage
"""
import urllib.request, urllib.parse, re, socket, sys, time

BMC = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.160"
IMG = sys.argv[2] if len(sys.argv) > 2 else "work/KCMA8214_mod.ima"
USER, PW = "admin", "password"

def req(path, data=None, raw=False):
    url = f"http://{BMC}{path}"
    r = urllib.request.Request(url, data=data)
    if CK: r.add_header("Cookie", f"SessionCookie={CK}")
    return urllib.request.urlopen(r, timeout=60).read()

def cookie():
    d = urllib.parse.urlencode({"WEBVAR_USERNAME": USER, "WEBVAR_PASSWORD": PW}).encode()
    t = urllib.request.urlopen(urllib.request.Request(
        f"http://{BMC}/rpc/WEBSES/create.asp", data=d), timeout=15).read().decode("latin1")
    m = re.search(r"SESSION_COOKIE' : '([A-Za-z0-9]+)'", t)
    assert m, "login failed"
    return m.group(1)

CK = cookie()
print("[+] session", CK[:20] + "...")

for step in ("setTimeEEPROM", "prepflash"):
    try:
        r = req(f"/rpc/{step}.asp")
        m = re.search(r"HAPI_STATUS\s*:\s*(-?\d+)", r.decode("latin1", "replace"))
        print(f"[+] {step}: status={m.group(1) if m else r[:120]!r}")
    except Exception as e:
        print(f"[!] {step}: {e}")

img = open(IMG, "rb").read()
print(f"[+] uploading {IMG} ({len(img)} bytes) to /mnt/rom.ima ...")
boundary = b"----ikvmBoundary42"
fname = b"/mnt/rom.ima?12582912"
body = (b"--" + boundary + b'\r\nContent-Disposition: form-data; name="'
        + fname + b'"; filename="fw.ima"\r\nContent-Type: application/octet-stream\r\n\r\n'
        + img + b"\r\n--" + boundary + b"--\r\n")
url = f"http://{BMC}/page/UI_fwverify.html"
r = urllib.request.Request(url, data=body)
r.add_header("Cookie", f"SessionCookie={CK}")
r.add_header("Content-Type", f"multipart/form-data; boundary={boundary.decode()}")
try:
    resp = urllib.request.urlopen(r, timeout=300).read()
    print("[+] upload response:", resp[:400].decode("latin1", "replace"))
except Exception as e:
    print("[!] upload:", e); sys.exit(1)

time.sleep(2)
print("[+] verifyimage ...")
try:
    r = req("/rpc/verifyimage.asp", data=b"")
    print(r.decode("latin1", "replace")[:2000])
except Exception as e:
    print("[!] verify:", e)
