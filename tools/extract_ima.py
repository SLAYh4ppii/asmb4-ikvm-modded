#!/usr/bin/env python3
"""Extract modules from an AMI $MODULE$ .ima image (ASMB4/AST2050 MegaRAC).

Usage: extract_ima.py <stock.ima> <outdir>

Writes <outdir>/root.cramfs (uImage header stripped) and <outdir>/www.cramfs.
Unpacking the cramfs into real directories happens inside the Docker image
(fsck.cramfs --extract) — see compile.sh.
"""
import sys, struct

# name -> (fmh_offset, region_end) — verified against KCMA8214.ima + flasher binary
MODULES = {
    "boot":    (0x00ff80, 0x040000),
    "params":  (0x040000, 0x140000),
    "root":    (0x140000, 0x690000),
    "osimage": (0x690000, 0x790000),
    "www":     (0x790000, 0x9f0000),
    "ast2100": (0x9f0000, 0xa00000),
}

def fmh_at(img, off):
    h = img[off:off+64]
    assert h[:8] == b"$MODULE$" and h[62:64] == b"\xaa\x55", "bad FMH @%#x" % off
    return h

def data_off(img, fmh_off):
    return fmh_off + struct.unpack_from("<I", img, fmh_off + 36)[0]

def main():
    img = open(sys.argv[1], "rb").read()
    out = sys.argv[2]
    import os; os.makedirs(out, exist_ok=True)
    for name in ("root", "www"):
        fmh_off, _end = MODULES[name]
        doff = data_off(img, fmh_off)
        used = struct.unpack_from("<I", fmh_at(img, fmh_off), 40)[0]
        payload = img[doff:doff+used]
        if name == "root":
            assert payload[:4] == b"\x27\x05\x19\x56", "no uImage magic on root"
            payload = payload[64:]          # strip 64B uImage header
        with open(os.path.join(out, name + ".cramfs"), "wb") as f:
            f.write(payload)
        print("wrote %s/%s.cramfs (%d bytes)" % (out, name, len(payload)))

if __name__ == "__main__":
    main()
