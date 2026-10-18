#!/usr/bin/env python3
"""Repack AMI $MODULE$ .ima image (ASMB4/AST2050 MegaRAC).

FMH fields (verified against flasher binary + KCMA8214.ima):
  +0x00 "$MODULE$"        +0x0C region size    +0x10 own offset
  +0x18 name              +0x24 data-off delta (data_off = fmh + field36)
  +0x28 used/payload size (includes any sub-header, e.g. uImage hdr for root)
  +0x32 payload CRC32 over [data_off, +used]  (zlib.crc32)
  +0x3E "\xAA\x55"        +0x17 sum byte -> 64B header sums to 0 mod 256

Module data offsets (from field36 in the stock image):
  boot fmh@0xff80 mid-region | params fmh+0x10000 | root fmh+0x10000 (uImage+cramfs)
  osimage fmh+0x40 | www fmh+0x10000 | ast2100 fmh+0x40

root payload is a uImage: 64B mkimage header (magic 0x27051956, BE fields,
size@+12, dataCRC@+24, headerCRC@+4) followed by cramfs.
"""
import zlib, struct, sys

IMG = sys.argv[1]           # stock image to patch
OUT = sys.argv[2]           # output path

# name -> (fmh_offset, region_end)
MODULES = {
    "boot":    (0x00ff80, 0x040000),
    "params":  (0x040000, 0x140000),
    "root":    (0x140000, 0x690000),
    "osimage": (0x690000, 0x790000),
    "www":     (0x790000, 0x9f0000),
    "ast2100": (0x9f0000, 0xa00000),
}

def fmh_at(img, off):
    h = bytearray(img[off:off+64])
    assert h[:8] == b"$MODULE$" and h[62:64] == b"\xaa\x55", "bad FMH @%#x" % off
    return h

def data_off(img, fmh_off):
    return fmh_off + struct.unpack_from("<I", img, fmh_off + 36)[0]

def fix_fmh(h):
    h[23] = 0
    h[23] = (-sum(h)) & 0xff
    assert sum(h) & 0xff == 0

def uimage_header(orig_hdr, data):
    """Patch the 64B uImage header for new payload: size, data CRC, header CRC (all BE)."""
    h = bytearray(orig_hdr)
    assert h[:4] == b"\x27\x05\x19\x56", "no uImage magic"
    struct.pack_into(">I", h, 12, len(data))                    # data size
    struct.pack_into(">I", h, 24, zlib.crc32(data) & 0xffffffff)  # data crc
    struct.pack_into(">I", h, 4, 0)
    struct.pack_into(">I", h, 4, zlib.crc32(bytes(h)) & 0xffffffff)  # header crc
    return bytes(h)

def patch_module(img, name, payload, uimage=False):
    fmh_off, region_end = MODULES[name]
    doff = data_off(img, fmh_off)
    if uimage:
        orig_hdr = img[doff:doff+64]
        payload = uimage_header(orig_hdr, payload) + payload
    h = fmh_at(img, fmh_off)
    cap = region_end - doff
    assert len(payload) <= cap, "%s payload %#x > cap %#x" % (name, len(payload), cap)
    img[doff:doff+len(payload)] = payload
    img[doff+len(payload):region_end] = b"\xff" * (cap - len(payload))
    struct.pack_into("<I", h, 40, len(payload))
    struct.pack_into("<I", h, 50, zlib.crc32(payload) & 0xffffffff)
    fix_fmh(h)
    img[fmh_off:fmh_off+64] = bytes(h)
    print("patched %-8s off=%#x used=%#x crc=%#010x"
          % (name, doff, len(payload), zlib.crc32(payload) & 0xffffffff))

def fix_image_checksum(img):
    """The last FMH (ast2100) stores the whole-image CRC32 at +50:
    crc over image[0..file_end], skipping ITS OWN header bytes 23 & 50-53.
    Must be recomputed after ANY content change — this is the 'Img chksum'
    the flasher's VerifyImageIntegrity compares."""
    fmh_off = MODULES["ast2100"][0]
    c = 0
    for i in range(len(img)):
        rel = i - fmh_off
        if rel in (23, 50, 51, 52, 53):
            continue
        c = zlib.crc32(bytes((img[i],)), c)
    img[fmh_off+50:fmh_off+54] = struct.pack("<I", c & 0xffffffff)
    h = fmh_at(img, fmh_off)
    fix_fmh(h)
    img[fmh_off:fmh_off+64] = bytes(h)
    print("image checksum -> %#010x (ast2100 fmh updated)" % (c & 0xffffffff))

def main():
    img = bytearray(open(IMG, "rb").read())
    args = sys.argv[3:]
    i = 0
    while i < len(args):
        if args[i] == "--module":
            name, fn = args[i+1], args[i+2]
            patch_module(img, name, open(fn, "rb").read(), uimage=(name == "root"))
            i += 3
        else:
            i += 1
    fix_image_checksum(img)
    open(OUT, "wb").write(bytes(img))
    print("wrote %s (%d bytes)" % (OUT, len(img)))

if __name__ == "__main__":
    main()
