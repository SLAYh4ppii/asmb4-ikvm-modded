#!/usr/bin/env python3
"""cramfs reader for the ASMB4 firmware images — list + extract files."""
import sys, zlib, struct

class CramFS:
    def __init__(self, data, base=0):
        self.d = data; self.base = base
        sb = data[base:base+64]
        magic, size, flags = struct.unpack_from("<III", sb)
        assert magic == 0x28cd3d45, hex(magic)

    def _inode(self, off):
        abs_off = self.base + off
        mode, uid = struct.unpack_from("<HH", self.d, abs_off)
        size_gid, namelen_off = struct.unpack_from("<II", self.d, abs_off+4)
        size = size_gid & 0xFFFFFF
        namelen = (namelen_off & 0x3F) * 4 + 4          # name len in 4B units, incl NUL pad... (namelen stored -1?)
        boff = namelen_off >> 6
        name_end = self.d.index(b"\0", abs_off+12)
        name = self.d[abs_off+12:name_end].decode("latin1")
        # file data pointer table = boff*4 from fs start
        return mode, size, boff*4, name, abs_off

    def read_file(self, boff, size):
        """decompress all pages of a file"""
        ptr = boff
        out = b""
        pages = (size + 4095) // 4096
        for i in range(pages):
            p = struct.unpack_from("<I", self.d, ptr + i*4)[0]
            if p == 0:
                out += b"\0" * 4096
                continue
            # zlib stream at fs offset p
            try:
                out += zlib.decompressobj().decompress(self.d[p:], 4096+64)
            except zlib.error:
                # some pages are stored raw
                out += self.d[p:p+4096]
        return out[:size]

    def walk(self, off=None, path=""):
        if off is None:
            # root inode inside superblock at +64
            off = 64
        mode, size, boff, name, abs_off = self._inode(off)
        cur = f"{path}/{name}" if path else "/"
        yield cur, mode, size, abs_off
        if stat_isdir(mode):
            # directory entries: inode-size block at boff? For cramfs, dir data = inode list
            ptr = self.base + boff
            end = ptr + size
            i = ptr
            while i < end:
                try:
                    yield from self.walk(i - self.base, cur if cur != "/" else "")
                except Exception:
                    break
                # advance by inode record: 12 + namelen(padded4)
                _, _, _, _, iabs = self._inode(i - self.base)
                nl = self.d.index(b"\0", iabs+12) - (iabs+12)
                i += 12 + ((nl + 1 + 3) & ~3)
        # else regular — no walk

def stat_isdir(mode): return (mode & 0o170000) == 0o040000
def stat_islink(mode): return (mode & 0o170000) == 0o120000

if __name__ == "__main__":
    img = sys.argv[1]; off = int(sys.argv[2], 16)
    d = open(img, "rb").read()
    fs = CramFS(d, off)
    want = sys.argv[3] if len(sys.argv) > 3 else None
    for path, mode, size, abs_off in fs.walk():
        if want and want not in path: continue
        if want and not stat_isdir(mode):
            _,_,boff,name,_ = fs._inode(abs_off)
            data = fs.read_file(boff, size)
            fn = path.strip("/").replace("/", "_")
            open(fn, "wb").write(data)
            print("saved", fn, len(data))
        else:
            print(path, oct(mode), size)
