#!/usr/bin/env python3
"""Minimal RMCP+ (IPMI 2.0 over LAN) client — integrity-only (HMAC-SHA1-96),
NO AES. For the C port into bmcweb on the ASMB4 card (127.0.0.1:623)."""
import socket, struct, hmac, hashlib, os, sys

BMC = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.160"
USER = "admin"; PWD = b"password"
PRIV = 4

def hmac_sha1(key, data): return hmac.new(key, data, hashlib.sha1).digest()

class RMCP:
    def __init__(self, host):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.settimeout(3); self.host = host
        self.localsid = struct.unpack("<I", os.urandom(4))[0]
        self.tag = 0; self.seq = 0; self.rqseq = 1

    def tx(self, raw, expect=True):
        self.s.sendto(raw, (self.host, 623))
        for _ in range(3):
            try: d, _ = self.s.recvfrom(2048)
            except socket.timeout:
                self.s.sendto(raw, (self.host, 623)); continue
            if d[:4] == b"\x06\x00\xff\x06" or d[3] in (6, 7):
                return d
        raise IOError("no reply")

    def open(self, conf_alg=0):
        self.tag += 1
        p = bytes([self.tag, 0, 0, 0]) + struct.pack("<I", self.localsid)
        p += bytes([0,0,0,8,1,0,0,0, 1,0,0,8,1,0,0,0, 2,0,0,8,conf_alg,0,0,0])
        d = self.tx(b'\x06\x00\xff\x07'+bytes([6,0x10])+struct.pack("<I",0)+struct.pack("<I",0)+struct.pack("<H",len(p))+p)
        if d[4] != 6 or (d[5] & 0x3f) != 0x11: raise IOError("bad open rsp")
        plen=struct.unpack("<H",d[14:16])[0];pl = d[16:16+plen]
        assert pl[1] == 0, f"open status {pl[1]}"
        self.mgmtsid = struct.unpack("<I", pl[8:12])[0]
        self.confalg = pl[12+8+8+4]
        return self.mgmtsid

    def rakp1(self):
        self.tag += 1
        self.crand = os.urandom(16)
        uid = USER.encode()
        p = bytes([self.tag,0,0,0]) + struct.pack("<I", self.mgmtsid) + self.crand \
            + bytes([PRIV,0,0,len(uid)]) + uid
        d = self.tx(b'\x06\x00\xff\x07'+bytes([6,0x12])+struct.pack("<I",self.mgmtsid)+struct.pack("<I",0)+struct.pack("<H",len(p))+p)
        plen=struct.unpack("<H",d[14:16])[0];pl = d[16:16+plen]
        assert pl[0] == self.tag and pl[1] == 0, f"rakp2 status {pl[1]}"
        assert struct.unpack("<I", pl[4:8])[0] == self.localsid
        self.brand = pl[8:24]; self.guid = pl[24:40]
        uid = USER.encode()
        exp = hmac_sha1(PWD, struct.pack("<II", self.localsid, self.mgmtsid)
                        + self.crand + self.brand + self.guid
                        + bytes([PRIV, len(uid)]) + uid)
        assert exp == pl[40:40+20], "RAKP2 auth fail (password?)"
        self.sik = hmac_sha1(PWD, self.crand + self.brand + bytes([PRIV, len(uid)]) + uid)
        self.k1 = hmac_sha1(self.sik, b"\x01"*20)
        self.rakp2 = pl

    def rakp3(self):
        self.tag += 1
        uid = USER.encode()
        auth = hmac_sha1(PWD, self.brand + struct.pack("<I", self.localsid)
                         + bytes([PRIV, len(uid)]) + uid)
        p = bytes([self.tag,0,0,0]) + struct.pack("<I", self.mgmtsid) + auth
        d = self.tx(b'\x06\x00\xff\x07'+bytes([6,0x14])+struct.pack("<I",self.mgmtsid)+struct.pack("<I",0)+struct.pack("<H",len(p))+p)
        plen=struct.unpack("<H",d[14:16])[0];pl = d[16:16+plen]
        assert pl[0] == self.tag and pl[1] == 0, f"rakp4 status {pl[1]}"
        exp = hmac_sha1(self.sik, self.crand + struct.pack("<I", self.mgmtsid) + self.guid)[:12]
        assert exp == pl[8:20], "RAKP4 integ fail"

    def ipmi(self, netfn, cmd, data=b"", timeout=3):
        """send an in-session IPMI request; returns response data bytes."""
        rq = bytes([0x20, netfn << 2])
        rq += bytes([(256 - sum(rq) & 0xff) & 0xff])
        rq += bytes([0x81, self.rqseq << 2, cmd]) + data
        rq += bytes([(256 - sum(rq[3:]) & 0xff) & 0xff])
        self.rqseq = (self.rqseq + 1) & 0x3f
        self.seq += 1
        msg = bytearray(b'\x06\x00\xff\x07' + bytes([6, 0x40])
                        + struct.pack("<I", self.mgmtsid) + struct.pack("<I", self.seq)
                        + struct.pack("<H", len(rq)) + rq)
        np = (len(msg) - 2) % 4
        if np: np = 4 - np
        msg += b'\xff' * np + bytes([np, 7])
        msg += hmac_sha1(self.k1, bytes(msg[4:]))[:12]
        d = self.tx(bytes(msg))
        ptype = d[5] & 0x3f
        assert ptype == 0, f"unexpected payload type {ptype}"
        plen = struct.unpack("<H", d[14:16])[0]
        pl = d[16:16+plen]
        end = len(d) - 12
        trailer = d[end:]
        exp = hmac_sha1(self.k1, d[4:end])[:12]
        assert exp == trailer, "integrity mismatch"
        # ipmi msg: rsAddr,netfn,chk, rqAddr,seq,cmd,cc,data...,chk2
        assert pl[0] == 0x81
        assert pl[6] == 0 or pl[6] in range(0,256)  # cc any
        if pl[6] != 0: raise IOError(f"cmd {cmd:#x} cc={pl[6]:#x}")
        return pl[7:-1]

    def close(self):
        self.ipmi(6, 0x3c, struct.pack("<I", self.mgmtsid))

if __name__=="__main__":
  r = RMCP(BMC)
  sid = r.open(conf_alg=0)
  print(f"[+] open ok conf=NONE mgmtsid={sid:#x}")
  r.rakp1(); print("[+] RAKP2 verified, SIK/K1 derived")
  r.rakp3(); print("[+] RAKP4 verified — SESSION UP")
  
  d = r.ipmi(6, 0x01)  # Get Device ID
  print(f"[+] DeviceID: fw={d[2]}.{d[3]} ipmi={d[4]&0xf}.{d[4]>>4} mfg={d[6]|d[7]<<8|d[8]<<16:#x}")
  # SDR walk: repo info -> reserve -> get sdr by id, follow next-id
  d = r.ipmi(0x0a, 0x20)  # Get SDR Repository Info
  nrec = d[12] | d[13] << 8
  print(f"[+] SDR repo: recs={nrec}")
  recid, cnt = 0, 0
  while recid != 0xffff and cnt < 64:
      rsv = r.ipmi(0x0a, 0x22)  # Reserve SDR Repository
      resid = rsv[0] | rsv[1] << 8
      d = r.ipmi(0x0a, 0x23, struct.pack("<HHBB", resid, recid, 0, 64))  # Get SDR
      nxt = d[0] | d[1] << 8
      rec = d[2:]
      rid = rec[0] | rec[1] << 8; rtype = rec[4]
      name = ""
      if rtype == 1 and len(rec) > 48:
          nl = rec[47] & 0x3f
          name = rec[48:48+nl].decode('latin1')
      elif rtype == 2 and len(rec) > 32:
          nl = rec[31] & 0x3f
          name = rec[32:32+nl].decode('latin1')
      snr = rec[7] if len(rec) > 7 else ord('?')
      print(f"    sdr #{rid} type={rtype} snr={rec[5] if len(rec)>5 else '?'} '{name}'")
      recid = nxt; cnt += 1
  d = r.ipmi(0x04, 0x2d, bytes([0x01]))  # Get Sensor Reading
  print(f"[+] sensor1: {d.hex()}")
  d = r.ipmi(0, 0x01)  # Get Chassis Status
  print(f"[+] chassis: power={'ON' if d[0]&1 else 'OFF'} raw={d.hex()}")
  r.ipmi(0, 0x04, bytes([15, 0]))  # Chassis Identify 15s
  print("[+] identify 15s sent")
  d = r.ipmi(0x0a, 0x40)  # Get SEL Info
  print(f"[+] SEL info: entries={d[2]|d[3]<<8}")
  r.close(); print("[+] closed clean")
  