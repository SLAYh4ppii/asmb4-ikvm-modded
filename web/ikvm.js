/* ikvm.js — IVTP KVM client for ASMB4-iKVM (MegaRAC Aster / AST2050).
 *
 * Speaks the 7-byte Aster framing: [type u8][pktSize u32][status u16].
 * Transport = WebSocket -> kvmproxy on the BMC -> TCP:7578 (raw passthrough).
 * Video fragments (type 5) are reassembled into frames:
 *   [VideoHdr 39B: ..."ASP-2000"...][ASP2000ImgHdr 86B][compressed data]
 * which SocVideoDecoder (soc_decoder.js) renders to BGR.
 * Input (type 6) wraps IUSB HID reports for keyboard + absolute mouse.
 */
"use strict";

const IVTP = {
  VIDEO_FRAGMENT: 5, HID_PKT: 6, SET_BANDWIDTH: 7, SET_QUALITY: 8,
  SET_FPS: 10, REFRESH: 12, PAUSE: 13, RESUME: 14, BLANK_SCREEN: 15,
  AUTO_CALIBRATE: 22, STOP_SESSION: 25, GET_USB_MOUSE_MODE: 33,
  VALIDATE_VIDEO: 34, VALIDATE_VIDEO_RESP: 35,
  AST2K_SET_VE: 40, AST2K_GET_VE: 41, SESSION_ACCEPTED: 51,
  WEB_SESSION: 52, KEYBD_LED: 121,
};

function ivtpHdr(type, size, status = 0) {
  const b = new Uint8Array(7);
  b[0] = type;
  b[1] = size & 0xff; b[2] = (size >> 8) & 0xff;
  b[3] = (size >> 16) & 0xff; b[4] = (size >> 24) & 0xff;
  b[5] = status & 0xff; b[6] = (status >> 8) & 0xff;
  return b;
}

/* ---------- IUSB HID reports (Aster layout, type 6) ---------- */
const IUSB_SIG = [73, 85, 83, 66, 32, 32, 32, 32]; // "IUSB    "

let _kbdSeq = 0, _mseSeq = 0;

function iusbChecksum(body /*Uint8Array, IUSB portion*/) {
  let s = 0;
  for (let i = 0; i < 32; i++) s = (s + body[i]) & 0xff;
  return (256 - s) & 0xff; // -sum & 0xff at offset 11 (wire 18)
}

/* 48-byte HID packet: 7B IVTP + 32B IUSB + 1B rptLen + 8B kb report */
function keyboardPacket(hidReport /*Uint8Array(8)*/) {
  const p = new Uint8Array(48);
  p.set(ivtpHdr(IVTP.HID_PKT, 41, 0), 0);
  const u = p.subarray(7);
  u.set(IUSB_SIG, 0);
  u[8] = 1; u[9] = 0; u[10] = 32; u[11] = 0;         // ver, hdrlen, chksum
  u[12] = 9;                                        // dataPacketLen = 9
  u[16] = 0; u[17] = 0x30; u[18] = 0x10; u[19] = 0x80;
  u[20] = 2; u[21] = 0; u[22] = 0; u[23] = 0;
  const sq = _kbdSeq++;
  u[24] = sq & 0xff; u[25] = (sq >> 8) & 0xff;
  u[26] = (sq >> 16) & 0xff; u[27] = (sq >> 24) & 0xff;
  u[32] = 8;                                        // rptLen
  u.set(hidReport, 33);
  u[11] = iusbChecksum(u);                          // sum over bytes 0..31
  return p;
}

/* 45-byte ABS mouse packet: 7B IVTP + 32B IUSB + 1B rptLen + 5B report */
function mousePacket(btn, x, y, w, h) {
  const p = new Uint8Array(45);
  p.set(ivtpHdr(IVTP.HID_PKT, 38, 0), 0);
  const u = p.subarray(7);
  u.set(IUSB_SIG, 0);
  u[8] = 1; u[9] = 0; u[10] = 32; u[11] = 0;
  u[12] = 6;                                        // dataPacketLen = 6
  u[16] = 0; u[17] = 0x31; u[18] = 0x20; u[19] = 0x80;
  u[20] = 2; u[21] = 1; u[22] = 0; u[23] = 0;
  const sq = _mseSeq++;
  u[24] = sq & 0xff; u[25] = (sq >> 8) & 0xff;
  u[26] = (sq >> 16) & 0xff; u[27] = (sq >> 24) & 0xff;
  u[32] = 5;                                        // rptLen = 5
  u[33] = btn;
  const xd = Math.round((x * 32767) / w), yd = Math.round((y * 32767) / h);
  u[34] = xd & 0xff; u[35] = (xd >> 8) & 0xff;
  u[36] = yd & 0xff; u[37] = (yd >> 8) & 0xff;
  u[11] = iusbChecksum(u);
  return p;
}

/* ---------- Keymap: KeyboardEvent.code + location -> HID ---------- */
const HID = {
  KeyA:4,KeyB:5,KeyC:6,KeyD:7,KeyE:8,KeyF:9,KeyG:10,KeyH:11,KeyI:12,KeyJ:13,
  KeyK:14,KeyL:15,KeyM:16,KeyN:17,KeyO:18,KeyP:19,KeyQ:20,KeyR:21,KeyS:22,
  KeyT:23,KeyU:24,KeyV:25,KeyW:26,KeyX:27,KeyY:28,KeyZ:29,
  Digit1:30,Digit2:31,Digit3:32,Digit4:33,Digit5:34,Digit6:35,Digit7:36,
  Digit8:37,Digit9:38,Digit0:39,
  Enter:40,Escape:41,Backspace:42,Tab:43,Space:44,Minus:45,Equal:46,
  BracketLeft:47,BracketRight:48,Backslash:49,IntlBackslash:50,
  Semicolon:51,Quote:52,Backquote:53,Comma:54,Period:55,Slash:56,
  CapsLock:57,F1:58,F2:59,F3:60,F4:61,F5:62,F6:63,F7:64,F8:65,F9:66,
  F10:67,F11:68,F12:69,PrintScreen:70,ScrollLock:71,Pause:72,
  Insert:73,Home:74,PageUp:75,Delete:76,End:77,PageDown:78,
  ArrowRight:79,ArrowLeft:80,ArrowDown:81,ArrowUp:82,
  NumLock:83,NumpadDivide:84,NumpadMultiply:85,NumpadSubtract:86,
  NumpadAdd:87,NumpadEnter:88,Numpad1:89,Numpad2:90,Numpad3:91,Numpad4:92,
  Numpad5:93,Numpad6:94,Numpad7:95,Numpad8:96,Numpad9:97,Numpad0:98,
  NumpadDecimal:99,IntlYen:135,ContextMenu:118,
  F13:104,F14:105,F15:106,F16:107,F17:108,F18:109,F19:110,F20:111,
  F21:112,F22:113,F23:114,F24:115,
  ControlLeft:224,ShiftLeft:225,AltLeft:226,MetaLeft:227,
  ControlRight:228,ShiftRight:229,AltRight:230,MetaRight:231,
};
const MOD_BIT = { ControlLeft:1,ShiftLeft:2,AltLeft:4,MetaLeft:8,
                  ControlRight:16,ShiftRight:32,AltRight:64,MetaRight:128 };

class KbdState {
  constructor() { this.mods = 0; this.usage = 0; }
  report() {
    const r = new Uint8Array(8);
    r[0] = this.mods; r[2] = this.usage;
    return r;
  }
  onKey(code, down) {
    if (code in MOD_BIT) {
      const bit = MOD_BIT[code];
      this.mods = down ? (this.mods | bit) : (this.mods & ~bit & 0xff);
    } else {
      this.usage = down ? (HID[code] || 0) : 0;
    }
    return this.report();
  }
}

/* ---------- IVTP client over WebSocket ---------- */
class IvKvmClient {
  constructor(opts) {
    this.wsUrl = opts.wsUrl;
    this.onStatus = opts.onStatus || (() => {});
    this.onFrame = opts.onFrame || (() => {});
    this.onBlank = opts.onBlank || (() => {});
    this.onLed = opts.onLed || (() => {});
    this.onStats = opts.onStats || (() => {});
    this.stats = { video: 0, frames: 0, blank: 0, ctrl: {} };
    this.decoder = new SocVideoDecoder();
    this.frag = [];          // frame fragment buffer
    this.rxbuf = new Uint8Array(0);  // raw stream accumulator
    this.kbd = new KbdState();
    this.ws = null; this.open = false;
  }
  connect(token, webToken) {
    const ws = this.ws = new WebSocket(this.wsUrl);
    ws.binaryType = "arraybuffer";
    ws.onopen = () => {
      this.open = true;
      this.onStatus("ws open — authenticating");
      const t = new Uint8Array(16);
      for (let i = 0; i < Math.min(16, token.length); i++) t[i] = token.charCodeAt(i);
      this.send(ivtpHdr(IVTP.VALIDATE_VIDEO, 16), t);            // type 34
      const w = new Uint8Array(webToken.length);
      for (let i = 0; i < webToken.length; i++) w[i] = webToken.charCodeAt(i);
      this.send(ivtpHdr(IVTP.WEB_SESSION, w.length), w);         // type 52
    };
    ws.onmessage = e => this.onData(new Uint8Array(e.data));
    ws.onclose = () => { this.open = false; this.onStatus("disconnected"); };
    ws.onerror = () => this.onStatus("ws error");
  }
  send(...parts) {
    if (!this.open) return;
    for (const p of parts) this.ws.send(p);
  }
  sendRaw(u8) { if (this.open) this.ws.send(u8); }

  onData(chunk) {
    // append to rxbuf
    const b = new Uint8Array(this.rxbuf.length + chunk.length);
    b.set(this.rxbuf); b.set(chunk, this.rxbuf.length);
    this.rxbuf = b;
    for (;;) {
      if (this.rxbuf.length < 7) return;
      const type = this.rxbuf[0];
      const size = this.rxbuf[1] | this.rxbuf[2]<<8 | this.rxbuf[3]<<16 | this.rxbuf[4]<<24;
      const status = this.rxbuf[5] | this.rxbuf[6]<<8;
      if (type === IVTP.VIDEO_FRAGMENT) {
        if (this.rxbuf.length < 9) return;
        const fragNum = this.rxbuf[7] | this.rxbuf[8]<<8;
        const need = 9 + (size - 2);
        if (this.rxbuf.length < need) return;
        this.onFragment(fragNum, this.rxbuf.subarray(9, need));
        this.rxbuf = this.rxbuf.subarray(need);
      } else {
        const need = 7 + size;
        if (this.rxbuf.length < need) return;
        this.onControl(type, status, this.rxbuf.subarray(7, need));
        this.rxbuf = this.rxbuf.subarray(need);
      }
    }
  }

  onControl(type, status, body) {
    switch (type) {
      case IVTP.VALIDATE_VIDEO_RESP:
        if (body.length && body[0] === 0) { this.onStatus("session REJECTED"); return; }
        this.onStatus("session valid — starting video");
        const bw = new Uint8Array(4); bw[0] = 0x00; bw[1] = 0x00; bw[2] = 0xC8;
        this.send(ivtpHdr(IVTP.SET_BANDWIDTH, 4), bw);           // 100 Mbps
        this.send(ivtpHdr(IVTP.REFRESH, 0));
        break;
      case IVTP.BLANK_SCREEN: this.stats.blank++; this.onBlank(); break;
      case IVTP.SESSION_ACCEPTED: this.onStatus("session accepted"); break;
      case IVTP.KEYBD_LED: if (body.length) this.onLed(body[0]); break;
      case IVTP.GET_USB_MOUSE_MODE: break;
      default:
        this.stats.ctrl[type] = (this.stats.ctrl[type] || 0) + 1;
        this.onStats(this.stats);
    }
  }

  onFragment(fragNum, payload) {
    this.stats.video++;
    if ((fragNum & 0x7fff) === 0) this.frag = [];
    this.frag.push(payload);
    if (fragNum & 0x8000) {
      this.stats.frames++;
      // assemble
      let n = 0; for (const p of this.frag) n += p.length;
      const frame = new Uint8Array(n);
      let o = 0; for (const p of this.frag) { frame.set(p, o); o += p.length; }
      this.frag = [];
      // VideoHdr: 19B reserved + "ASP-2000" + hdrLen u16 + dataLen u32 + cmd/status/reserved
      const sig = String.fromCharCode(...frame.subarray(19, 27));
      if (sig !== "ASP-2000") { this.onStatus("bad frame sig"); return; }
      const imgFrame = frame.subarray(39);
      try {
        const r = this.decoder.decodeFrame(imgFrame);
        this.onFrame(r);
      } catch (e) { this.onStatus("decode: " + e.message); }
    }
  }

  /* input */
  keyDown(code)  { this.sendRaw(keyboardPacket(this.kbd.onKey(code, true))); }
  keyUp(code)    { this.sendRaw(keyboardPacket(this.kbd.onKey(code, false))); }
  mouse(btn, x, y, w, h) { this.sendRaw(mousePacket(btn, x, y, w, h)); }
  sendCtrl(type, size = 0, status = 0) { this.send(ivtpHdr(type, size, status)); }
  disconnect() { this.sendCtrl(IVTP.STOP_SESSION); this.ws && this.ws.close(); }
}
