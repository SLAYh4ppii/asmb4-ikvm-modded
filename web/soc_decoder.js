/* soc_decoder.js — ASPEED AST2050/AST2100 "SOC" video decoder for the
 * ASMB4-iKVM (MegaRAC Aster) IVTP video channel.
 *
 * Ported 1:1 from LunarView (IlyaBOT, MIT-style research implementation),
 * which itself models the decompiled com.ami.kvm.jviewer.video.Decoder.
 * Produces BGR pixel data; caller blits to canvas.
 *
 * Frame = VideoHeader (86B LE) + compressedSize bytes of command stream.
 * Commands: 4-bit opcodes driving JPEG/VQ tiles over a 8x8 or 16x16 grid.
 */
"use strict";

/* ---------- BitReader: LE-dword packed, MSB-first per dword ---------- */
class BitReader {
  constructor(bytes) {
    const w = Math.ceil(bytes.length / 4);
    this.words = new Uint32Array(w);
    for (let i = 0; i < bytes.length; i++)
      this.words[i >>> 2] |= bytes[i] << ((i & 3) * 8);
    this.bitCount = w * 32;
    this.pos = 0;
  }
  bitsRemaining() { return this.bitCount - this.pos; }
  bitPosition() { return this.pos; }
  peek(count) {
    if (count === 0 || count > 32) throw new Error("bad bit width");
    if (count > this.bitsRemaining()) throw new Error("bitstream truncated");
    let v = 0;
    for (let i = 0; i < count; i++) {
      const a = this.pos + i;
      const bit = (this.words[a >>> 5] >>> (31 - (a & 31))) & 1;
      v = (v << 1) | bit;
    }
    return v >>> 0;
  }
  read(count) { const v = this.peek(count); this.pos += count; return v; }
  skip(count) {
    if (count > this.bitsRemaining()) throw new Error("skip beyond end");
    this.pos += count;
  }
}

/* ---------- Canonical JPEG Huffman ---------- */
const ZIGZAG_TO_NATURAL = [
   0, 1, 8,16, 9, 2, 3,10, 17,24,32,25, 18,11, 4, 5,
  12,19,26,33,40,48,41,34, 27,20,13, 6,  7,14,21,28,
  35,42,49,56,57,50,43,36, 29,22,15,23, 30,37,44,51,
  58,59,52,45,38,31,39,46, 53,60,61,54, 47,55,62,63,
];
const NATURAL_TO_ZIGZAG = [
   0, 1, 5, 6,14,15,27,28,  2, 4, 7,13,16,26,29,42,
   3, 8,12,17,25,30,41,43,  9,11,18,24,31,40,44,53,
  10,19,23,32,39,45,52,54, 20,22,33,38,46,51,55,60,
  21,34,37,47,50,56,59,61, 35,36,48,49,57,58,62,63,
];

class HuffmanTable {
  constructor(codeCounts, symbols) {
    this.symbols = symbols;
    this.firstCode = new Uint32Array(17);
    this.firstSymbol = new Uint16Array(17);
    this.count = new Uint16Array(17);
    let nextCode = 0, nextSym = 0;
    for (let len = 1; len <= 16; len++) {
      const c = codeCounts[len - 1];
      this.firstCode[len] = nextCode;
      this.firstSymbol[len] = nextSym;
      this.count[len] = c;
      nextCode += c; nextSym += c; nextCode <<= 1;
    }
  }
  decode(r) {
    let code = 0;
    for (let len = 1; len <= 16; len++) {
      code = (code << 1) | r.read(1);
      const f = this.firstCode[len], c = this.count[len];
      if (code >= f && code - f < c)
        return this.symbols[this.firstSymbol[len] + (code - f)];
    }
    throw new Error("no matching Huffman code");
  }
}

function decodeMagnitude(r, width) {
  if (width === 0) return 0;
  const enc = r.read(width);
  const pos = 1 << (width - 1);
  return enc >= pos ? enc : enc + 1 - (1 << width);
}

function decodeJpegDataUnit(r, dcTable, acTable, dcRef) {
  const coef = new Int32Array(64);
  const dcWidth = dcTable.decode(r);
  if (dcWidth > 16) throw new Error("bad DC width");
  const dc = dcRef.v + decodeMagnitude(r, dcWidth);
  coef[0] = dc;
  // wrapJavaShort
  dcRef.v = ((dc & 0xffff) + 0x8000 & 0xffff) - 0x8000;
  let pos = 1;
  while (pos < 64) {
    const sym = acTable.decode(r);
    const run = sym >> 4, width = sym & 0x0f;
    if (width === 0) {
      if (run === 0) break;
      if (run !== 15) throw new Error("reserved AC symbol");
      pos += 16;
      continue;
    }
    pos += run;
    if (pos >= 64) throw new Error("AC run overflow");
    coef[ZIGZAG_TO_NATURAL[pos]] = decodeMagnitude(r, width);
    pos++;
  }
  return coef;
}

/* ---------- standard JPEG tables (AST SOC profile) ---------- */
const DC_LUM_COUNTS   = [0,1,5,1,1,1,1,1,1,0,0,0,0,0,0,0];
const DC_CHROM_COUNTS = [0,3,1,1,1,1,1,1,1,1,1,0,0,0,0,0];
const DC_SYMBOLS      = [0,1,2,3,4,5,6,7,8,9,10,11];
const AC_LUM_COUNTS   = [0,2,1,3,3,2,4,3,5,5,4,4,0,0,1,125];
const AC_LUM_SYMBOLS  = [
  1,2,3,0,4,17,5,18,33,49,65,6,19,81,97,7,
  34,113,20,50,129,145,161,8,35,66,177,193,21,82,209,240,
  36,51,98,114,130,9,10,22,23,24,25,26,37,38,39,40,
  41,42,52,53,54,55,56,57,58,67,68,69,70,71,72,73,
  74,83,84,85,86,87,88,89,90,99,100,101,102,103,104,105,
  106,115,116,117,118,119,120,121,122,131,132,133,134,135,136,137,
  138,146,147,148,149,150,151,152,153,154,162,163,164,165,166,167,
  168,169,170,178,179,180,181,182,183,184,185,186,194,195,196,197,
  198,199,200,201,202,210,211,212,213,214,215,216,217,218,225,226,
  227,228,229,230,231,232,233,234,241,242,243,244,245,246,247,248,
  249,250];
const AC_CHROM_COUNTS = [0,2,1,2,4,4,3,4,7,5,4,4,0,1,2,119];
const AC_CHROM_SYMBOLS= [
  0,1,2,3,17,4,5,33,49,6,18,65,81,7,97,113,
  19,34,50,129,8,20,66,145,161,177,193,9,35,51,82,240,
  21,98,114,209,10,22,36,52,225,37,241,23,24,25,26,38,
  39,40,41,42,53,54,55,56,57,58,67,68,69,70,71,72,
  73,74,83,84,85,86,87,88,89,90,99,100,101,102,103,104,
  105,106,115,116,117,118,119,120,121,122,130,131,132,133,134,135,
  136,137,138,146,147,148,149,150,151,152,153,154,162,163,164,165,
  166,167,168,169,170,178,179,180,181,182,183,184,185,186,194,195,
  196,197,198,199,200,201,202,210,211,212,213,214,215,216,217,218,
  226,227,228,229,230,231,232,233,234,242,243,244,245,246,247,248,
  249,250];

const HUFF = {
  lumDc:  new HuffmanTable(DC_LUM_COUNTS, DC_SYMBOLS),
  lumAc:  new HuffmanTable(AC_LUM_COUNTS, AC_LUM_SYMBOLS),
  chrDc:  new HuffmanTable(DC_CHROM_COUNTS, DC_SYMBOLS),
  chrAc:  new HuffmanTable(AC_CHROM_COUNTS, AC_CHROM_SYMBOLS),
};

/* ---------- Quantization (selector tables + scaling) ---------- */
// Selector order 000,014,029,043,057,071,086,100 — each stores Y then UV.
const QUANT_TABLES = [
  [20,13,12,20,30,50,63,76,15,15,17,23,32,72,75,68,17,16,20,30,50,71,86,70,
   17,21,27,36,63,108,100,77,22,27,46,70,85,136,128,96,30,43,68,80,101,130,141,115,
   61,80,97,108,128,151,150,126,90,115,118,122,140,125,128,123],
  [31,33,45,88,185,185,185,185,33,39,48,123,185,185,185,185,45,48,105,185,185,185,185,185,
   88,123,185,185,185,185,185,185,185,185,185,185,185,185,185,185,185,185,185,185,185,185,185,185,185,185,
   185,185,185,185,185,185,185,185,185,185,185,185,185,185,185,185],
  [17,12,10,17,26,43,55,66,13,13,15,20,28,63,65,60,15,14,17,26,43,62,75,61,
   15,18,24,31,55,95,87,67,19,24,40,61,74,119,112,84,26,38,60,70,88,113,123,100,
   53,70,85,95,112,132,131,110,78,100,103,107,122,109,112,108],
  [27,29,39,76,160,160,160,160,29,34,42,107,160,160,160,160,39,42,91,160,160,160,160,160,
   76,107,160,160,160,160,160,160,160,160,160,160,160,160,160,160,160,160,160,160,160,160,160,160,160,160,
   160,160,160,160,160,160,160,160,160,160,160,160,160,160,160,160],
  [14,9,9,14,21,36,46,55,10,10,12,17,23,52,54,49,12,11,14,21,36,51,62,50,
   12,15,19,26,46,78,72,56,16,19,33,50,61,98,93,69,21,31,49,58,73,94,102,83,
   44,58,70,78,93,109,108,91,65,83,86,88,101,90,93,89],
  [22,24,32,63,133,133,133,133,24,28,34,88,133,133,133,133,32,34,75,133,133,133,133,133,
   63,88,133,133,133,133,133,133,133,133,133,133,133,133,133,133,133,133,133,133,133,133,133,133,133,133,
   133,133,133,133,133,133,133,133,133,133,133,133,133,133,133,133],
  [11,7,7,11,17,28,36,43,8,8,10,13,18,41,43,39,10,9,11,17,28,40,49,40,
   10,12,15,20,36,62,57,44,12,15,26,40,48,78,74,55,17,25,39,46,58,74,81,66,
   35,46,56,62,74,86,86,72,51,66,68,70,80,71,74,71],
  [18,19,26,51,108,108,108,108,19,22,28,72,108,108,108,108,26,28,61,108,108,108,108,108,
   51,72,108,108,108,108,108,108,108,108,108,108,108,108,108,108,108,108,108,108,108,108,108,108,108,108,
   108,108,108,108,108,108,108,108,108,108,108,108,108,108,108,108],
  [9,6,5,9,13,22,28,34,6,6,7,10,14,32,33,30,7,7,9,13,22,32,38,31,
   7,9,12,16,28,48,45,34,10,12,20,31,38,61,57,43,13,19,30,36,45,58,63,51,
   27,36,43,48,57,68,67,56,40,51,53,55,63,56,57,55],
  [13,14,19,38,80,80,80,80,14,17,21,53,80,80,80,80,19,21,45,80,80,80,80,80,
   38,53,80,80,80,80,80,80,80,80,80,80,80,80,80,80,80,80,80,80,80,80,80,80,80,80,
   80,80,80,80,80,80,80,80,80,80,80,80,80,80,80,80],
  [6,4,3,6,9,15,19,22,4,4,5,7,9,21,22,20,5,4,6,9,15,21,25,21,
   5,6,8,10,19,32,30,23,6,8,13,21,25,40,38,28,9,13,20,24,30,39,42,34,
   18,24,29,32,38,45,45,37,27,34,35,36,42,37,38,37],
  [9,10,13,26,55,55,55,55,10,11,14,37,55,55,55,55,13,14,31,55,55,55,55,55,
   26,37,55,55,55,55,55,55,55,55,55,55,55,55,55,55,55,55,55,55,55,55,55,55,55,55,
   55,55,55,55,55,55,55,55,55,55,55,55,55,55,55,55],
  [3,2,1,3,4,7,9,11,2,2,2,3,4,10,11,10,2,2,3,4,7,10,12,10,
   2,3,4,5,9,16,15,11,3,4,6,10,12,20,19,14,4,6,10,12,15,19,21,17,
   9,12,14,16,19,22,22,18,13,17,17,18,21,18,19,18],
  [4,5,6,13,27,27,27,27,5,5,7,18,27,27,27,27,6,7,15,27,27,27,27,27,
   13,18,27,27,27,27,27,27,27,27,27,27,27,27,27,27,27,27,27,27,27,27,27,27,27,27,
   27,27,27,27,27,27,27,27,27,27,27,27,27,27,27,27],
  [2,1,1,2,3,5,6,7,1,1,1,2,3,7,7,6,1,1,2,3,5,7,8,7,
   1,2,2,3,6,10,10,7,2,2,4,7,8,13,12,9,3,4,6,8,10,13,14,11,
   6,8,9,10,12,15,15,12,9,11,11,12,14,12,12,12],
  [3,3,4,8,18,18,18,18,3,3,4,12,18,18,18,18,4,4,10,18,18,18,18,18,
   8,12,18,18,18,18,18,18,18,18,18,18,18,18,18,18,18,18,18,18,18,18,18,18,18,18,
   18,18,18,18,18,18,18,18,18,18,18,18,18,18,18,18],
];

const AAN_SCALE = [1.0,1.3870399,1.306563,1.1758755,1.0,0.78569496,0.5411961,0.27589938];

function selectQuantization(selector, chrominance, mapChromaToLuma, scaleFactor) {
  const index = selector * 2 + ((chrominance && !mapChromaToLuma) ? 1 : 0);
  const naturalOrder = QUANT_TABLES[index];
  // makeLegacyQuantizationStorage(naturalOrder, scaleFactor, LegacySigned)
  const storage = new Uint8Array(64);
  for (let i = 0; i < 64; i++) {
    let b = naturalOrder[i];
    let v = (b < 0x80 ? b : b - 256) * 16;
    v = Math.trunc(v / scaleFactor);
    v = Math.min(255, Math.max(1, v));
    storage[NATURAL_TO_ZIGZAG[i]] = v;
  }
  // restoreNaturalQuantization
  const natural = new Uint8Array(64);
  for (let i = 0; i < 64; i++) natural[i] = storage[NATURAL_TO_ZIGZAG[i]];
  // makeLegacyIdctQuantization: int(natural[i] * (scale[r]*scale[c])) * 65536
  const fixed = new Float64Array(64);
  for (let r = 0; r < 8; r++)
    for (let c = 0; c < 8; c++) {
      const i = r * 8 + c;
      fixed[i] = Math.trunc(natural[i] * (AAN_SCALE[r] * AAN_SCALE[c])) * 65536;
    }
  return fixed;
}

function makeQuantizationTables(header) {
  const mapC = header.jpegYuvTableMapping === 1;
  return {
    baseY:     selectQuantization(header.jpegTableSelector, false, mapC, header.jpegScaleFactor),
    baseChroma:selectQuantization(header.jpegTableSelector, true,  mapC, header.jpegScaleFactor),
    advY:      selectQuantization(header.advanceTableSelector, false, mapC, header.advanceScaleFactor),
    advChroma: selectQuantization(header.advanceTableSelector, true,  mapC, header.advanceScaleFactor),
  };
}

/* ---------- IDCT (legacy AAN butterfly, integer domain) ---------- */
function asr(v, n) { return Math.floor(v / (1 << n)); }        // arithmetic shift right
function dequantize(coef, quant) {                              // quant is q48.16
  const product = (coef >>> 0) * (quant >>> 0);                 // low 32 bits of u32*u32
  const wrapped = product % 4294967296;
  const signed = wrapped >= 0x80000000 ? wrapped - 0x100000000 : wrapped;
  return asr(signed, 16);
}
function transform1D(inp) {
  const m8 = (v, s) => asr(v * s, 8);                           // multiplyQ8
  const e04s = inp[0] + inp[4], e04d = inp[0] - inp[4];
  const e26s = inp[2] + inp[6];
  const e26r = m8(inp[2] - inp[6], 362) - e26s;
  const e0 = e04s + e26s, e3 = e04s - e26s;
  const e1 = e04d + e26r, e2 = e04d - e26r;
  const o53s = inp[5] + inp[3], o53d = inp[5] - inp[3];
  const o17s = inp[1] + inp[7], o17d = inp[1] - inp[7];
  const oc = o17s + o53s;
  const orot = m8(o17s - o53s, 362);
  const omix = m8(o53d + o17d, 473);
  const ohi = m8(o17d, 277) - omix;
  const olo = m8(o53d, -669) + omix;
  const o1 = olo - oc, o2 = orot - o1, o3 = ohi + o2;
  return [e0+oc, e1+o1, e2+o2, e3-o3, e3+o3, e2-o2, e1-o1, e0-oc];
}
function rangeLimit(t) {
  const wrapped = asr(t, 3) & 0x3ff;
  const idx = 384 + wrapped;
  if (idx < 512) return idx - 256;
  if (idx < 895) return 255;
  if (idx < 1280) return 0;
  return idx & 0xff;
}
function inverseDct(coef, quant) {
  const ws = new Int32Array(64);
  for (let c = 0; c < 8; c++) {
    let dcOnly = true;
    for (let r = 1; r < 8; r++) dcOnly = dcOnly && coef[r*8+c] === 0;
    if (dcOnly) {
      const dc = dequantize(coef[c], quant[c]);
      for (let r = 0; r < 8; r++) ws[r*8+c] = dc;
      continue;
    }
    const col = new Int32Array(8);
    for (let r = 0; r < 8; r++) col[r] = dequantize(coef[r*8+c], quant[r*8+c]);
    const t = transform1D(col);
    for (let r = 0; r < 8; r++) ws[r*8+c] = t[r];
  }
  const out = new Uint8Array(64);
  for (let r = 0; r < 8; r++) {
    const row = new Int32Array(8);
    for (let c = 0; c < 8; c++) row[c] = ws[r*8+c];
    const t = transform1D(row);
    for (let c = 0; c < 8; c++) out[r*8+c] = rangeLimit(t[c]);
  }
  return out;
}

/* ---------- VQ ---------- */
class VqColorCache {
  constructor() { this.colors = [0x008080, 0xff8080, 0x808080, 0xc08080]; }
  packed(i) { return this.colors[i]; }
  setPacked(i, v) { this.colors[i] = v; }
}
function decodeVqTile(r, cache, colorCount) {
  const bits = colorCount === 1 ? 0 : colorCount === 2 ? 1 : 2;
  const mapping = new Uint8Array(4);
  for (let i = 0; i < colorCount; i++) {
    const update = r.read(1) !== 0;
    mapping[i] = r.read(2);
    if (update) cache.setPacked(mapping[i], r.read(24));
  }
  const tile = new Uint8Array(64 * 3);
  for (let i = 0; i < 64; i++) {
    const sel = bits === 0 ? 0 : r.read(bits);
    const packed = cache.packed(mapping[sel]);
    tile[i*3] = (packed >> 16) & 0xff;       // Y
    tile[i*3+1] = (packed >> 8) & 0xff;      // Cb
    tile[i*3+2] = packed & 0xff;             // Cr
  }
  return tile;
}

/* ---------- YCbCr -> BGR ---------- */
const clampB = v => v < 0 ? 0 : v > 255 ? 255 : v;
const fc = (scale, delta) => Math.floor((scale * delta + 32768) / 65536);
function yCbCrToBgr(y, cb, cr) {
  const yy = fc(76284, y - 16);
  const cb_ = cb - 128, cr_ = cr - 128;
  return [
    clampB(yy + fc(132096, cb_)),
    clampB(yy + fc(-25600, cb_) + fc(-53248, cr_)),
    clampB(yy + fc(104704, cr_)),
  ];
}
function yCbCrToBgrTile(tileYuv /*Uint8Array 192*/) {
  const out = new Uint8Array(192);
  for (let i = 0; i < 64; i++) {
    const b = yCbCrToBgr(tileYuv[i*3], tileYuv[i*3+1], tileYuv[i*3+2]);
    out[i*3] = b[0]; out[i*3+1] = b[1]; out[i*3+2] = b[2];
  }
  return out;
}

/* ---------- VideoHeader (86 bytes LE) ---------- */
const VIDEO_HEADER_SIZE = 86;
function parseVideoHeader(f) {
  const u16 = o => f[o] | (f[o+1] << 8);
  const u32 = o => (f[o] | f[o+1]<<8 | f[o+2]<<16 | f[o+3]<<24) >>> 0;
  return {
    engineVersion: u16(0), headerLength: u16(2),
    sourceWidth: u16(4), sourceHeight: u16(6),
    sourceColorDepth: u16(8), sourceRefreshRate: u16(10),
    sourceModeIndex: f[12],
    destinationWidth: u16(13), destinationHeight: u16(15),
    destinationColorDepth: u16(17), destinationRefreshRate: u16(19),
    destinationModeIndex: f[21],
    startCode: u32(22), frameNumber: u32(26),
    horizontalSize: u16(30), verticalSize: u16(32),
    compressionMode: f[42], jpegScaleFactor: f[43],
    jpegTableSelector: f[44], jpegYuvTableMapping: f[45],
    sharpModeSelection: f[46], advanceTableSelector: f[47],
    advanceScaleFactor: f[48], macroblockCount: u32(49),
    rc4Enable: f[53], rc4Reset: f[54], mode420: f[55],
    downScalingMethod: f[56], differentialSetting: f[57],
    analogDiffThresh: u16(58), digitalDiffThresh: u16(60),
    externalSignalEnable: f[62], autoMode: f[63], vqMode: f[64],
    sourceFrameSize: u32(65), compressedSize: u32(69),
    horizontalDebug: u32(73), verticalDebug: u32(77),
    inputSignal: f[81], cursorX: u16(82), cursorY: u16(84),
  };
}

/* ---------- Main decoder ---------- */
class SocVideoDecoder {
  constructor() { this.reset(); }
  reset() {
    this.width = 0; this.height = 0;
    this.bgr = null; this.prevYuv = null;
    this.baseValid = null; this.coverage = null;
    this.coveredPixels = 0;
  }
  /* assembledFrame: Uint8Array with 86B header + compressed payload.
     Returns {width,height,bgr,frameNumber,covered,commands} */
  decodeFrame(frame) {
    const h = parseVideoHeader(frame);
    if (h.rc4Enable !== 0) throw new Error("RC4 video unsupported");
    if (h.mode420 > 1) throw new Error("unknown chroma mode");
    if (h.jpegTableSelector > 7 || h.advanceTableSelector > 7)
      throw new Error("bad quant selector");
    if (h.compressedSize === 0 || VIDEO_HEADER_SIZE + h.compressedSize > frame.length)
      throw new Error("compressed size exceeds payload");
    if (h.compressedSize % 4) throw new Error("compressed size not dword aligned");
    if (h.sourceWidth !== h.destinationWidth || h.sourceHeight !== h.destinationHeight)
      throw new Error("scaled modes unsupported");

    const W = h.sourceWidth, H = h.sourceHeight, pixels = W * H;
    if (!this.bgr || this.width !== W || this.height !== H) {
      this.width = W; this.height = H;
      this.bgr = new Uint8Array(pixels * 3);
      this.prevYuv = new Uint8Array(pixels * 3);
      this.baseValid = new Uint8Array(pixels);
      this.coverage = new Uint8Array(pixels);
      this.coveredPixels = 0;
    }
    const frameNumber = h.frameNumber;
    const quant = makeQuantizationTables(h);
    const payload = frame.subarray(VIDEO_HEADER_SIZE, VIDEO_HEADER_SIZE + h.compressedSize);
    const reader = new BitReader(payload);
    const pred = { y: {v:0}, cb: {v:0}, cr: {v:0} };
    const vq = new VqColorCache();
    const tileSize = h.mode420 === 1 ? 16 : 8;
    const tileCols = Math.ceil(W / tileSize), tileRows = Math.ceil(H / tileSize);
    let tileX = 0, tileY = 0, commands = 0, updated = 0;

    const write444 = (tx, ty, tile, pass2) => {
      const ox = tx * 8, oy = ty * 8;
      let upd = 0;
      for (let row = 0; row < 8 && oy + row < H; row++)
        for (let col = 0; col < 8 && ox + col < W; col++) {
          const px = (oy + row) * W + ox + col, by = px * 3, ti = (row * 8 + col) * 3;
          let Y = tile[ti], Cb = tile[ti+1], Cr = tile[ti+2];
          if (pass2) {
            Y  = clampB(this.prevYuv[by]   + Y  - 128);
            Cb = clampB(this.prevYuv[by+1] + Cb - 128);
            Cr = clampB(this.prevYuv[by+2] + Cr - 128);
          } else {
            this.prevYuv[by] = Y; this.prevYuv[by+1] = Cb; this.prevYuv[by+2] = Cr;
            this.baseValid[px] = 1;
          }
          const b = yCbCrToBgr(Y, Cb, Cr);
          this.bgr[by] = b[0]; this.bgr[by+1] = b[1]; this.bgr[by+2] = b[2];
          if (!pass2 && this.coverage[px] === 0) { this.coverage[px] = 1; this.coveredPixels++; }
          upd++;
        }
      return upd;
    };
    const write420 = (tx, ty, block) => {
      const ox = tx * 16, oy = ty * 16;
      let upd = 0;
      for (let row = 0; row < 16 && oy + row < H; row++)
        for (let col = 0; col < 16 && ox + col < W; col++) {
          const px = (oy + row) * W + ox + col, by = px * 3;
          const quad = ((row >> 3) * 2) + (col >> 3);
          const li = (row % 8) * 8 + (col % 8);
          const ci = (row >> 1) * 8 + (col >> 1);
          const b = yCbCrToBgr(block.y[quad][li], block.cb[ci], block.cr[ci]);
          this.bgr[by] = b[0]; this.bgr[by+1] = b[1]; this.bgr[by+2] = b[2];
          if (this.coverage[px] === 0) { this.coverage[px] = 1; this.coveredPixels++; }
          upd++;
        }
      return upd;
    };
    const jpegBlock = (dc, ac, p, q) => inverseDct(decodeJpegDataUnit(reader, dc, ac, p), q);
    const jpeg444 = (qy, qc) => {
      const t = new Uint8Array(192);
      const y  = jpegBlock(HUFF.lumDc, HUFF.lumAc, pred.y, qy);
      const cb = jpegBlock(HUFF.chrDc, HUFF.chrAc, pred.cb, qc);
      const cr = jpegBlock(HUFF.chrDc, HUFF.chrAc, pred.cr, qc);
      for (let i = 0; i < 64; i++) { t[i*3] = y[i]; t[i*3+1] = cb[i]; t[i*3+2] = cr[i]; }
      return t;
    };
    const jpeg420 = (qy, qc) => {
      const b = { y: [], cb: null, cr: null };
      for (let i = 0; i < 4; i++) b.y[i] = jpegBlock(HUFF.lumDc, HUFF.lumAc, pred.y, qy);
      b.cb = jpegBlock(HUFF.chrDc, HUFF.chrAc, pred.cb, qc);
      b.cr = jpegBlock(HUFF.chrDc, HUFF.chrAc, pred.cr, qc);
      return b;
    };
    const isCoord = o => o===0x8||o===0xa||o===0xc||o===0xd||o===0xe||o===0xf;
    const isVq = o => o===0x5||o===0x6||o===0x7||o===0xd||o===0xe||o===0xf;
    const vqCount = o => (o===0x5||o===0xd)?1:(o===0x6||o===0xe)?2:4;

    while (reader.bitsRemaining() >= 4) {
      const op = reader.read(4);
      if (op === 0x9) break;
      commands++;
      if (op === 0x1 || op === 0x3 || op === 0xb) throw new Error("bad opcode "+op);
      if (isCoord(op)) { tileX = reader.read(8); tileY = reader.read(8); }
      if (tileX >= tileCols || tileY >= tileRows)
        throw new Error("tile coordinate out of range");

      if (op === 0x0 || op === 0x8 || op === 0x4 || op === 0xc) {
        const adv = (op === 0x4 || op === 0xc);
        const qy = adv ? quant.advY : quant.baseY;
        const qc = adv ? quant.advChroma : quant.baseChroma;
        if (h.mode420 === 1) updated += write420(tileX, tileY, jpeg420(qy, qc));
        else updated += write444(tileX, tileY, jpeg444(qy, qc), false);
      } else if (op === 0x2 || op === 0xa) {
        if (h.mode420 === 1) throw new Error("pass2 in 420");
        updated += write444(tileX, tileY, jpeg444(quant.advY, quant.advChroma), true);
      } else if (isVq(op)) {
        if (h.mode420 === 1) throw new Error("vq in 420");
        updated += write444(tileX, tileY, decodeVqTile(reader, vq, vqCount(op)), false);
      } else throw new Error("unsupported opcode "+op);

      if (++tileX >= tileCols) { tileX = 0; if (++tileY >= tileRows) tileY = 0; }
    }
    return { width: W, height: H, bgr: this.bgr, frameNumber,
             covered: this.coveredPixels, total: pixels, commands, updated };
  }
}

/* export for browser + node test */
if (typeof module !== "undefined") module.exports = {
  SocVideoDecoder, BitReader, HuffmanTable,
  decodeJpegDataUnit, inverseDct, dequantize, transform1D, rangeLimit,
  selectQuantization, makeQuantizationTables, yCbCrToBgr, VqColorCache,
  decodeVqTile, parseVideoHeader, VIDEO_HEADER_SIZE,
};
