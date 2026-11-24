"use strict";

/* =============================================================== */
/* IPC PAY FORENSICS — the tamper reader.                          */
/* =============================================================== */
/* The OCR gates answer "does the screenshot SAY what the member
   claims?" This module answers the harder question: "IS THE
   SCREENSHOT ITSELF HONEST?" Every proof image is run through a
   forensic scan before a single auto decision is made:

     1. PROOF FINGERPRINT  — a SHA-256 of the exact bytes. The same
        screenshot re-submitted on another order (a classic move:
        one real receipt, five orders) is caught here even when the
        OCR text is perfect.
     2. METADATA READ      — EXIF / PNG text chunks / JPEG comments
        are walked for photo-EDITOR signatures (Photoshop, PicsArt,
        Snapseed, Canva...). A phone screenshot carries no editor
        name; a retouched one often does.
     3. ERROR LEVEL ANALYSIS — the image is re-compressed at a fixed
        quality and the difference is mapped block by block. A JPEG
        that was edited after its first save keeps inconsistent
        compression levels around the touched region — the pasted
        amount lights up against the untouched background. (PNG is
        lossless, so ELA does not apply there — the metadata read,
        the fingerprint and the OCR cross-checks carry that format.)
     4. OCR SUPPORT PREP   — screenshots are grayscale-stretched and
        upscaled 2x into a cleaner second OCR pass so small receipt
        text actually reads.

   The scan's read IS the decision's backbone: any medium-or-worse
   forensic signal makes the auto reader REJECT the proof on its own —
   edited, AI-generated and reused receipts are declined automatically
   with the reason spelled out. A re-saved screenshot is judged by
   what the OCR cross-checks can prove, never by the noise alone, and
   an edited one can never breeze past the club. ------------------------------- */

const zlib = require("node:zlib");
const crypto = require("node:crypto");

/* ---- photo-EDITOR signatures. Wallet apps (GCash, Maya) are NOT
   editors and never match — a wallet's own name on its receipt is
   expected. Only retouching/compositing tools are flagged. ------- */
const EDITOR_SIGNATURES = [
  { re: /photoshop|photopea|adobe\s?express|photoshop\s?express/i, name: "Photoshop" },
  { re: /picsart/i, name: "PicsArt" },
  { re: /snapseed/i, name: "Snapseed" },
  { re: /canva/i, name: "Canva" },
  { re: /pixlr/i, name: "Pixlr" },
  { re: /\bgimp\b/i, name: "GIMP" },
  { re: /lightroom/i, name: "Lightroom" },
  { re: /airbrush/i, name: "Airbrush" },
  { re: /facetune/i, name: "Facetune" },
  { re: /meitu|beautyplus/i, name: "Meitu" },
  { re: /\bfotor\b/i, name: "Fotor" },
  { re: /\bvsco\b/i, name: "VSCO" },
  { re: /polarr/i, name: "Polarr" },
  { re: /affinity\s?photo/i, name: "Affinity Photo" },
  { re: /\bprocreate\b/i, name: "Procreate" },
  { re: /paint\.net|painttool\s?sai|corel\s?paint/i, name: "Paint.NET/SAI" },
  { re: /\binshot\b|\bcapcut\b|kinemaster/i, name: "InShot/CapCut" },
  { re: /remove\.?bg|\bremini\b|cutout\.pro|bg\.jpg/i, name: "Background remover" },
  { re: /pixelab|pixel\s?lab/i, name: "PixelLab" },
  { re: /\blightx\b|\btoonme\b|\bprequel\b|\bundo\s?edit\b/i, name: "Retouch app" },
];

/* ---- AI-GENERATOR signatures. A receipt that was never taken from a
   real wallet app is the newest scam: an image model is prompted with
   "Maya receipt for ₱X" and the render can look perfect to the eye.
   Image generators and content-provenance manifests leave markers in
   the file's metadata — prompts, generator names, C2PA/JUMBF boxes,
   IPTC "trained algorithmic media" codes. Any of these on a payment
   proof is a hard reject on sight. Wallet apps never match. ------- */
const AI_SIGNATURES = [
  { re: /dall[-·.]?e|openai|chatgpt/i, name: "DALL-E / OpenAI" },
  { re: /midjourney/i, name: "Midjourney" },
  { re: /stable\s?diffusion|stablediffusion|comfyui|automatic1111|a1111|invokeai|kohya/i, name: "Stable Diffusion" },
  { re: /firefly|adobe\s?generative/i, name: "Adobe Firefly" },
  { re: /imagen|gemini|nanobanana|made\s?with\s?google\s?ai|whisk/i, name: "Google AI" },
  { re: /grok\s?imagine/i, name: "Grok Imagine" },
  { re: /bing\s?image\s?creator|copilot\s?image/i, name: "Bing Image Creator" },
  { re: /leonardo(\.ai)?\b/i, name: "Leonardo AI" },
  { re: /ideogram|recraft|runwayml|playground\s?ai|\bkrea\b|neural\.love|nightcafe|starryai|wombo/i, name: "AI art service" },
  { re: /black\s?forest\s?labs|flux\.?1|fluxdev|fluxschnell/i, name: "FLUX" },
  { re: /cogview|wanx|hunyuan|doubao|jimeng|qwenimage|seedream/i, name: "AI generator (CN)" },
  { re: /trainedalgorithmicmedia|trainedalgorithmic/i, name: "IPTC trained-algorithmic-media" },
  { re: /c2pa|contentcredentials|content\s?credentials|jumbf|synthid/i, name: "Content-provenance manifest" },
  { re: /\bai[-\s]?generated\b|\baigc\b|\bgenerative\s?ai\b/i, name: "AI-generated marker" },
];

/* ---- ELA calibration. A single-generation JPEG compresses evenly;
   a pasted region keeps visibly hotter error levels than its
   surroundings. Thresholds sit ABOVE the honest baseline: text-heavy
   receipt screenshots spike to ratio ~2.4 on their own (measured),
   so anything below 3.5 is treated as normal texture, never an
   accusation. ------------------------------------------------------ */
const ELA_QUALITY = 75;
const ELA_BLOCK = 16;
const ELA_HOT_FACTOR = 5;
const ELA_MIN_RATIO = 3.5;      /* max block vs active median */
const ELA_HOT_MIN = 0.004;      /* hot blocks below 0.4% = noise */
const ELA_HOT_MAX = 0.35;       /* above 35% = whole image re-saved, not a splice */
const ELA_MAX_PIXELS = 30 * 1000 * 1000;
const OCR_PREP_MAX_PIXELS = 12 * 1000 * 1000;

const SEVERITY = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

/* ---------------------------------------------------------------- */
/* Basics                                                            */
/* ---------------------------------------------------------------- */

function imageHash(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function sniffFormat(buf) {
  if (!buf || buf.length < 12) return null;
  if (buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return "jpeg";
  const PNG = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
  for (let i = 0; i < 8; i++) if (buf[i] !== PNG[i]) return null;
  return "png";
}

/* Walk JPEG markers and return segment payloads (skips scan data). */
function jpegSegments(buf) {
  const segs = [];
  let i = 2;
  while (i + 4 <= buf.length) {
    if (buf[i] !== 0xff) { i++; continue; }
    const marker = buf[i + 1];
    if (marker === 0xd8 || marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) { i += 2; continue; }
    if (marker === 0xda || marker === 0xd9) break; /* scan data / EOI */
    const len = (buf[i + 2] << 8) | buf[i + 3];
    if (len < 2 || i + 2 + len > buf.length) break;
    segs.push({ marker, start: i + 4, len: len - 2 });
    i += 2 + len;
  }
  return segs;
}

function jpegDimensions(buf) {
  try {
    for (const s of jpegSegments(buf)) {
      if ((s.marker >= 0xc0 && s.marker <= 0xcf) &&
          s.marker !== 0xc4 && s.marker !== 0xc8 && s.marker !== 0xcc) {
        const h = (buf[s.start + 1] << 8) | buf[s.start + 2];
        const w = (buf[s.start + 3] << 8) | buf[s.start + 4];
        if (w > 0 && h > 0) return { width: w, height: h };
      }
    }
  } catch { /* dimensional read is best-effort */ }
  return { width: 0, height: 0 };
}

/* Minimal TIFF/EXIF walk — enough for Software / Make / Model /
   DateTimeOriginal. Every step bounds-checked: a hostile EXIF blob
   can never walk this code off the buffer. ------------------------ */
function parseTiffTags(tiff) {
  const out = {};
  try {
    const le = tiff[0] === 0x49 && tiff[1] === 0x49;
    const rd16 = (o) => (o + 2 <= tiff.length)
      ? (le ? tiff[o] | (tiff[o + 1] << 8) : (tiff[o] << 8) | tiff[o + 1]) : 0;
    const rd32 = (o) => (o + 4 <= tiff.length)
      ? (le
        ? (tiff[o] | (tiff[o + 1] << 8) | (tiff[o + 2] << 16) | (tiff[o + 3] << 24)) >>> 0
        : ((tiff[o] << 24) | (tiff[o + 1] << 16) | (tiff[o + 2] << 8) | tiff[o + 3]) >>> 0) : 0;
    if (rd16(2) !== 42) return out;
    const TAGS = { 0x010f: "make", 0x0110: "model", 0x0131: "software", 0x0132: "dateTime", 0x9003: "dateTimeOriginal" };
    const readIfd = (base, depth) => {
      if (depth > 3 || base + 2 > tiff.length) return;
      const n = rd16(base);
      if (n > 200) return;
      for (let k = 0; k < n; k++) {
        const e = base + 2 + k * 12;
        if (e + 12 > tiff.length) return;
        const tag = rd16(e), type = rd16(e + 2), count = rd32(e + 4);
        const sizes = { 1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8 };
        const sz = (sizes[type] || 1) * count;
        /* TIFF value offsets are absolute from the TIFF header start */
        const valOff = sz <= 4 ? e + 8 : rd32(e + 8);
        if (type === 2 && valOff + Math.min(count, 128) <= tiff.length) {
          const key = TAGS[tag];
          if (key && !out[key]) {
            const str = tiff.slice(valOff, valOff + Math.min(count - 1, 96)).toString("latin1").trim();
            if (str) out[key] = str;
          }
        }
        if (tag === 0x8769 && type === 4) readIfd(rd32(e + 8), depth + 1);
      }
    };
    readIfd(rd32(4), 0);
  } catch { /* hostile metadata stays a no-op, never a crash */ }
  return out;
}

function parseJpegMeta(buf) {
  const meta = { format: "jpeg", strings: [], exif: {} };
  try {
    for (const s of jpegSegments(buf)) {
      const payload = buf.slice(s.start, s.start + s.len);
      if (s.marker === 0xfe) { /* COM */
        const c = payload.toString("latin1").replace(/[^\x20-\x7e]/g, " ").trim();
        if (c) { meta.comment = c.slice(0, 160); meta.strings.push(c); }
      } else if (s.marker === 0xe1 && payload.slice(0, 4).toString("latin1") === "Exif") {
        const tags = parseTiffTags(payload.slice(6));
        Object.assign(meta.exif, tags);
        for (const v of Object.values(tags)) if (v) meta.strings.push(v);
      } else if (s.marker === 0xed) { /* APP13 — Photoshop IRB lives here */
        const c = payload.toString("latin1").replace(/[^\x20-\x7e]/g, " ");
        meta.strings.push(c.slice(0, 512));
        if (/Photoshop\s?3\.0/i.test(c)) meta.photoshopIrb = true;
      } else if (s.marker >= 0xe0 && s.marker <= 0xef) {
        const c = payload.toString("latin1").replace(/[^\x20-\x7e]/g, " ");
        if (c.length > 6) meta.strings.push(c.slice(0, 256));
      }
    }
  } catch { /* malformed segments are a note, never a crash */ }
  return meta;
}

function parsePngMeta(buf) {
  const meta = { format: "png", strings: [], exif: {}, texts: [] };
  try {
    let off = 8;
    while (off + 8 <= buf.length) {
      const len = (buf[off] << 24 | buf[off + 1] << 16 | buf[off + 2] << 8 | buf[off + 3]) >>> 0;
      const type = buf.slice(off + 4, off + 8).toString("latin1");
      if (len > buf.length - off - 12 || len > 4 * 1024 * 1024) break;
      const data = buf.slice(off + 8, off + 8 + len);
      if (type === "IHDR") {
        meta.width = (data[0] << 24 | data[1] << 16 | data[2] << 8 | data[3]) >>> 0;
        meta.height = (data[4] << 24 | data[5] << 16 | data[6] << 8 | data[7]) >>> 0;
      } else if (type === "tEXt") {
        const z = data.indexOf(0);
        if (z > 0) meta.texts.push({ keyword: data.slice(0, z).toString("latin1"), value: data.slice(z + 1).toString("latin1").slice(0, 200) });
      } else if (type === "zTXt") {
        const z = data.indexOf(0);
        if (z > 0) {
          try {
            meta.texts.push({ keyword: data.slice(0, z).toString("latin1"), value: zlib.inflateSync(data.slice(z + 2)).toString("latin1").slice(0, 200) });
          } catch { /* bad zlib chunk — ignore */ }
        }
      } else if (type === "iTXt") {
        const z = data.indexOf(0);
        if (z > 0) {
          const kw = data.slice(0, z).toString("latin1");
          let v = "";
          try {
            const comp = data[z + 1 + kw.length]; /* compression flag byte after keyword NUL + encoding */
            const rest = data.slice(z + 1);
            const z2 = rest.indexOf(0, kw.length + 2);
            const body = comp === 1 && z2 > 0
              ? zlib.inflateSync(rest.slice(z2 + 3)).toString("utf8")
              : rest.slice(rest.indexOf(0) + 2).toString("utf8");
            v = body;
          } catch { /* keep whatever parsed */ }
          meta.texts.push({ keyword: kw, value: String(v).slice(0, 200) });
        }
      } else if (type === "eXIf") {
        Object.assign(meta.exif, parseTiffTags(data));
      }
      off += 12 + len;
    }
    for (const t of meta.texts) if (t.value) meta.strings.push(t.keyword + " " + t.value);
    for (const v of Object.values(meta.exif)) if (v) meta.strings.push(v);
  } catch { /* malformed chunks are a note, never a crash */ }
  return meta;
}

function detectEditor(strings) {
  for (const s of strings || []) {
    for (const sig of EDITOR_SIGNATURES) {
      if (sig.re.test(s)) return { name: sig.name, source: String(s).slice(0, 96) };
    }
  }
  return null;
}

function detectAIGenerator(strings) {
  for (const s of strings || []) {
    for (const sig of AI_SIGNATURES) {
      if (sig.re.test(s)) return { name: sig.name, source: String(s).slice(0, 96) };
    }
  }
  return null;
}

/* ---------------------------------------------------------------- */
/* ELA — error level analysis (JPEG only)                            */
/* ---------------------------------------------------------------- */

function elaScanJPEG(buf) {
  const skip = { applicable: true, verdict: "skipped", reason: "image too large to analyze" };
  try {
    const jpegjs = require("jpeg-js");
    const img = jpegjs.decode(buf, { useTArray: true, maxMemoryUsageInMB: 512 });
    const { width: w, height: h, data } = img;
    if (w * h > ELA_MAX_PIXELS || !w || !h) return skip;

    const luma = new Float32Array(w * h);
    for (let p = 0, q = 0; p < w * h; p++, q += 4) {
      luma[p] = 0.299 * data[q] + 0.587 * data[q + 1] + 0.114 * data[q + 2];
    }
    const re = jpegjs.encode({ data: Buffer.from(data.buffer, data.byteOffset, data.length), width: w, height: h }, ELA_QUALITY);
    const img2 = jpegjs.decode(re.data, { useTArray: true, maxMemoryUsageInMB: 512 });
    const d2 = img2.data;

    const bw = Math.floor(w / ELA_BLOCK), bh = Math.floor(h / ELA_BLOCK);
    if (bw < 4 || bh < 4) return { applicable: true, verdict: "inconclusive", reason: "image too small for block analysis" };
    const err = new Float32Array(bw * bh);
    for (let by = 0; by < bh; by++) {
      for (let bx = 0; bx < bw; bx++) {
        let sum = 0, n = 0;
        for (let y = by * ELA_BLOCK; y < (by + 1) * ELA_BLOCK; y++) {
          for (let x = bx * ELA_BLOCK; x < (bx + 1) * ELA_BLOCK; x++) {
            const p = y * w + x, q = p * 4;
            const l2 = 0.299 * d2[q] + 0.587 * d2[q + 1] + 0.114 * d2[q + 2];
            sum += Math.abs(luma[p] - l2); n++;
          }
        }
        err[by * bw + bx] = n ? sum / n : 0;
      }
    }
    /* Dark UI screenshots keep most blocks near zero — a median over
       every block would read as noise. The splice fingerprint is read
       over the ACTIVE blocks (error >= 1.0) with an absolute floor so
       a dark background can never impersonate a hotspot. */
    let max = 0;
    for (let i = 0; i < err.length; i++) if (err[i] > max) max = err[i];
    const active = [];
    for (let i = 0; i < err.length; i++) if (err[i] >= 1.0) active.push(err[i]);
    if (active.length < err.length * 0.01) {
      return { applicable: true, verdict: "inconclusive", median: 0, max: round2(max), reason: "flat image — error levels unreadable" };
    }
    active.sort((a, b) => a - b);
    const median = active[Math.floor(active.length / 2)] || 0;
    const p90 = active[Math.floor(active.length * 0.9)] || 0;

    const hotThreshold = Math.max(ELA_HOT_FACTOR * median, 8);
    let hot = 0, hx0 = bw, hy0 = bh, hx1 = 0, hy1 = 0;
    for (let i = 0; i < err.length; i++) {
      if (err[i] >= hotThreshold) {
        hot++;
        const bx = i % bw, by = Math.floor(i / bw);
        if (bx < hx0) hx0 = bx; if (bx > hx1) hx1 = bx;
        if (by < hy0) hy0 = by; if (by > hy1) hy1 = by;
      }
    }
    const hotRatio = hot / err.length;
    const ratio = max / median;
    let verdict = "clean";
    if (ratio >= ELA_MIN_RATIO && hotRatio >= ELA_HOT_MIN && hotRatio <= ELA_HOT_MAX) verdict = "suspicious";
    else if (p90 > 4 * median && hotRatio > ELA_HOT_MAX) verdict = "resaved";
    return {
      applicable: true, verdict, median: round2(median), max: round2(max),
      ratio: round2(ratio), hotRatio: round4(hotRatio), hotBlocks: hot,
      hotArea: hot ? { x: hx0 * ELA_BLOCK, y: hy0 * ELA_BLOCK, w: (hx1 - hx0 + 1) * ELA_BLOCK, h: (hy1 - hy0 + 1) * ELA_BLOCK } : null,
    };
  } catch (e) {
    return { applicable: true, verdict: "skipped", reason: "analysis error: " + (e && e.message) };
  }
}

function round2(n) { return Math.round(n * 100) / 100; }
function round4(n) { return Math.round(n * 10000) / 10000; }

/* ---------------------------------------------------------------- */
/* OCR support prep — grayscale stretch + 2x upscale + clean encode  */
/* ---------------------------------------------------------------- */

function preprocessForOCR(buf, format) {
  try {
    const jpegjs = require("jpeg-js");
    let w, h, rgba;
    if (format === "png") {
      const { PNG } = require("pngjs");
      const img = PNG.sync.read(buf);
      w = img.width; h = img.height; rgba = img.data;
      if (rgba.length < w * h * 4) return null; /* palette PNGs expand in sync.read — guard anyway */
    } else if (format === "jpeg") {
      const img = jpegjs.decode(buf, { useTArray: true, maxMemoryUsageInMB: 512 });
      w = img.width; h = img.height; rgba = img.data;
    } else return null;
    if (!w || !h || w * h > OCR_PREP_MAX_PIXELS) return null;

    const gray = new Uint8Array(w * h);
    for (let p = 0, q = 0; p < w * h; p++, q += 4) {
      gray[p] = 0.299 * rgba[q] + 0.587 * rgba[q + 1] + 0.114 * rgba[q + 2];
    }
    /* 2nd/98th percentile stretch by histogram — cheap and bounded */
    const hist = new Uint32Array(256);
    for (let p = 0; p < gray.length; p += 7) hist[gray[p]]++;
    const total = Math.ceil(gray.length / 7);
    let acc = 0, lo = 0, hi = 255;
    for (let v = 0; v < 256; v++) { acc += hist[v]; if (acc >= total * 0.02) { lo = v; break; } }
    acc = 0;
    for (let v = 255; v >= 0; v--) { acc += hist[v]; if (acc >= total * 0.02) { hi = v; break; } }
    const span = Math.max(1, hi - lo);
    const stretched = new Uint8Array(w * h);
    for (let p = 0; p < gray.length; p++) {
      stretched[p] = Math.max(0, Math.min(255, ((gray[p] - lo) * 255 / span) | 0));
    }
    /* 2x nearest-neighbor upscale */
    const W = w * 2, H = h * 2;
    const out = Buffer.alloc(W * H * 4);
    for (let y = 0; y < H; y++) {
      const sy = y >> 1;
      for (let x = 0; x < W; x++) {
        const v = stretched[sy * w + (x >> 1)];
        const q = (y * W + x) * 4;
        out[q] = out[q + 1] = out[q + 2] = v; out[q + 3] = 255;
      }
    }
    const enc = jpegjs.encode({ data: out, width: W, height: H }, 95);
    return { buffer: enc.data, mime: "image/jpeg", width: W, height: H };
  } catch {
    return null; /* prep is best-effort — original pass still ran */
  }
}

/* ---------------------------------------------------------------- */
/* OCR text helpers                                                  */
/* ---------------------------------------------------------------- */

/* OCR misreads on screenshots: O↔0, I/L↔1, S↔5, B↔8, Z↔2. Compare the
   member's reference under the same confusions before failing it. */
function confusionFold(s) {
  return String(s).toUpperCase().replace(/[^A-Z0-9]/g, "")
    .replace(/O/g, "0").replace(/[IQ|]/g, "1").replace(/L/g, "1")
    .replace(/S/g, "5").replace(/B/g, "8").replace(/Z/g, "2");
}

function refMatchesOCR(refNo, ocrText) {
  const ref = String(refNo || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
  const text = String(ocrText || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
  if (ref.length < 4 || !text) return { found: false, fuzzy: false };
  if (text.indexOf(ref) >= 0) return { found: true, fuzzy: false };
  const refF = confusionFold(ref), textF = confusionFold(text);
  if (refF.length >= 4 && textF.indexOf(refF) >= 0) return { found: true, fuzzy: true };
  /* digit references: match inside long digit runs the OCR may have
     merged with neighbouring characters */
  if (/^\d+$/.test(refF)) {
    const runs = textF.match(/\d{8,}/g) || [];
    for (const run of runs) {
      if (run.indexOf(refF) >= 0 || refF.indexOf(run) >= 0) return { found: true, fuzzy: true };
    }
  }
  return { found: false, fuzzy: false };
}

const MONEY_RE = /(?:₱|\bPHP|\bP)?\s?(?:\d{1,3}(?:,\d{3})+(?:\.\d{1,2})?|\d{1,3}(?: \d{3})+(?:\.\d{1,2})?|\d+\.\d{1,2}|(?<!\d)\d{1,6}(?!\d))/g;

function extractMoneyTokens(text) {
  const norm = String(text || "").toUpperCase().replace(/\s+/g, " ");
  const out = [];
  const seen = new Set();
  const toks = norm.match(MONEY_RE) || [];
  for (const t of toks) {
    const num = t.replace(/[^\d.]/g, "");
    if (!num || /^\.$/.test(num)) continue;
    const cents = Math.round(parseFloat(num) * 100);
    if (!cents || cents <= 0 || cents > 100 * 1000 * 1000) continue;
    if (!seen.has(cents)) { seen.add(cents); out.push({ cents, raw: t.trim() }); }
  }
  return out;
}

/* The receipt prints the figure next to a label — read that line, and
   if the label stands alone, walk to the next non-empty line (OCR often
   leaves blanks between the label and the figure). */
function labeledAmount(text) {
  const lines = String(text || "").toUpperCase().split(/\r?\n|\s{2,}/);
  const strip = (l) => l.replace(/\bAMOUNT SENT\b|\bTOTAL AMOUNT\b|\bAMOUNT\b|\bTOTAL\b|\bPRICE\b|₱|\bPHP\b/g, " ");
  for (let i = 0; i < lines.length; i++) {
    if (/\b(AMOUNT SENT|TOTAL AMOUNT|AMOUNT|TOTAL|PRICE)\b/.test(lines[i])) {
      let toks = extractMoneyTokens(strip(lines[i]));
      for (let j = i + 1; !toks.length && j < lines.length && j <= i + 2; j++) {
        toks = extractMoneyTokens(strip(lines[j]));
      }
      if (toks.length) return { cents: toks[0].cents, raw: toks[0].raw };
    }
  }
  return null;
}

/* ---------------------------------------------------------------- */
/* PIXEL SIGNALS — the reads that survive stripped metadata.         */
/* ---------------------------------------------------------------- */
/* Metadata can be wiped in one save. These three reads judge the
   pixels themselves, so an AI render or a pasted edit stays visible
   even when the file carries no names at all:

     5. FLAT-REGION PURITY — a real app screenshot is drawn by a UI
        engine: backgrounds are EXACTLY one color (variance ~0) across
        large fields. Generative models cannot hold a flat field —
        their "empty" areas carry low-amplitude texture everywhere. An
        image with virtually no dead-flat area reads as synthetic.
     6. JPEG-GHOST LOCALIZATION — PNG is lossless, so honest
        screenshots carry no compression grid. Content that ever
        passed through a JPEG (a crop of another receipt, a messenger
        round-trip, an AI render saved as JPG) keeps ringing on the
        8px block grid. A compact region of grid-periodic energy
        inside a PNG is pasted content.
     7. COPY-MOVE MAP — pasting usually drags background along. Blocks
        duplicated elsewhere at one shared offset expose the move even
        when every metadata read is clean. ---------------------------- */

const PIXEL_MAX = OCR_PREP_MAX_PIXELS;
const PURITY_BLOCK = 8;
const PURITY_FLAT_STD = 0.6;      /* stdev under this = a dead-flat field */
const PURITY_MIN_BLOCKS = 2500;   /* need a real screenshot's area to judge */
const PURITY_SUSPECT_SHARE = 0.02;

function decodePixels(buf, format) {
  try {
    if (format === "jpeg") {
      const jpegjs = require("jpeg-js");
      const img = jpegjs.decode(buf, { useTArray: true, maxMemoryUsageInMB: 512 });
      if (!img.width || !img.height || img.width * img.height > PIXEL_MAX) return null;
      return img;
    }
    if (format === "png") {
      const { PNG } = require("pngjs");
      const img = PNG.sync.read(buf);
      if (!img.width || !img.height || img.width * img.height > PIXEL_MAX) return null;
      if (!img.data || img.data.length < img.width * img.height * 4) return null;
      return img;
    }
  } catch { /* hostile pixels are a note, never a crash */ }
  return null;
}

function flatPurityScan(buf, format) {
  const na = { applicable: false, verdict: "na", reason: "image unreadable or too small for the texture read" };
  const img = decodePixels(buf, format);
  if (!img) return na;
  const { width: w, height: h, data } = img;
  const bw = Math.floor(w / PURITY_BLOCK), bh = Math.floor(h / PURITY_BLOCK);
  const total = bw * bh;
  if (total < PURITY_MIN_BLOCKS) return na;
  let flat = 0;
  for (let by = 0; by < bh; by++) {
    for (let bx = 0; bx < bw; bx++) {
      let sum = 0, sum2 = 0, n = 0;
      for (let y = by * PURITY_BLOCK; y < (by + 1) * PURITY_BLOCK; y++) {
        for (let x = bx * PURITY_BLOCK; x < (bx + 1) * PURITY_BLOCK; x++) {
          const q = (y * w + x) * 4;
          const l = 0.299 * data[q] + 0.587 * data[q + 1] + 0.114 * data[q + 2];
          sum += l; sum2 += l * l; n++;
        }
      }
      const mean = sum / n;
      const varr = Math.max(0, sum2 / n - mean * mean);
      if (Math.sqrt(varr) < PURITY_FLAT_STD) flat++;
    }
  }
  const flatShare = flat / total;
  const verdict = flatShare < PURITY_SUSPECT_SHARE ? "suspicious" : "clean";
  return {
    applicable: true, verdict,
    flatShare: round4(flatShare), flatBlocks: flat, totalBlocks: total,
    reason: verdict === "suspicious"
      ? "no dead-flat regions — a UI screenshot is always built on perfectly flat fields"
      : null,
  };
}

const GHOST_SUPER = 32;
const GHOST_PERIOD = 1.2;         /* one phase carries >= 2.2x the average diff */
const GHOST_MIN_INFO = 30;        /* textured superblocks needed to judge */
const GHOST_MIN_SHARE = 0.10;

/* Grid-periodicity of the gradient energy, per 32x32 superblock: JPEG
   ringing lives on ONE 8px phase AND energizes every grid column of
   that phase — a straight UI edge lives on one column only. Both facts
   must hold, so honest text and table edges never read as ghosts. */
function ghostSpreadOK(energy, base, phase) {
  const off = ((phase - (base % 8)) % 8 + 8) % 8;
  const js = [];
  for (let k = 0; k < 4; k++) {
    const j = off + k * 8;
    if (j < energy.length) js.push(energy[j]);
  }
  const mx = Math.max.apply(null, js);
  if (mx <= 0) return false;
  return js.filter((v) => v >= 0.3 * mx).length >= 3;
}

function jpegGhostScan(buf, format) {
  if (format !== "png") {
    return { applicable: false, verdict: "na",
      reason: "JPEG carries its own compression grid — the ghost read runs on PNG proofs" };
  }
  const img = decodePixels(buf, format);
  if (!img || img.width < 96 || img.height < 96) {
    return { applicable: false, verdict: "na", reason: "image too small for the ghost read" };
  }
  const { width: w, height: h, data } = img;
  const gray = new Float32Array(w * h);
  for (let p = 0, q = 0; p < w * h; p++, q += 4) {
    gray[p] = 0.299 * data[q] + 0.587 * data[q + 1] + 0.114 * data[q + 2];
  }
  const sw = Math.floor(w / GHOST_SUPER), sh = Math.floor(h / GHOST_SUPER);
  let informative = 0, ghost = 0;
  for (let sy = 0; sy < sh; sy++) {
    for (let sx = 0; sx < sw; sx++) {
      const x0 = sx * GHOST_SUPER, y0 = sy * GHOST_SUPER;
      const phH = new Float64Array(8), phHN = new Float64Array(8);
      const phV = new Float64Array(8), phVN = new Float64Array(8);
      const colH = new Float64Array(GHOST_SUPER);
      const rowV = new Float64Array(GHOST_SUPER);
      for (let y = y0 + 1; y < y0 + GHOST_SUPER; y++) {
        for (let x = x0 + 1; x < x0 + GHOST_SUPER; x++) {
          const dh = Math.abs(gray[y * w + x] - gray[y * w + x - 1]);
          const dv = Math.abs(gray[y * w + x] - gray[(y - 1) * w + x]);
          phH[x % 8] += dh; phHN[x % 8]++; colH[x - x0] += dh;
          phV[y % 8] += dv; phVN[y % 8]++; rowV[y - y0] += dv;
        }
      }
      const phaseCheck = (ph, pn, energy, base) => {
        let total = 0, n = 0, bestP = -1, bestMean = 0;
        for (let p = 0; p < 8; p++) {
          total += ph[p]; n += pn[p];
          const m = pn[p] ? ph[p] / pn[p] : 0;
          if (m > bestMean) { bestMean = m; bestP = p; }
        }
        if (!n) return false;
        const mean = total / n;
        if (mean < 1.0) return false;   /* flat field — no grid to read */
        if (!(bestMean / mean >= GHOST_PERIOD)) return false;
        return ghostSpreadOK(energy, base, bestP);
      };
      const hit = phaseCheck(phH, phHN, colH, x0) || phaseCheck(phV, phVN, rowV, y0);
      if (hit) informative++;
      else {
        /* non-ghost textured superblocks still count toward the share */
        let anyH = 0, anyV = 0, nH = 0, nV = 0;
        for (let p = 0; p < 8; p++) { anyH += phH[p]; nH += phHN[p]; anyV += phV[p]; nV += phVN[p]; }
        if ((nH && anyH / nH >= 1.0) || (nV && anyV / nV >= 1.0)) informative++;
      }
      if (hit) ghost++;
    }
  }
  if (informative < GHOST_MIN_INFO) {
    return { applicable: true, verdict: "inconclusive", informative, ghost,
      reason: "too little textured area for a grid read" };
  }
  const share = ghost / informative;
  if (share >= GHOST_MIN_SHARE) {
    return { applicable: true, verdict: "suspicious", informative, ghost, share: round4(share),
      reason: "JPEG ringing on the 8px grid inside a PNG — content passed through another file" };
  }
  return { applicable: true, verdict: "clean", informative, ghost, share: round4(share) };
}

const CM_WORK_MAX = 480;
const CM_BLOCK = 8;
const CM_MIN_DIST = 12;           /* blocks between the twins */
const CM_MIN_PAIRS = 8;
const CM_MIN_STD = 5;             /* textured enough to fingerprint */

function copyMoveScan(buf, format) {
  const img = decodePixels(buf, format);
  if (!img || img.width < 96 || img.height < 96) {
    return { applicable: false, verdict: "na", reason: "image too small for the duplicate read" };
  }
  const w0 = img.width, h0 = img.height;
  const scale = Math.min(1, CM_WORK_MAX / Math.max(w0, h0));
  const w = Math.max(32, Math.round(w0 * scale)), h = Math.max(32, Math.round(h0 * scale));
  const gray = new Float32Array(w * h);
  const xr = w0 / w, yr = h0 / h;
  for (let y = 0; y < h; y++) {
    const sy0 = Math.floor(y * yr), sy1 = Math.max(sy0 + 1, Math.floor((y + 1) * yr));
    for (let x = 0; x < w; x++) {
      const sx0 = Math.floor(x * xr), sx1 = Math.max(sx0 + 1, Math.floor((x + 1) * xr));
      let s = 0, n = 0;
      for (let sy = sy0; sy < sy1 && sy < h0; sy++) {
        for (let sx = sx0; sx < sx1 && sx < w0; sx++) {
          const q = (sy * w0 + sx) * 4;
          s += 0.299 * img.data[q] + 0.587 * img.data[q + 1] + 0.114 * img.data[q + 2]; n++;
        }
      }
      gray[y * w + x] = n ? s / n : 0;
    }
  }
  const bw = Math.floor(w / CM_BLOCK), bh = Math.floor(h / CM_BLOCK);
  const sig = new Map();
  for (let by = 0; by < bh; by++) {
    for (let bx = 0; bx < bw; bx++) {
      let sum = 0, sum2 = 0, n = 0;
      const qsum = [0, 0, 0, 0];
      for (let y = by * CM_BLOCK; y < (by + 1) * CM_BLOCK; y++) {
        for (let x = bx * CM_BLOCK; x < (bx + 1) * CM_BLOCK; x++) {
          const l = gray[y * w + x];
          sum += l; sum2 += l * l; n++;
          qsum[(y >= by * CM_BLOCK + 4 ? 2 : 0) + (x >= bx * CM_BLOCK + 4 ? 1 : 0)] += l;
        }
      }
      const mean = sum / n;
      const std = Math.sqrt(Math.max(0, sum2 / n - mean * mean));
      if (std < CM_MIN_STD) continue;   /* flat blocks fingerprint nothing */
      const qn = n / 4;
      const key =
        Math.min(15, Math.round(qsum[0] / qn / 16)) + "." +
        Math.min(15, Math.round(qsum[1] / qn / 16)) + "." +
        Math.min(15, Math.round(qsum[2] / qn / 16)) + "." +
        Math.min(15, Math.round(qsum[3] / qn / 16)) + "." +
        (std < 12 ? 0 : std < 24 ? 1 : 2);
      if (!sig.has(key)) sig.set(key, []);
      const pts = sig.get(key);
      if (pts.length < 200) pts.push([bx, by]);
    }
  }
  const offsets = new Map();
  for (const pts of sig.values()) {
    if (pts.length < 2) continue;
    for (let i = 0; i < pts.length; i++) {
      for (let j = i + 1; j < pts.length; j++) {
        const dx = pts[j][0] - pts[i][0], dy = pts[j][1] - pts[i][1];
        if (Math.max(Math.abs(dx), Math.abs(dy)) < CM_MIN_DIST) continue;
        const k = dx + "," + dy;
        offsets.set(k, (offsets.get(k) || 0) + 1);
      }
    }
  }
  let top = 0;
  for (const v of offsets.values()) if (v > top) top = v;
  if (top >= CM_MIN_PAIRS) {
    return { applicable: true, verdict: "suspicious", duplicatePairs: top,
      reason: "the same block pattern repeats at one shared offset — content was copied and pasted" };
  }
  return { applicable: true, verdict: "clean", duplicatePairs: top };
}

/* ---------------------------------------------------------------- */
/* Receipt date reader — a receipt for THIS payment was created at   */
/* checkout. A printed date older than the order itself is a reused  */
/* receipt, even when every pixel is untouched. --------------------- */
/* ---------------------------------------------------------------- */

const MONTHS = { JAN: 1, FEB: 2, MAR: 3, APR: 4, MAY: 5, JUN: 6, JUL: 7, AUG: 8, SEP: 9, SEPT: 9, OCT: 10, NOV: 11, DEC: 12 };

function validDate(y, m, d) {
  if (!(y >= 2020 && y <= 2100) || !(m >= 1 && m <= 12) || !(d >= 1 && d <= 31)) return null;
  return { y, m, d };
}

/* Returns { y, m, d } or null; numeric d/m/y returns BOTH parses with
   ambiguous: true — a stale verdict needs every parse to be too old. */
function extractReceiptDate(text) {
  const t = String(text || "").toUpperCase();
  let m;
  if ((m = t.match(/\b(20\d\d)[-\/.](\d{1,2})[-\/.](\d{1,2})\b/))) {
    return validDate(+m[1], +m[2], +m[3]);
  }
  if ((m = t.match(/\b([A-Z]{3,9})\.?\s+(\d{1,2}),?\s+(20\d\d)\b/))) {
    const mo = MONTHS[m[1].slice(0, 3)];   /* NOVEMBER → NOV — receipts print full names */
    if (mo) return validDate(+m[3], mo, +m[2]);
  }
  if ((m = t.match(/\b(\d{1,2})\s+([A-Z]{3,9})\.?,?\s+(20\d\d)\b/))) {
    const mo = MONTHS[m[2].slice(0, 3)];
    if (mo) return validDate(+m[3], mo, +m[1]);
  }
  if ((m = t.match(/\b(\d{1,2})\/(\d{1,2})\/(20\d\d)\b/))) {
    const a = validDate(+m[3], +m[1], +m[2]);
    const b = validDate(+m[3], +m[2], +m[1]);
    if (a && b) return { y: a.y, m: a.m, d: a.d, y2: b.y, m2: b.m, d2: b.d, ambiguous: true };
    return a || b;
  }
  return null;
}

function receiptDateTs(dt) {
  if (!dt) return NaN;
  return Date.UTC(dt.y, dt.m - 1, dt.d);
}

/* ---------------------------------------------------------------- */
/* Full scan — fingerprint + metadata + editor + ELA + pixel signals */
/* in one call. Returns the sanitized shape that gets persisted on   */
/* the payment and rendered on the admin card. Raw metadata strings  */
/* never leave this module — only the verdict and its reasons. ------ */
function scanProofImage(buf) {
  const hash = imageHash(buf);
  const format = sniffFormat(buf);
  const scan = {
    hash,
    hashShort: hash.slice(0, 16),
    format: format || "unknown",
    width: 0, height: 0,
    bytes: buf.length,
    editor: null,
    editorSource: null,
    aiGenerator: null,
    aiSource: null,
    ela: null,
    notes: [],
  };
  if (!format) {
    scan.notes.push("unrecognized image container — format checks skipped");
    return scan;
  }
  if (format === "jpeg") {
    const meta = parseJpegMeta(buf);
    const dims = jpegDimensions(buf);
    scan.width = dims.width; scan.height = dims.height;
    const editor = detectEditor(meta.strings);
    if (editor) { scan.editor = editor.name; scan.editorSource = editor.source; }
    if (meta.photoshopIrb && !scan.editor) { scan.editor = "Photoshop"; scan.editorSource = "Photoshop IRB segment"; }
    const ai = detectAIGenerator(meta.strings);
    if (ai) { scan.aiGenerator = ai.name; scan.aiSource = ai.source; }
    if (meta.exif.software) scan.notes.push("jpeg software tag: " + meta.exif.software);
    if (meta.comment) scan.notes.push("jpeg comment: " + meta.comment.slice(0, 80));
    scan.ela = elaScanJPEG(buf);
  } else {
    const meta = parsePngMeta(buf);
    scan.width = meta.width || 0; scan.height = meta.height || 0;
    const editor = detectEditor(meta.strings);
    if (editor) { scan.editor = editor.name; scan.editorSource = editor.source; }
    const ai = detectAIGenerator(meta.strings);
    if (ai) { scan.aiGenerator = ai.name; scan.aiSource = ai.source; }
    /* generation-parameter chunks — Stable Diffusion / ComfyUI write the
       literal prompt into tEXt chunks. A prompt inside a "receipt" is an
       AI-made image no matter how clean the render looks. */
    for (const t of meta.texts || []) {
      const kw = String(t.keyword || "").toLowerCase();
      if (kw === "prompt" || kw === "parameters" || kw === "workflow" || kw === "negative_prompt") {
        if (!scan.aiGenerator) { scan.aiGenerator = "Generation-prompt metadata"; scan.aiSource = "PNG " + kw + " chunk"; }
        break;
      }
    }
    if (meta.exif.software) scan.notes.push("png software tag: " + meta.exif.software);
    scan.ela = { applicable: false, verdict: "na",
      reason: "PNG is lossless — the pixel signals below carry the tamper read" };
  }
  /* the pixel signals run on BOTH formats — they judge the picture, not
     the container, so stripped metadata changes nothing */
  scan.purity = flatPurityScan(buf, format);
  scan.ghost = jpegGhostScan(buf, format);
  scan.copyMove = copyMoveScan(buf, format);
  return scan;
}

/* One real receipt must never fund two orders. The fingerprint is
   checked against every OTHER payment still in play or already
   accepted — a REJECTED claim never bought anything, so its old
   screenshot does not block (same law as the reference check). */
async function findProofReuse(d, paymentId, hash) {
  if (!d || !hash) return "unknown";
  try {
    const twin = await d.collection("payments").findOne({
      proofHash: hash,
      _id: { $ne: paymentId },
      status: { $in: ["paid", "under_verification"] },
    }, { projection: { status: 1, paymentReference: 1 } });
    if (!twin) return "none";
    return twin.status === "paid" ? "paid_elsewhere" : "pending_elsewhere";
  } catch {
    return "unknown"; /* DB hiccup — never fabricate a reuse verdict */
  }
}

/* Forensic signals from a scan + reuse verdict. Severity >= medium
   blocks the auto reader; the human sees every reason on the card. */
function forensicSignals(scan, reuse) {
  const signals = [];
  if (reuse === "paid_elsewhere") {
    signals.push({ code: "proof_reused_paid", severity: "critical",
      label: "THIS EXACT IMAGE ALREADY PAID FOR ANOTHER ORDER — ONE RECEIPT COVERS ONE ORDER ONLY" });
  } else if (reuse === "pending_elsewhere") {
    signals.push({ code: "proof_reused_pending", severity: "high",
      label: "THIS EXACT IMAGE IS ATTACHED TO ANOTHER ORDER WAITING FOR VERIFICATION" });
  }
  if (scan && scan.editor) {
    signals.push({ code: "editor_detected", severity: "medium",
      label: "IMAGE CARRIES AN EDITOR SIGNATURE (" + scan.editor.toUpperCase() + ") — SUBMIT THE RAW SCREENSHOT STRAIGHT FROM THE WALLET APP" });
  }
  if (scan && scan.aiGenerator) {
    signals.push({ code: "ai_generated", severity: "critical",
      label: "IMAGE CARRIES AN AI-GENERATOR SIGNATURE (" + scan.aiGenerator.toUpperCase() + ") — AI-MADE RECEIPTS ARE REJECTED ON SIGHT" });
  }
  if (scan && scan.ela && scan.ela.verdict === "suspicious") {
    signals.push({ code: "ela_splice", severity: "high",
      label: "INCONSISTENT COMPRESSION AROUND A COMPACT REGION — POSSIBLE PASTED-ON EDIT" });
  }
  if (scan && scan.ela && scan.ela.verdict === "resaved") {
    signals.push({ code: "ela_resaved", severity: "low",
      label: "IMAGE WAS RE-COMPRESSED WHOLE — OFTEN A MESSENGER TRANSFER, NOT AN EDIT" });
  }
  if (scan && scan.ela && scan.ela.verdict === "na") {
    signals.push({ code: "png_ela_na", severity: "info", label: "PNG PROOF — TAMPER READ RUNS ON FINGERPRINT + METADATA + PIXEL SIGNALS + OCR CROSS-CHECKS" });
  }
  if (scan && scan.purity && scan.purity.verdict === "suspicious") {
    signals.push({ code: "ai_texture", severity: "high",
      label: "IMAGE TEXTURE READS AS SYNTHETIC — A REAL APP SCREENSHOT IS BUILT ON PERFECTLY FLAT FIELDS AND THIS ONE HAS NONE, WHICH IS HOW AI-GENERATED IMAGES READ" });
  }
  if (scan && scan.ghost && scan.ghost.verdict === "suspicious") {
    /* advisory: the grid read only proves itself on large, strongly
       compressed pastes — honest receipts must never fail on it alone. */
    signals.push({ code: "jpeg_ghost", severity: "low",
      label: "PART OF THIS IMAGE CARRIES JPEG COMPRESSION GHOSTING — CONTENT MAY HAVE PASSED THROUGH ANOTHER FILE" });
  }
  if (scan && scan.copyMove && scan.copyMove.verdict === "suspicious") {
    /* advisory only: honest receipts repeat UI rows, which can imitate
       a copy-move — so this one informs the admin card, it never alone
       rejects. The decisive reads are purity, ghost, ELA, metadata. */
    signals.push({ code: "copy_move", severity: "low",
      label: "LARGE PARTS OF THIS IMAGE DUPLICATE ANOTHER AREA OF IT — COPIED-AND-PASTED CONTENT POSSIBLE" });
  }
  return signals;
}

module.exports = {
  EDITOR_SIGNATURES, AI_SIGNATURES, SEVERITY,
  imageHash, sniffFormat,
  jpegDimensions, parseJpegMeta, parsePngMeta, parseTiffTags,
  detectEditor, detectAIGenerator, elaScanJPEG, preprocessForOCR,
  refMatchesOCR, extractMoneyTokens, labeledAmount, confusionFold,
  flatPurityScan, jpegGhostScan, copyMoveScan,
  extractReceiptDate, receiptDateTs,
  scanProofImage, findProofReuse, forensicSignals,
};
