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
/* Full scan — fingerprint + metadata + editor + ELA in one call.    */
/* Returns the sanitized shape that gets persisted on the payment    */
/* and rendered on the admin card. Raw metadata strings never leave  */
/* this module — only the verdict and its reasons. ------------------ */
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
      reason: "PNG is lossless — fingerprint, metadata and OCR cross-checks carry the tamper read" };
  }
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
    signals.push({ code: "png_ela_na", severity: "info", label: "PNG PROOF — TAMPER READ RUNS ON FINGERPRINT + METADATA + OCR CROSS-CHECKS" });
  }
  return signals;
}

module.exports = {
  EDITOR_SIGNATURES, AI_SIGNATURES, SEVERITY,
  imageHash, sniffFormat,
  jpegDimensions, parseJpegMeta, parsePngMeta, parseTiffTags,
  detectEditor, detectAIGenerator, elaScanJPEG, preprocessForOCR,
  refMatchesOCR, extractMoneyTokens, labeledAmount, confusionFold,
  scanProofImage, findProofReuse, forensicSignals,
};
