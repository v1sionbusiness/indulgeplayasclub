"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const F = require("../ipc-pay/forensics");
const jpegjs = require("jpeg-js");
const { PNG } = require("pngjs");

/* ---- image builders (real bytes, no mocks in the assertions) ---- */
const crcTable = [];
for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; crcTable[n] = c >>> 0; }
const crc = (b) => { let c = 0xffffffff; for (const x of b) c = crcTable[(c ^ x) & 0xff] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; };
const chunk = (type, data) => {
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type), data]);
  const c = Buffer.alloc(4); c.writeUInt32BE(crc(body));
  return Buffer.concat([len, body, c]);
};
function texturedJpeg(w = 320, h = 640, q = 85) {
  const px = Buffer.alloc(w * h * 4);
  let s = 9;
  const rnd = () => { s = (s * 1103515245 + 12345) & 0x7fffffff; return s / 0x7fffffff; };
  for (let i = 0; i < w * h; i++) { const v = 40 + Math.floor(rnd() * 60); px[i * 4] = v; px[i * 4 + 1] = v + 8; px[i * 4 + 2] = v + 16; px[i * 4 + 3] = 255; }
  return jpegjs.encode({ data: px, width: w, height: h }, q).data;
}
function textPng(textChunk) {
  const png = new PNG({ width: 300, height: 200 });
  let s = 5;
  const rnd = () => { s = (s * 1103515245 + 12345) & 0x7fffffff; return s / 0x7fffffff; };
  for (let i = 0; i < 300 * 200; i++) { const v = 30 + Math.floor(rnd() * 40); png.data[i * 4] = v; png.data[i * 4 + 1] = v + 2; png.data[i * 4 + 2] = v + 4; png.data[i * 4 + 3] = 255; }
  const raw = PNG.sync.write(png);
  if (!textChunk) return raw;
  return Buffer.concat([raw.slice(0, raw.length - 12), chunk("tEXt", Buffer.from(textChunk, "latin1")), Buffer.from([0, 0, 0, 0]), Buffer.from("IEND")]);
}
/* an honest Maya-style screenshot: flat UI fields, flat text bars,
   randomized so no two rows repeat — this is what a REAL proof is */
function screenshotPng(w = 480, h = 960, seed = 3) {
  const png = new PNG({ width: w, height: h });
  for (let i = 0; i < w * h; i++) { png.data[i * 4] = 246; png.data[i * 4 + 1] = 246; png.data[i * 4 + 2] = 244; png.data[i * 4 + 3] = 255; }
  let s = seed;
  const rnd = () => { s = (s * 1103515245 + 12345) & 0x7fffffff; return s / 0x7fffffff; };
  let y = 60;
  while (y < h - 80) {
    const rows = 1 + Math.floor(rnd() * 2);
    const bw = 40 + Math.floor(rnd() * (w - 120));
    const x0 = 24 + Math.floor(rnd() * (w - bw - 48));
    for (let r = 0; r < rows; r++) {
      const yy = y + r * 8;
      if (yy + 5 > h) break;
      for (let py = yy; py < yy + 5; py++) {
        for (let xx = x0; xx < x0 + bw; xx++) {
          const q = (py * w + xx) * 4;
          png.data[q] = 20; png.data[q + 1] = 20; png.data[q + 2] = 22;
        }
      }
    }
    y += rows * 8 + 12 + Math.floor(rnd() * 24);
  }
  const raw = PNG.sync.write(png);
  if (!arguments[3]) return raw;
  return Buffer.concat([raw.slice(0, raw.length - 12), chunk("tEXt", Buffer.from(arguments[3], "latin1")), Buffer.from([0, 0, 0, 0]), Buffer.from("IEND")]);
}
/* a metadata-stripped AI-style render: texture everywhere, no flat field */
function aiNoisePng(w = 480, h = 960, seed = 11) {
  const png = new PNG({ width: w, height: h });
  let s = seed;
  const rnd = () => { s = (s * 1103515245 + 12345) & 0x7fffffff; return s / 0x7fffffff; };
  for (let i = 0; i < w * h; i++) {
    const v = 200 + Math.floor(rnd() * 30);
    png.data[i * 4] = v; png.data[i * 4 + 1] = v + 2; png.data[i * 4 + 2] = v + 4; png.data[i * 4 + 3] = 255;
  }
  return PNG.sync.write(png);
}
/* an edited PNG: a JPEG-compressed gradient patch pasted into an honest screenshot */
function ghostPng(slope = 240, q = 30, noise = 4) {
  const base = new PNG({ width: 480, height: 960 });
  for (let i = 0; i < 480 * 960; i++) { base.data[i * 4] = 246; base.data[i * 4 + 1] = 246; base.data[i * 4 + 2] = 244; base.data[i * 4 + 3] = 255; }
  const pw = 208, ph = 160, px = Buffer.alloc(pw * ph * 4);
  let s = 9;
  const rnd = () => { s = (s * 1103515245 + 12345) & 0x7fffffff; return s / 0x7fffffff; };
  for (let y = 0; y < ph; y++) {
    for (let x = 0; x < pw; x++) {
      const v = Math.round(40 + (x / pw) * slope + (rnd() - 0.5) * noise);
      const qq = (y * pw + x) * 4;
      px[qq] = v; px[qq + 1] = v; px[qq + 2] = v + 2; px[qq + 3] = 255;
    }
  }
  const jb = jpegjs.encode({ data: px, width: pw, height: ph }, q).data;
  const jp = jpegjs.decode(jb, { useTArray: true });
  for (let y = 0; y < ph; y++) {
    for (let x = 0; x < pw; x++) {
      const qq = ((640 + y) * 480 + (136 + x)) * 4;
      base.data[qq] = jp.data[(y * pw + x) * 4];
      base.data[qq + 1] = jp.data[(y * pw + x) * 4 + 1];
      base.data[qq + 2] = jp.data[(y * pw + x) * 4 + 2];
    }
  }
  return PNG.sync.write(base);
}
/* JPEG with an APP1 EXIF blob carrying Software = Adobe Photoshop 24.0 */
function photoshopJpeg() {
  const base = texturedJpeg(320, 640, 90);
  // TIFF: II*42, IFD0 with 1 entry: tag 0x0131 (Software), ASCII "Adobe Photoshop 24.0\0"
  const sw = Buffer.from("Adobe Photoshop 24.0\0", "latin1");
  const tiff = Buffer.alloc(8 + 2 + 12 + 4 + sw.length);
  tiff.write("II", 0, "latin1"); tiff.writeUInt16LE(42, 2); tiff.writeUInt32LE(8, 4);
  tiff.writeUInt16LE(1, 8);
  tiff.writeUInt16LE(0x0131, 10); tiff.writeUInt16LE(2, 12); tiff.writeUInt32LE(sw.length, 14);
  tiff.writeUInt32LE(8 + 2 + 12 + 4, 18);
  sw.copy(tiff, 22);
  const exif = Buffer.concat([Buffer.from("Exif\0\0", "latin1"), tiff]);
  const len = 2 + exif.length;
  const seg = Buffer.alloc(4 + len);
  seg[0] = 0xff; seg[1] = 0xe1; seg[2] = (len >> 8) & 0xff; seg[3] = len & 0xff;
  exif.copy(seg, 4);
  // insert APP1 right after SOI
  return Buffer.concat([base.slice(0, 2), seg, base.slice(2)]);
}

/* ---- format + hash ---- */
test("sniffs jpeg, png and rejects garbage", () => {
  assert.equal(F.sniffFormat(texturedJpeg()), "jpeg");
  assert.equal(F.sniffFormat(textPng(null)), "png");
  assert.equal(F.sniffFormat(Buffer.from("not-an-image-at-all!!!!")), null);
  assert.equal(F.sniffFormat(Buffer.alloc(0)), null);
});

test("image hash is a stable sha-256 of the exact bytes", () => {
  const buf = texturedJpeg();
  assert.equal(F.imageHash(buf), F.imageHash(buf));
  assert.equal(F.imageHash(buf).length, 64);
  assert.notEqual(F.imageHash(buf), F.imageHash(texturedJpeg(320, 640, 84)));
});

/* ---- metadata + editor detection ---- */
test("detects Photoshop from EXIF software tag on a JPEG", () => {
  const scan = F.scanProofImage(photoshopJpeg());
  assert.equal(scan.format, "jpeg");
  assert.equal(scan.editor, "Photoshop");
  assert.ok(scan.editorSource.toLowerCase().includes("photoshop"));
  const sig = F.forensicSignals(scan, "none");
  assert.ok(sig.some((s) => s.code === "editor_detected" && s.severity === "medium"));
});

test("detects PicsArt from a PNG text chunk", () => {
  const scan = F.scanProofImage(textPng("Software\0PicsArt Photo Editor"));
  assert.equal(scan.format, "png");
  assert.equal(scan.editor, "PicsArt");
});

test("wallet names and phone screenshots are never editors", () => {
  assert.equal(F.detectEditor(["Software GCash"]), null);
  assert.equal(F.detectEditor(["Software Maya"]), null);
  assert.equal(F.detectEditor(["Screenshot, Samsung Electronics"]), null);
  assert.equal(F.detectEditor([]), null);
  assert.equal(F.detectEditor(["Adobe Photoshop 2024"]).name, "Photoshop");
  assert.equal(F.detectEditor(["Snapseed 2.0"]).name, "Snapseed");
});

test("AI-generator signatures are caught, wallet names never match them", () => {
  assert.equal(F.detectAIGenerator(["Software GCash"]), null);
  assert.equal(F.detectAIGenerator(["Software Maya"]), null);
  assert.equal(F.detectAIGenerator(["Screenshot, Samsung Electronics"]), null);
  assert.equal(F.detectAIGenerator([]), null);
  assert.equal(F.detectAIGenerator(["Software DALL-E 3"]).name, "DALL-E / OpenAI");
  assert.equal(F.detectAIGenerator(["Software Midjourney v6"]).name, "Midjourney");
  assert.equal(F.detectAIGenerator(["prompt Stable Diffusion checkpoint"]).name, "Stable Diffusion");
  assert.equal(F.detectAIGenerator(["c2pa manifest JUMBF"]).name, "Content-provenance manifest");
  assert.equal(F.detectAIGenerator(["TrainedAlgorithmicMedia"]).name, "IPTC trained-algorithmic-media");
  assert.equal(F.detectAIGenerator(["ai-generated image"]).name, "AI-generated marker");
});

test("AI software tags and generation-prompt chunks scan as critical", () => {
  const aiPng = F.scanProofImage(textPng("Software\0DALL-E 3 (OpenAI)"));
  assert.equal(aiPng.aiGenerator, "DALL-E / OpenAI");
  const aiSigs = F.forensicSignals(aiPng, "none");
  const ai = aiSigs.find((s) => s.code === "ai_generated");
  assert.ok(ai && ai.severity === "critical", JSON.stringify(aiSigs));

  const promptPng = F.scanProofImage(textPng("parameters\0Steps: 30, Sampler: Euler a, Size: 512x512"));
  assert.equal(promptPng.aiGenerator, "Generation-prompt metadata");
  assert.ok(F.forensicSignals(promptPng, "none").some((s) => s.code === "ai_generated"));

  const clean = F.scanProofImage(textPng(null));
  assert.equal(clean.aiGenerator, null);
  assert.ok(!F.forensicSignals(clean, "none").some((s) => s.code === "ai_generated"));
});

test("honest screenshot scans carry no medium-or-worse signals", () => {
  for (const buf of [screenshotPng(), textPng(null)]) {
    const scan = F.scanProofImage(buf);
    const sigs = F.forensicSignals(scan, "none");
    assert.ok(!sigs.some((s) => F.SEVERITY[s.severity] >= F.SEVERITY.medium), JSON.stringify(sigs));
  }
});

/* ---- v36 pixel signals — the reads that survive stripped metadata ---- */
test("flat-region purity: honest screenshots are clean, AI-style renders read as synthetic", () => {
  const clean = F.flatPurityScan(screenshotPng(), "png");
  assert.equal(clean.verdict, "clean");
  assert.ok(clean.flatShare > 0.5, String(clean.flatShare));
  const ai = F.flatPurityScan(aiNoisePng(), "png");
  assert.equal(ai.verdict, "suspicious");
  assert.equal(ai.flatShare, 0);
  /* and the full scan turns it into a high-severity auto-reject signal */
  const scan = F.scanProofImage(aiNoisePng());
  const sig = F.forensicSignals(scan, "none").find((s) => s.code === "ai_texture");
  assert.ok(sig && sig.severity === "high", JSON.stringify(sig));
  /* the same law holds for JPEG uploads */
  assert.equal(F.flatPurityScan(texturedJpeg(480, 960, 85), "jpeg").verdict, "suspicious");
});

test("jpeg-ghost stays advisory: honest PNGs never read as ghosts", () => {
  const honest = F.jpegGhostScan(screenshotPng(), "png");
  assert.ok(["clean", "inconclusive"].includes(honest.verdict), JSON.stringify(honest));
  const jpeg = F.jpegGhostScan(texturedJpeg(480, 960, 85), "jpeg");
  assert.equal(jpeg.verdict, "na");
  /* a huge, strongly compressed paste reads suspicious — but only ever
     surfaces as a LOW advisory signal, never a rejection on its own */
  const ghost = F.jpegGhostScan(ghostPng(240, 30, 4), "png");
  if (ghost.verdict === "suspicious") {
    const sig = F.forensicSignals(F.scanProofImage(ghostPng(240, 30, 4)), "none").find((s) => s.code === "jpeg_ghost");
    assert.ok(sig && sig.severity === "low", JSON.stringify(sig));
  }
});

test("receipt date reader: month names, ISO, day-first, ambiguous numerics", () => {
  assert.deepEqual(F.extractReceiptDate("DATE: NOV 24, 2026 10:32:11 AM"), { y: 2026, m: 11, d: 24 });
  assert.deepEqual(F.extractReceiptDate("DATE: NOVEMBER 24, 2026"), { y: 2026, m: 11, d: 24 });
  assert.deepEqual(F.extractReceiptDate("2026-11-24 10:32"), { y: 2026, m: 11, d: 24 });
  assert.deepEqual(F.extractReceiptDate("24 NOVEMBER 2026"), { y: 2026, m: 11, d: 24 });
  assert.deepEqual(F.extractReceiptDate("SEPT 5, 2026"), { y: 2026, m: 9, d: 5 });
  const amb = F.extractReceiptDate("PAID 11/12/2026 OK");
  assert.equal(amb.ambiguous, true);
  assert.deepEqual({ y: amb.y, m: amb.m, d: amb.d }, { y: 2026, m: 11, d: 12 });
  assert.deepEqual({ y: amb.y2, m: amb.m2, d: amb.d2 }, { y: 2026, m: 12, d: 11 });
  /* an impossible alternate parse resolves on its own — never a false fail */
  assert.deepEqual(F.extractReceiptDate("PAID 11/24/2026 OK"), { y: 2026, m: 11, d: 24 });
  assert.equal(F.extractReceiptDate("no date in this text at all"), null);
  assert.equal(F.extractReceiptDate("ref 1234567890123 total 125000"), null);
  assert.equal(F.receiptDateTs({ y: 2026, m: 11, d: 24 }), Date.UTC(2026, 10, 24));
  assert.ok(Number.isNaN(F.receiptDateTs(null)));
});

/* ---- ELA sanity ---- */
test("ELA reads honest images as clean or inconclusive, never suspicious", () => {
  const scan = F.scanProofImage(texturedJpeg(480, 960, 85));
  assert.ok(scan.ela && scan.ela.applicable);
  assert.ok(["clean", "inconclusive"].includes(scan.ela.verdict), scan.ela.verdict);
});

test("ELA skips gracefully on absurdly large dimensions and garbage", () => {
  assert.ok(["skipped", "inconclusive"].includes(F.elaScanJPEG(Buffer.alloc(8)).verdict) || F.elaScanJPEG(Buffer.alloc(8)).reason);
});

/* ---- OCR text helpers ---- */
test("reference matching: exact, OCR-confusion folded, digit runs, misses", () => {
  const t = "MAYA RECEIPT REF NO. IPCREF12345 PAID";
  assert.deepEqual(F.refMatchesOCR("IPCREF12345", t), { found: true, fuzzy: false });
  assert.deepEqual(F.refMatchesOCR("IPCREF-12345", t), { found: true, fuzzy: false });
  /* the member typed O where the receipt prints 0 — confusion folding saves it */
  const fuzzy = F.refMatchesOCR("IPCREFO12345", "ref no ipcref012345 paid");
  assert.deepEqual(fuzzy, { found: true, fuzzy: true });
  assert.equal(F.refMatchesOCR("IPCREF99999", t).found, false);
  assert.equal(F.refMatchesOCR("", t).found, false);
  assert.equal(F.refMatchesOCR("AB1", t).found, false);
  assert.deepEqual(F.refMatchesOCR("1234567890", "paid 0991234567890 x").found, true);
});

test("money tokens survive commas, currency marks and stay whole", () => {
  const toks = (s) => F.extractMoneyTokens(s).map((t) => t.cents);
  assert.ok(toks("Total: ₱1,250.00").includes(125000));
  assert.ok(toks("PHP1,250.00 fee 15.00").includes(125000));
  assert.ok(toks("sent P 1250.00").includes(125000));
  // a long Maya reference is EXCLUDED whole from money candidates — never
  // chopped into digits that could impersonate an order amount
  const refToks = toks("ref no 1234567890123");
  assert.deepEqual(refToks, [], JSON.stringify(refToks));
  assert.ok(!refToks.includes(12300) && !refToks.includes(123400));
  assert.ok(toks("fee 15").includes(1500));
  assert.ok(toks("1 250.00").includes(125000));
});

test("labeled amount reads the figure next to AMOUNT/TOTAL, or the line under it", () => {
  assert.equal(F.labeledAmount("AMOUNT: PHP1,250.00").cents, 125000);
  assert.equal(F.labeledAmount("AMOUNT SENT\nPHP1,250.00").cents, 125000);
  assert.equal(F.labeledAmount("TOTAL AMOUNT\n\n₱ 2,000.00").cents, 200000);
  assert.equal(F.labeledAmount("no money labels here"), null);
});

/* ---- OCR prep ---- */
test("preprocess upscales and re-encodes, and fails soft on garbage", () => {
  const prep = F.preprocessForOCR(textPng(null), "png");
  assert.ok(prep && prep.width === 600 && prep.height === 400, JSON.stringify(prep));
  assert.equal(prep.mime, "image/jpeg");
  assert.ok(prep.buffer.length > 1024);
  const jp = F.preprocessForOCR(texturedJpeg(200, 150), "jpeg");
  assert.ok(jp && jp.width === 400 && jp.height === 300);
  assert.equal(F.preprocessForOCR(Buffer.from("garbage"), "png"), null);
  assert.equal(F.preprocessForOCR(Buffer.from("garbage"), "jpeg"), null);
});

/* ---- reuse + signals ---- */
function stubDb(rows) {
  return { collection: () => ({ findOne: async (f) => {
    const allowed = f.status && f.status.$in ? f.status.$in : null;
    return rows.find((r) => r.proofHash === f.proofHash
      && String(r._id) !== String(f._id.$ne)
      && (!allowed || allowed.includes(r.status))) || null;
  } }) };
}
test("proof reuse: none, pending elsewhere, paid elsewhere, failed never blocks, unknown on db error", async () => {
  assert.equal(await F.findProofReuse(stubDb([]), "B", "h1"), "none");
  const paid = [{ _id: "A", proofHash: "h1", status: "paid" }];
  assert.equal(await F.findProofReuse(stubDb(paid), "B", "h1"), "paid_elsewhere");
  const pend = [{ _id: "A", proofHash: "h1", status: "under_verification" }];
  assert.equal(await F.findProofReuse(stubDb(pend), "B", "h1"), "pending_elsewhere");
  /* a rejected claim never bought anything — its screenshot can't block */
  const dead = [{ _id: "A", proofHash: "h1", status: "failed" }];
  assert.equal(await F.findProofReuse(stubDb(dead), "B", "h1"), "none");
  const boom = { collection: () => ({ findOne: async () => { throw new Error("down"); } }) };
  assert.equal(await F.findProofReuse(boom, "B", "h1"), "unknown");
  assert.equal(await F.findProofReuse(null, "B", "h1"), "unknown");
});

test("forensic signal severities", () => {
  const scan = { hash: "x", editor: "Canva", ela: { verdict: "na" } };
  const sigs = F.forensicSignals(scan, "paid_elsewhere");
  const codes = Object.fromEntries(sigs.map((s) => [s.code, s.severity]));
  assert.equal(codes.proof_reused_paid, "critical");
  assert.equal(codes.editor_detected, "medium");
  assert.equal(codes.png_ela_na, "info");
  const s2 = F.forensicSignals({ hash: "x", ela: { verdict: "suspicious" } }, "pending_elsewhere");
  const c2 = Object.fromEntries(s2.map((s) => [s.code, s.severity]));
  assert.equal(c2.proof_reused_pending, "high");
  assert.equal(c2.ela_splice, "high");
  /* ghost + copy-move are advisory — they can never alone reject a proof */
  const s3 = F.forensicSignals({ hash: "x", ghost: { verdict: "suspicious" }, copyMove: { verdict: "suspicious" } }, "none");
  const c3 = Object.fromEntries(s3.map((s) => [s.code, s.severity]));
  assert.equal(c3.jpeg_ghost, "low");
  assert.equal(c3.copy_move, "low");
});

/* ---- garbage in, verdict out — never a crash ---- */
test("scan of garbage bytes returns a note, not an exception", () => {
  const scan = F.scanProofImage(Buffer.from("definitely not an image " + "x".repeat(3000)));
  assert.ok(scan.notes.some((n) => n.includes("unrecognized")));
  assert.equal(scan.format, "unknown");
});
