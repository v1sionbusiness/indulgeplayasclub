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

test("honest scans carry no medium-or-worse signals", () => {
  for (const buf of [textPng(null), texturedJpeg()]) {
    const scan = F.scanProofImage(buf);
    const sigs = F.forensicSignals(scan, "none");
    assert.ok(!sigs.some((s) => F.SEVERITY[s.severity] >= F.SEVERITY.medium), JSON.stringify(sigs));
  }
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
  return { collection: () => ({ findOne: async (f) => rows.find((r) => r.proofHash === f.proofHash && String(r._id) !== String(f._id.$ne)) || null }) };
}
test("proof reuse: none, pending elsewhere, paid elsewhere, unknown on db error", async () => {
  assert.equal(await F.findProofReuse(stubDb([]), "B", "h1"), "none");
  const paid = [{ _id: "A", proofHash: "h1", status: "paid" }];
  assert.equal(await F.findProofReuse(stubDb(paid), "B", "h1"), "paid_elsewhere");
  const pend = [{ _id: "A", proofHash: "h1", status: "under_verification" }];
  assert.equal(await F.findProofReuse(stubDb(pend), "B", "h1"), "pending_elsewhere");
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
});

/* ---- garbage in, verdict out — never a crash ---- */
test("scan of garbage bytes returns a note, not an exception", () => {
  const scan = F.scanProofImage(Buffer.from("definitely not an image " + "x".repeat(3000)));
  assert.ok(scan.notes.some((n) => n.includes("unrecognized")));
  assert.equal(scan.format, "unknown");
});
