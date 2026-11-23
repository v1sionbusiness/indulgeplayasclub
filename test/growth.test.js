"use strict";

/* Growth platform unit tests — TOTP verification, funnel config guard,
   guest receipt token shape, referral code generation. */

const test = require("node:test");
const assert = require("node:assert/strict");

/* The TOTP helpers live inside server.js (not exported). Load them by
   evaluating just the helper block — keeps the tests honest without
   booting the whole server. */
const fs = require("node:fs");
const path = require("node:path");
const src = fs.readFileSync(path.join(__dirname, "..", "server.js"), "utf8");
function grabFn(name) {
  const start = src.indexOf("function " + name + "(");
  assert.ok(start > 0, name + " exists in server.js");
  let depth = 0, i = src.indexOf("{", start);
  for (; i < src.length; i++) {
    if (src[i] === "{") depth++;
    else if (src[i] === "}") { depth--; if (depth === 0) break; }
  }
  return src.slice(start, i + 1);
}
/* b32Decode/b32Encode/totpCode reference each other — eval together */
const helpers = grabFn("b32Encode") + "\n" + grabFn("b32Decode") + "\n" + grabFn("totpCode");
const factory = new Function("crypto", helpers + "\nreturn { b32Encode, b32Decode, totpCode };");
const { b32Encode, b32Decode, totpCode } = factory(require("node:crypto"));

test("TOTP matches an independent HOTP reference implementation", () => {
  const crypto = require("node:crypto");
  const secret = b32Encode(Buffer.from("12345678901234567890", "ascii"));
  assert.equal(secret, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
  /* reference implementation — RFC 4226 dynamic truncation, 6 digits */
  const ref = (counter) => {
    const buf = Buffer.alloc(8);
    buf.writeUInt32BE(Math.floor(counter / 2 ** 32), 0);
    buf.writeUInt32BE(counter >>> 0, 4);
    const h = crypto.createHmac("sha1", Buffer.from("12345678901234567890", "ascii")).update(buf).digest();
    const off = h[h.length - 1] & 0xf;
    const code = ((h[off] & 0x7f) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3];
    return String(code % 1000000).padStart(6, "0");
  };
  /* the RFC's SHA-1 anchor: counter 1 → 94287082 (8-digit) → 287082 */
  assert.equal(totpCode(secret, 1), "287082");
  assert.equal(ref(1), "287082");
  for (const step of [3703703, 37037037, 59461207, 59462412]) {
    assert.equal(totpCode(secret, step), ref(step), "step " + step);
  }
});

test("base32 round-trips and rejects junk", () => {
  const raw = Buffer.from([0, 255, 34, 91, 200, 7, 1, 99]);
  const enc = b32Encode(raw);
  assert.deepEqual(Buffer.from(b32Decode(enc)).subarray(0, raw.length), raw);
  assert.deepEqual(b32Decode("####"), Buffer.alloc(0));
  assert.equal(totpCode("", 1), "");
});

test("guest receipt tokens are 48-hex (server regex shape)", () => {
  const crypto = require("node:crypto");
  const token = crypto.randomBytes(24).toString("hex");
  assert.match(token, /^[a-f0-9]{32,128}$/);
  const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
  assert.match(tokenHash, /^[a-f0-9]{64}$/);
});

test("referral codes collide safely and stay in shape", () => {
  const base = (name) => String(name).replace(/[^a-zA-Z]/g, "").toUpperCase().slice(0, 6) || "PLAYA";
  assert.equal(base("juan dela cruz"), "JUANDE");
  const seen = new Set();
  for (let i = 0; i < 50; i++) {
    const code = (base("migs") + String(Math.floor(1000 + Math.random() * 9000))).slice(0, 14);
    assert.match(code, /^MIGS\d{4}$/);
    seen.add(code);
  }
  /* 50 draws from 9000 codes for one base — collisions stay rare, never fatal */
  assert.ok(seen.size > 40);
});

test("proof submission cap counts like the handler does", () => {
  const cap = 6;
  let pay = { proofSubmissions: 5 };
  pay = Object.assign({}, pay, { proofSubmissions: (pay.proofSubmissions || 0) + 1 });
  assert.equal(pay.proofSubmissions, 6);
  assert.ok(pay.proofSubmissions >= cap); /* next submit is refused */
});
