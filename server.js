"use strict";
/*
 * INDULGE PLAYAS CLUB — contact API + IPC accounts + IPC Pay
 * -----------------------------------------------------------
 * One small Node server, three jobs:
 *
 * 1. CONTACT RELAY — relays "SEND US A MESSAGE" form posts to EmailJS.
 *    The three EmailJS values live in the host's Environment settings —
 *    never in this file, so nothing secret is ever pushed to GitHub.
 *
 * 2. IPC ACCOUNTS — register / login / me / logout on MongoDB Atlas
 *    (collections and documents, no SQL). Passwords hashed with scrypt,
 *    sessions are random 48-char tokens with a 30-day expiry.
 *
 * 3. IPC PAY — orders + payments in integer centavos. QR-only. A customer
 *    submitting proof moves their payment to "under_verification". The IPC
 *    PAY AUTO READER then reads the submission: with the reader switch on
 *    (default) and a payment screenshot attached, the payment is verified
 *    automatically and an order tracking record opens. Reference-only
 *    claims ALWAYS wait for a human — POST /api/admin/decision still
 *    decides those manually, and the dashboard can switch the reader off.
 *
 * Environment variables:
 *   CONTACT RELAY (unchanged):
 *     EMAILJS_PUBLIC_KEY / EMAILJS_SERVICE_ID / EMAILJS_TEMPLATE_ID
 *     EMAILJS_CONFIRMATION_TEMPLATE_ID — customer contact confirmation
 *   IPC ACCOUNTS (new):
 *     MONGODB_URI        — Atlas connection string (mongodb+srv://…)
 *     MONGODB_DB         — database name (default "ipc")
 *     ADMIN_EMAIL        — seeded as the admin account on boot
 *     ADMIN_PASSWORD     — admin password (seeded on boot)
 *     ADMIN_NAME         — optional display name (default "Club Admin")
 *     ADMIN_RESET_PASSWORD — "true" to reset the admin password on boot
 *
 * Endpoints:
 *   GET  /healthz                  → { ok: true }
 *   GET  /                         → serves the website if index.html sits
 *                                    next to this file, else health JSON
 *   GET  /api/ipc-pay/health       → pings MongoDB Atlas
 *   POST /api/contact              → EmailJS relay (unchanged behavior)
 *   POST /api/auth/register        → { name, email, password }
 *   POST /api/auth/login           → { email | mobile, password }
 *   POST /api/auth/logout          → (Bearer token)
 *   GET  /api/auth/me              → (Bearer token) profile + role + membership level
 *   POST /api/admin/role           → (Bearer admin) { email, role } grant/revoke admin
 *   POST /api/orders               → (Bearer) create order + payment record
 *   GET  /api/orders/mine          → (Bearer) my order history
 *   GET  /api/payments/<reference> → (Bearer) owner or admin
 *   POST /api/payments/proof       → (Bearer) { reference, refNo, proofDataUrl? }
 *   GET  /api/admin/overview       → (Bearer admin)
 *   GET  /api/admin/payments       → (Bearer admin) verification queue
 *   GET  /api/admin/orders         → (Bearer admin)
 *   GET  /api/admin/users          → (Bearer admin) ?q= search, ?status= filter
 *   GET  /api/admin/member         → (Bearer admin) ?email= full member record
 *   POST /api/admin/decision       → (Bearer admin) { paymentId, action }
 *
 * The club email address is set ONCE in the EmailJS template ("To Email"),
 * never in code, never on the website.
 */

const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const {
  initDatabase, checkConnection, uriHints,
  createSession, findSession, deleteSession,
  findUserByEmail, findUserByPhone, findUserById, insertUser,
  nextReference,
} = require("./ipc-pay/mongo");

const {
  normalizePhilippineMobile,
  normalizeVoucherCode,
  calculateVoucherDiscount,
} = require("./ipc-pay/promotions");

/* The tamper reader — fingerprints, editor signatures, splice analysis. */
const forensics = require("./ipc-pay/forensics");

const PORT = process.env.PORT || 3000;
const EMAILJS_URL = "https://api.emailjs.com/api/v1.0/email/send";

/* The GitHub-Pages site lives on another origin, so allow its requests.
   Authorization is needed for the account endpoints. */
const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};

/* Security headers — every response (API, HTML, assets) carries the same set.
   CSP keeps 'unsafe-inline' because the whole storefront ships as one inline
   script/style document; tightening that is a later pass. Clickjacking is
   closed with frame-ancestors 'none' + X-Frame-Options DENY. */
const SECURITY_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "Content-Security-Policy": [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline'",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' data: https://fonts.gstatic.com",
    "img-src 'self' data: blob: https:",
    "connect-src 'self'",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "object-src 'none'",
  ].join("; "),
};

/* --------------------------------------------------------------- */
/* Rate limits (tiny in-memory buckets — fine for a club site)      */
/* --------------------------------------------------------------- */

const hits = new Map();
function rateLimited(ip, limit, windowMs, bucket) {
  const now = Date.now();
  const key = bucket + ":" + ip;
  const list = (hits.get(key) || []).filter((t) => now - t < windowMs);
  if (list.length >= limit) return true;
  list.push(now);
  hits.set(key, list);
  if (hits.size > 800) hits.clear();
  return false;
}

/* Two manual payment rejections within ten minutes trigger a short account
   cooldown. This is persisted in MongoDB so a Render restart cannot bypass it. */
const PAYMENT_REJECTION_WINDOW_MS = 10 * 60 * 1000;
const PAYMENT_COOLDOWN_MS = 5 * 60 * 1000;

async function paymentCooldownSeconds(db, userId) {
  const account = await db.collection("users").findOne(
    { _id: userId },
    { projection: { paymentCooldownUntil: 1 } }
  );
  if (!account || !account.paymentCooldownUntil) return 0;
  const until = new Date(account.paymentCooldownUntil).getTime();
  const remaining = Math.ceil((until - Date.now()) / 1000);
  if (remaining > 0) return remaining;
  await db.collection("users").updateOne(
    { _id: userId },
    { $unset: { paymentCooldownUntil: "" }, $set: { paymentRejections: [] } }
  );
  return 0;
}

function rejectPaymentDuringCooldown(res, seconds) {
  const minutes = Math.max(1, Math.ceil(seconds / 60));
  return send(res, 429, {
    ok: false,
    reason: "payment_cooldown",
    retryAfterSeconds: seconds,
    message: "PAYMENT REQUESTS ARE TEMPORARILY PAUSED AFTER TWO RECENT REJECTIONS. PLEASE WAIT ABOUT " +
      minutes + " MINUTE" + (minutes === 1 ? "" : "S") + " BEFORE STARTING ANOTHER CHECKOUT.",
  });
}

/* --------------------------------------------------------------- */
/* Product catalog — the server ALWAYS recomputes totals from this,  */
/* the client never names its own price. Money = integer centavos.   */
/* --------------------------------------------------------------- */

const PRODUCTS = [
  { id: "hoodie-001",   name: "OG LOGO HOODIE",     priceCentavos: 120000, sizes: ["S","M","L","XL"],   colors: ["JET BLACK"] },
  { id: "court-tee",    name: "COURT TEE",          priceCentavos:  75000, sizes: ["S","M","L","XL"],   colors: ["COURT WHITE"] },
  { id: "varsity-26",   name: "VARSITY '26",        priceCentavos: 280000, sizes: ["M","L","XL"],       colors: ["BLACK / WHITE"] },
  { id: "utility-cargo",name: "UTILITY CARGO",      priceCentavos: 180000, sizes: ["S","M","L","XL"],   colors: ["JET BLACK"] },
  { id: "rib-beanie",   name: "RIB BEANIE",         priceCentavos:  55000, sizes: ["OS"],               colors: ["JET BLACK"] },
  { id: "stripe-ls",    name: "STRIPE LONG SLEEVE", priceCentavos:  95000, sizes: ["S","M","L","XL"],   colors: ["BLACK / WHITE"] },
  { id: "club-tote",    name: "CLUB TOTE",          priceCentavos:  65000, sizes: ["OS"],               colors: ["HEAVY BLACK"] },
];
/* ---------- SHIPPING — priced by location, not by guesswork ----------
   Metro Manila rides a flat rate; everywhere else pays by zone. The
   tables below are the whole pricing model — edit a fee here and the
   checkout estimate, the voucher math and the order document all
   follow. The server recomputes the fee from the delivery address when
   the order is placed, so the number on the order is the real one.
   Rates are integer centavos. Keys are normalized (lowercase, ñ -> n,
   punctuation -> spaces) and matched as whole words on BOTH the city
   and the province field. Metro Manila is checked first so "quezon
   city" wins over the bare "quezon" province key. */
const SHIPPING_ZONES = [
  /* one zone for the capital — everything else is priced by location.
     The old band around the capital is gone: Rizal, Cavite, Laguna and
     Bulacan are outside Metro Manila and pay the Rest of Luzon rate. */
  { key: "metro_manila", fee: 6000, label: "METRO MANILA",
    provinces: ["metro manila", "ncr", "national capital region", "manila"],
    cities: ["quezon city", "manila", "makati", "taguig", "pasig", "pasay", "mandaluyong", "san juan", "marikina", "caloocan", "malabon", "navotas", "valenzuela", "paranaque", "las pinas", "muntinlupa", "pateros"] },
  { key: "rest_luzon", fee: 13000, label: "REST OF LUZON",
    provinces: ["rizal", "cavite", "laguna", "bulacan", "batangas", "pampanga", "zambales", "bataan", "tarlac", "pangasinan", "nueva ecija", "aurora", "quezon", "marinduque", "mindoro oriental", "oriental mindoro", "mindoro occidental", "occidental mindoro", "palawan", "romblon", "albay", "camarines norte", "camarines sur", "catanduanes", "sorsogon", "masbate", "batanes", "cagayan", "isabela", "nueva vizcaya", "quirino", "ifugao", "mountain province", "benguet", "kalinga", "abra", "ilocos norte", "ilocos sur", "la union"],
    cities: ["antipolo", "cainta", "bacoor", "imus", "dasmariinas", "general trias", "santa rosa", "calamba", "san pedro", "binan", "cabuyao", "baguio", "angeles", "san fernando", "olongapo", "cabanatuan", "legazpi", "naga", "lucena", "batangas city", "lipa", "tarlac city", "vigan", "laoag", "tuguegarao", "dagupan"] },
  { key: "visayas", fee: 16000, label: "VISAYAS",
    provinces: ["cebu", "bohol", "negros occidental", "negros oriental", "siquijor", "samar", "eastern samar", "northern samar", "western samar", "leyte", "southern leyte", "biliran", "iloilo", "guimaras", "capiz", "aklan", "antique"],
    cities: ["cebu city", "mandaue", "lapu lapu", "iloilo city", "bacolod", "tacloban", "ormoc", "roxas", "calbayog", "dumaguete", "tagbilaran"] },
  { key: "mindanao", fee: 18000, label: "MINDANAO",
    provinces: ["zamboanga del norte", "zamboanga del sur", "zamboanga sibugay", "zamboanga city", "misamis oriental", "misamis occidental", "lanao del norte", "lanao del sur", "bukidnon", "camiguin", "cotabato", "north cotabato", "south cotabato", "sultan kudarat", "sarangani", "maguindanao", "davao del sur", "davao del norte", "davao oriental", "davao de oro", "davao occidental", "agusan del norte", "agusan del sur", "surigao del norte", "surigao del sur", "dinagat islands", "basilan", "sulu", "tawi tawi"],
    cities: ["davao city", "cagayan de oro", "general santos", "butuan", "iligan", "tagum", "mati", "koronadal", "dipolog", "pagadian", "surigao city"] },
];
const SHIPPING_DEFAULT_FEE = 18000; /* an address outside every table pays the standard rate */
const SHIPPING_DEFAULT_LABEL = "STANDARD RATE";

function zoneNorm(s) {
  return String(s || "").toLowerCase()
    .replace(/ñ/g, "n")
    .replace(/[-.,']/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function computeShipping(city, province) {
  const hay = " " + zoneNorm(city) + " " + zoneNorm(province) + " ";
  for (const z of SHIPPING_ZONES) {
    const keys = z.provinces.concat(z.cities);
    if (keys.some((k) => hay.indexOf(" " + k + " ") !== -1)) {
      return { fee: z.fee, zone: z.label, key: z.key };
    }
  }
  return { fee: SHIPPING_DEFAULT_FEE, zone: SHIPPING_DEFAULT_LABEL, key: "standard" };
}

/* Share-card data for the baked-in shelf. The server mirrors the client's
   product pages so /p/<id> links unfurl with a real product card and Product
   structured data on every platform. Kept separate from PRODUCTS so catalog
   totals and inventory views stay lean. */
const BAKED_META = {
  "hoodie-001":   { img: "/assets/img/prod-og-logo-hoodie.jpg",
    blurb: "Heavyweight black hoodie with the club arch logo across the back and the OG mark printed at the chest. Drop shoulders, kangaroo pocket, ribbed cuffs — built to keep its shape wash after wash. PRE-ORDER ONLY: produced in the pre-order window, ships when the run lands." },
  "court-tee":    { img: "/assets/img/prod-court-tee.jpg",
    blurb: "Crisp white boxy tee with a small circular club logo printed at the chest and a second hit at the back yoke. Pre-shrunk cotton, so the fit stays true wash after wash." },
  "varsity-26":   { img: "/assets/img/prod-varsity-26.jpg",
    blurb: "Wool-blend varsity with white contrast sleeves, chenille club patch, snap buttons and quilted satin lining. Made in numbered batches — once it's gone, it's gone." },
  "utility-cargo":{ img: "/assets/img/prod-utility-cargo.jpg",
    blurb: "Wide-leg black cargos with adjustable utility straps, double knee pockets and a relaxed drape. Reinforced seams and a slight stretch for daily wear — block to beach." },
  "rib-beanie":   { img: "/assets/img/prod-rib-beanie.jpg",
    blurb: "Ribbed knit beanie in jet black with a woven IPC label at the fold. The stretchy cuff holds its shape and stays locked in through any season." },
  "stripe-ls":    { img: "/assets/img/prod-stripe-ls.jpg",
    blurb: "Black long sleeve with thin white engineered stripes, ribbed collar and printed sleeve hits at the forearm. Layer it under a jacket or run it solo." },
  "club-tote":    { img: "/assets/img/prod-club-tote.jpg",
    blurb: "Heavy canvas tote with bold block print, reinforced base stitching and an inner pocket for keys and phone. Carries the drop, the towel and everything else." },
};

/* The slugs the site ships with — a piece can only ride one of these or a
   collection the team registered through the admin inventory. */
const IPC_COLLECTION_SLUGS = ["graphic", "essentials", "limited", "accessories", "summer"];

const PROOF_MAX_BYTES = 5 * 1024 * 1024; /* 5MB decoded */
const PROOF_TYPES = { "image/jpeg": ".jpg", "image/jpg": ".jpg", "image/png": ".png" };

/* Custom pieces the club adds from the admin inventory. The baked-in catalog
   above stays the backbone; anything saved here rides on top of it and shows
   up on the shop, its collection page and its own product page right away. */
const PRODUCT_IMG_MAX_CHARS = 1600000; /* ~1.1MB binary after base64 — the client compresses before upload */
const TAG_WHITELIST = ["", "NEW DROP", "PRE-ORDER", "RESTOCK", "LIMITED", "CLUB ONLY"];

/* ---------- PRODUCT VISIBILITY — shop / gallery / collection, one by one
   A piece can ride one surface and not the others without touching the
   database record, the order history or the inventory numbers. Missing
   flags mean VISIBLE — the club never hides a piece by accident, and a
   hidden piece is always one flip away from coming back. ------------- */
const PRODUCT_SURFACES = ["shop", "gallery", "collection"];
function defaultVisibility() {
  return { shopVisible: true, galleryVisible: true, collectionVisible: true };
}
function normalizeVisibility(raw) {
  const out = defaultVisibility();
  PRODUCT_SURFACES.forEach((s) => {
    const key = s + "Visible";
    if (raw && raw[key] !== undefined) out[key] = !!raw[key];
  });
  /* shop and collection ride together — one switch in the admin, one
     state everywhere. A piece the club pulled from the shop never keeps
     selling on a collection page (and the reverse holds too). Legacy
     rows that only flipped one of the two snap to this rule on read. */
  out.collectionVisible = out.shopVisible && out.collectionVisible;
  return out;
}
function isFullyHidden(v) {
  return !!v && !v.shopVisible && !v.galleryVisible && !v.collectionVisible;
}
async function visibilityMap(d) {
  const rows = await d.collection("productVisibility").find({}).limit(1000).toArray();
  const map = {};
  rows.forEach((r) => { map[r.id] = normalizeVisibility(r); });
  return map;
}

/* ---------- PRODUCT META — per-piece overrides that ride on top of the
   baked-in catalog without touching its code: a corrected price, a new
   photo, a featured-rotation flip, or an archive that pulls the piece off
   every public surface while the record (and its order history) stays.
   Club-added pieces keep their own documents; this layer is for the
   seven core pieces the site ships with. ------------------------------ */
const META_FIELDS = ["name", "priceCentavos", "tag", "sizes", "colors", "desc",
  "fabric", "fit", "alt", "batchSize", "modelInfo", "img", "home", "featured", "archived"];
const BAKED_DEFAULT_HOME = { "hoodie-001": "main", "court-tee": true, "varsity-26": true, "club-tote": true };
async function productMetaMap(d) {
  const rows = await d.collection("productMeta").find({}).limit(1000).toArray();
  const map = {};
  rows.forEach((r) => { map[r.id] = r; });
  return map;
}
function applyBakedMeta(baked, meta) {
  if (!baked) return baked;
  if (!meta) return baked;
  const out = { ...baked };
  META_FIELDS.forEach((f) => {
    if (meta[f] !== undefined) out[f] = meta[f];
  });
  return out;
}
/* featured is a three-state story: a meta row overrides, otherwise the
   baked default carries it ('main' counts as featured — it's the hero) */
function bakedIsFeatured(meta, id) {
  if (meta && meta.featured !== undefined) return !!meta.featured;
  const def = BAKED_DEFAULT_HOME[id];
  return def === "main" || def === true;
}
/* the /p/<id> share-card builder needs the merged price without a db
   handle everywhere — the server re-reads meta lazily and caches it */
let bakedMetaCache = { at: 0, map: null };
async function bakedMetaCached(d) {
  const now = Date.now();
  if (bakedMetaCache.map && now - bakedMetaCache.at < 15000) return bakedMetaCache.map;
  const map = await productMetaMap(d).catch(() => ({}));
  bakedMetaCache = { at: now, map };
  return map;
}
/* ---------- ADMIN ACTIVITY LOG — append-only. Every important admin
   action lands here: who did it, what changed, when. There is no edit
   or delete endpoint anywhere — the regular admin interface cannot
   rewrite the record, and neither can the API. ---------------------- */
async function logActivity(d, actorEmail, action, targetType, targetId, targetLabel, details) {
  try {
    await d.collection("activityLogs").insertOne({
      actorEmail: String(actorEmail || "system").toLowerCase().slice(0, 120),
      action: String(action || "").slice(0, 40),
      targetType: String(targetType || "").slice(0, 30),
      targetId: String(targetId || "").slice(0, 120),
      targetLabel: String(targetLabel || "").slice(0, 200),
      details: String(details || "").slice(0, 500),
      createdAt: new Date(),
    });
  } catch { /* the log never blocks the action it records */ }
}

/* ---------- SUPPORT TICKETS — the club's own help desk -------------- */
const SUPPORT_CATEGORIES = ["order_issue", "product_question", "sizing_fit", "payment", "shipping", "membership", "other"];
const SUPPORT_STATUSES = ["open", "in_progress", "resolved", "closed"];
function cleanSupportText(raw, max) {
  return String(raw == null ? "" : raw).replace(/[\u0000-\u001f]+/g, " ").trim().slice(0, max);
}
function supportTicketView(t) {
  return {
    id: t.id,
    ref: t.ref,
    email: t.email,
    orderReference: t.orderReference || null,
    subject: t.subject,
    category: t.category,
    message: t.message,
    status: t.status,
    replies: (t.replies || []).map((r) => ({ by: r.by, author: r.author, body: r.body, at: r.at })),
    customerUnread: !!t.customerUnread,
    createdAt: t.createdAt,
    updatedAt: t.updatedAt,
  };
}

/* The client-facing shape of a saved piece — mirrors the baked-in catalog
   fields (priceC, img, collection…) so the shop renders both kinds alike. */
function productView(doc, soldUnits) {
  const batch = Math.round(Number(doc.batchSize) || 0);
  const sold = Math.round(Number(soldUnits) || 0);
  return {
    id: doc.id,
    name: doc.name,
    priceC: doc.priceCentavos,
    tag: doc.tag || "",
    img: doc.img,
    alt: doc.alt || (doc.name + " — Indulge Playas Club piece"),
    desc: doc.desc || "",
    fabric: doc.fabric || "",
    fit: doc.fit || "",
    sizes: doc.sizes || ["OS"],
    colors: doc.colors || [],
    collection: doc.collection || "",
    home: !!doc.home,
    custom: true,
    modelInfo: doc.modelInfo || "",
    /* honest scarcity: batch remainder when the club set a batch size */
    batchSize: batch > 0 ? batch : 0,
    unitsSold: sold,
    remaining: batch > 0 ? Math.max(0, batch - sold) : null,
  };
}

function normalizeProductCollection(raw) {
  return String(raw ?? "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 40);
}

/* --------------------------------------------------------------- */
/* Single-service mode (unchanged)                                  */
/* --------------------------------------------------------------- */

const INDEX_FILE = path.join(__dirname, "index.html");
/* Build stamp: the frontend carries the same value (IPC.BUILD). The app
   pings /api/ipc-pay/health when its tab wakes up and reloads itself when
   this stamp changes — so no visitor can stay stuck on a stale build
   (e.g. an old login screen) after a deploy. Bump BOTH on every release. */
const BUILD_STAMP = "ipc-v35-20261124-pay-verdict";
const HEALTH = { ok: true, service: "indulge playas club — contact api", build: BUILD_STAMP };

/* ---- product share cards: /p/<id> unfurls with real product meta ---- */
function escHtml(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
function injectProductMeta(html, id, info) {
  if (!html || !info || !info.name) return html;
  const url = SITE_ORIGIN + "/p/" + encodeURIComponent(id);
  const imgAbs = info.img && String(info.img).indexOf("data:") !== 0
    ? (String(info.img).indexOf("http") === 0 ? info.img : SITE_ORIGIN + info.img)
    : "";
  const title = escHtml(info.name + " — INDULGE PLAYAS CLUB");
  const desc = escHtml(String(info.blurb || info.name).slice(0, 300));
  const out = html
    .replace(/<link rel="canonical" href="[^"]*"\s*\/>/i,
      '<link rel="canonical" href="' + url + '" />')
    .replace(/<meta property="og:title" content="[^"]*"\s*\/>/g,
      '<meta property="og:title" content="' + title + '" />')
    .replace(/<meta property="og:description" content="[^"]*"\s*\/>/i,
      '<meta property="og:description" content="' + desc + '" />')
    .replace(/<meta property="og:type" content="[^"]*"\s*\/>/g,
      '<meta property="og:type" content="product" />')
    .replace(/<meta property="og:url" content="[^"]*"\s*\/>/i,
      '<meta property="og:url" content="' + url + '" />');
  const withImg = imgAbs
    ? out.replace(/<meta property="og:image" content="[^"]*"\s*\/>/i,
      '<meta property="og:image" content="' + escHtml(imgAbs) + '" />')
    : out;
  const ld = {
    "@context": "https://schema.org",
    "@type": "Product",
    name: info.name,
    description: String(info.blurb || info.name).slice(0, 500),
    image: imgAbs ? [imgAbs] : undefined,
    brand: { "@type": "Brand", name: "INDULGE PLAYAS CLUB" },
    offers: {
      "@type": "Offer",
      url: url,
      priceCurrency: "PHP",
      price: ((Number(info.priceCentavos) || 0) / 100).toFixed(2),
      availability: "https://schema.org/InStock",
      itemCondition: "https://schema.org/NewCondition",
    },
  };
  const tag = '<script type="application/ld+json">' + JSON.stringify(ld) + "</script>";
  return withImg.replace(/<\/head>/i, tag + "</head>");
}
function resolveProductPath(req) {
  const m = String((req && req.url) || "").split("?")[0]
    .match(/^\/p\/([A-Za-z0-9_.\-]{1,80})\/?$/);
  return m ? decodeURIComponent(m[1]) : null;
}

function serveIndex(req, res) {
  try {
    let html = fs.readFileSync(INDEX_FILE, "utf8");
    /* The frontend still contains the retired API hostname. Since this
       Render service now serves both the site and API, rewrite every
       occurrence before returning the page so browser requests stay same-origin. */
    html = html.replace(/https?:\/\/ipc-contact-api\.onrender\.com/gi,
      "https://indulgeplayasclub.onrender.com");
    html = html.replace(/ipc-contact-api\.onrender\.com/gi,
      "indulgeplayasclub.onrender.com");
    /* Rewrite legacy API calls at runtime too. This catches URLs assembled
       inside bundled JavaScript, fetch(), and XMLHttpRequest before network I/O. */
    const apiGuard = '<script id="ipc-api-host-guard">(function(){var oldHost="https://ipc-contact-api.onrender.com";var newHost="https://indulgeplayasclub.onrender.com";function fix(v){if(typeof v!=="string")return v;return v.replace(/https?:\\/\\/ipc-contact-api\\.onrender\\.com/gi,newHost).replace(/ipc-contact-api\\.onrender\\.com/gi,"indulgeplayasclub.onrender.com");}try{var nativeFetch=window.fetch;if(nativeFetch)window.fetch=function(input,init){if(typeof input==="string")input=fix(input);else if(input&&typeof Request!=="undefined"&&input instanceof Request&&input.url.indexOf(oldHost)===0)input=new Request(fix(input.url),input);return nativeFetch.call(this,input,init);};var nativeOpen=XMLHttpRequest.prototype.open;XMLHttpRequest.prototype.open=function(method,url){arguments[1]=fix(url);return nativeOpen.apply(this,arguments);};}catch(e){}try{localStorage.removeItem("ipc_api_override");}catch(e){}})();</script>';
    html = html.replace(/<\/head>/i, apiGuard + "</head>");
    /* Contact glass UI now ships inside index.html itself — no runtime injection. */

    /* Router compatibility: older IPC router code calls .forEach() on the
       result of $(). In some browsers/helpers that result is a single Element
       or an HTMLCollection, neither of which consistently exposes forEach.
       Install safe, standards-shaped iteration before page scripts execute. */
    const routerIterationCompat = `<script id="ipc-router-iteration-compat">
    (function () {
      function addForEach(proto, single) {
        if (!proto || typeof proto.forEach === "function") return;
        Object.defineProperty(proto, "forEach", {
          configurable: true,
          writable: true,
          value: function (callback, thisArg) {
            if (typeof callback !== "function") throw new TypeError("callback must be a function");
            if (single) {
              callback.call(thisArg, this, 0, [this]);
              return;
            }
            Array.prototype.forEach.call(this, callback, thisArg);
          }
        });
      }
      addForEach(window.Element && Element.prototype, true);
      addForEach(window.NodeList && NodeList.prototype, false);
      addForEach(window.HTMLCollection && HTMLCollection.prototype, false);
    })();
    </script>`;
    html = html.replace(/<\/head>/i, routerIterationCompat + "</head>");


    /* Navigation fallback: make same-page navigation reliable even when an
       older page script has stale handlers or the menu is rendered late. */
    const navigationFix = `<style id="ipc-navigation-fix">
      html { scroll-behavior: smooth; scroll-padding-top: 92px; }
      [id] { scroll-margin-top: 92px; }
      a[href^="#"], [data-scroll-to], [data-nav-target] { cursor: pointer; }
      @media (prefers-reduced-motion: reduce) { html { scroll-behavior: auto; } }
    </style>
    <script id="ipc-navigation-fix-script">
    (function () {
      if (window.__ipcNavigationFixInstalled) return;
      window.__ipcNavigationFixInstalled = true;
      function cleanTarget(value) {
        if (!value) return "";
        value = String(value).trim();
        if (!value || value === "#") return "";
        try { value = decodeURIComponent(value); } catch (_) {}
        value = value.replace(/^#/, "");
        return value.charAt(0) === "/" ? value.slice(1) : value;
      }
      function findTarget(value) {
        var key = cleanTarget(value);
        if (!key) return null;
        var target = document.getElementById(key);
        if (target) return target;
        var aliases = document.querySelectorAll("[data-page], [data-section], [data-page-id], [name]");
        for (var i = 0; i < aliases.length; i++) {
          var el = aliases[i];
          if ([el.getAttribute("data-page"), el.getAttribute("data-section"),
               el.getAttribute("data-page-id"), el.getAttribute("name")]
              .some(function (v) { return v && v.toLowerCase() === key.toLowerCase(); })) return el;
        }
        return null;
      }
      function closeMenus() {
        document.querySelectorAll(
          '.mobile-menu.open, .mobile-menu.active, .nav-menu.open, .nav-menu.active, ' +
          '.navbar-collapse.show, [data-mobile-menu].open, [data-mobile-menu].active'
        ).forEach(function (menu) {
          menu.classList.remove("open", "active", "show");
          menu.setAttribute("aria-hidden", "true");
        });
        document.querySelectorAll(
          '[aria-expanded="true"][aria-controls], .menu-toggle[aria-expanded="true"], ' +
          '.hamburger[aria-expanded="true], [data-menu-toggle][aria-expanded="true"]'
        ).forEach(function (toggle) {          toggle.setAttribute("aria-expanded", "false");        });
      }
      function navigate(target, updateHash) {
        if (!target) return false;
        if (target.hidden) target.hidden = false;
        if (window.getComputedStyle(target).display === "none") {
          target.style.display = "";
          if (window.getComputedStyle(target).display === "none") target.style.display = "block";
        }
        target.scrollIntoView({ behavior: window.matchMedia &&
          window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth",
          block: "start" });
        if (updateHash && target.id && location.hash !== "#" + target.id) {
          try { history.pushState(null, "", "#" + encodeURIComponent(target.id)); }
          catch (_) { location.hash = target.id; }
        }
        closeMenus();
        document.querySelectorAll('a[href^="#"], [data-scroll-to], [data-nav-target]').forEach(function (link) {
          var raw = link.getAttribute("href") || link.getAttribute("data-scroll-to") ||
                    link.getAttribute("data-nav-target");
          var selected = findTarget(raw) === target;
          if (selected) link.setAttribute("aria-current", "location");
          else link.removeAttribute("aria-current");
        });
        return true;
      }
      /* Do not capture or cancel clicks here. The IPC site's own router and
         admin dashboard use delegated click handlers; intercepting these
         events prevents their page and dashboard controls from running. */
      window.addEventListener("hashchange", function () {
        var target = findTarget(location.hash);
        if (target) target.scrollIntoView({ behavior: "auto", block: "start" });
      });
      window.addEventListener("popstate", function () {
        var target = findTarget(location.hash);
        if (target) target.scrollIntoView({ behavior: "auto", block: "start" });
      });
      function initialRoute() {
        if (!location.hash) return;
        var target = findTarget(location.hash);
        if (target) setTimeout(function () { target.scrollIntoView({ behavior: "auto", block: "start" }); }, 80);
      }
      if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", initialRoute);
      else initialRoute();
      new MutationObserver(function () {
        if (location.hash) {
          var target = findTarget(location.hash);
          if (target && target.getBoundingClientRect().height === 0) {
            target.hidden = false;
            target.style.display = "";
          }
        }
      }).observe(document.documentElement, { childList: true, subtree: true });
    })();
    </script>`;
    /* Inject before the LAST </body>. The app's own code contains string
       literals with </body> inside (the authenticity-card print window's
       document.write), and a first-match replace would inject INSIDE that
       string — its </script> tail then tears the main script apart and the
       browser prints raw JavaScript as page text. The real document end is
       always the last occurrence. */
    const bodyIdx = html.lastIndexOf("</body>");
    if (bodyIdx >= 0) html = html.slice(0, bodyIdx) + navigationFix + html.slice(bodyIdx);
    else html += navigationFix;

    /* Serve the SPA with no-cache + ETag: every reload revalidates for free
       (304 when unchanged) and always picks up the newest build. The old
       `public, max-age=300` let devices keep running a stale app after a
       deploy — the source of "the site still shows the old login" reports. */
    /* 304/200 writer — the ETag covers the FINAL html, so injected product
       cards get their own correct revalidation tag. */
    const finish = function (finalHtml) {
      const etagRaw = crypto.createHash("sha1").update(finalHtml).digest("hex").slice(0, 24);
      const etag = '"' + etagRaw + '"';
      /* Proxies (Cloudflare in front of Render) may rewrite the tag to weak
         form (W/"…") and the browser may echo a list — compare normalized. */
      const inm = String((req && req.headers["if-none-match"]) || "");
      const clientTags = inm.split(",").map(function (t) {
        return t.trim().replace(/^W\//i, "").replace(/"/g, "");
      });
      if (clientTags.indexOf(etagRaw) >= 0 || clientTags.indexOf("*") >= 0) {
        res.writeHead(304, {
          ETag: etag,
          "Cache-Control": "no-cache",
          ...SECURITY_HEADERS,
        });
        return res.end();
      }
      res.writeHead(200, {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-cache",
        ETag: etag,
        ...SECURITY_HEADERS,
      });
      return res.end(finalHtml);
    };

    /* /p/<id> → product share card. Baked-in pieces resolve sync; club-added
       pieces fetch their card data from Atlas async. Any failure still serves
       the full SPA — a product page never breaks over a meta tag. */
    const pid = resolveProductPath(req);
    if (!pid) { finish(html); return true; }

    const baked = PRODUCTS.find(function (x) { return x && x.id === pid; });
    if (baked) {
      /* meta overrides (corrected price/name/photo) ride onto the share
         card too — the club edits a piece and the unfurl follows. Meta
         lookup is strictly time-boxed: a slow or unreachable database
         never blocks the card — the baked defaults ship instead. */
      (async function () {
        let priceCentavos = baked.priceCentavos;
        let name = baked.name;
        let img = (BAKED_META[pid] || {}).img;
        let blurb = (BAKED_META[pid] || {}).blurb;
        try {
          const meta = await Promise.race([
            (async function () {
              const { connect } = require("./ipc-pay/mongo");
              const d = await connect();
              return (await bakedMetaCached(d))[pid] || null;
            })(),
            new Promise(function (res) { setTimeout(function () { res(null); }, 1200); }),
          ]).catch(function () { return null; });
          if (meta && !meta.archived) {
            if (meta.priceCentavos !== undefined) priceCentavos = meta.priceCentavos;
            if (meta.name !== undefined) name = meta.name;
            if (meta.img !== undefined) img = meta.img;
            if (meta.desc !== undefined) blurb = meta.desc;
          }
        } catch { /* baked defaults still make a complete card */ }
        finish(injectProductMeta(html, pid, {
          name,
          blurb,
          img,
          priceCentavos,
        }));
      })();
      return true;
    }

    (async function () {
      let info = null;
      try {
        const infoLookup = (async function () {
          const { connect } = require("./ipc-pay/mongo");
          const d = await connect();
          const doc = await d.collection("products")
            .findOne({ id: pid, active: { $ne: false } });
          if (doc) return {
            name: doc.name,
            blurb: doc.desc || doc.alt || doc.name,
            img: doc.img,
            priceCentavos: doc.priceCentavos,
          };
          return null;
        })();
        /* same time-box — an unreachable database serves the full SPA
           with the generic card instead of hanging the request */
        info = await Promise.race([
          infoLookup,
          new Promise(function (res) { setTimeout(function () { res(null); }, 1200); }),
        ]);
      } catch { /* generic page is the safe fallback */ }
      finish(info ? injectProductMeta(html, pid, info) : html);
    })();
    return true;
  } catch {
    return false; // no index.html here → caller falls back to the health JSON
  }
}

/* --------------------------------------------------------------- */
/* Static assets (extracted build images + tiny client libs)         */
/* --------------------------------------------------------------- */

const SITE_ORIGIN = process.env.IPC_SITE_ORIGIN || "https://indulgeplayasclub.onrender.com";
const ASSETS_DIR = path.join(__dirname, "assets");
const ASSET_TYPES = {
  ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png",
  ".webp": "image/webp", ".svg": "image/svg+xml", ".ico": "image/x-icon",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".css": "text/css; charset=utf-8", ".txt": "text/plain; charset=utf-8",
  ".xml": "application/xml; charset=utf-8", ".woff2": "font/woff2",
};

function serveStaticAsset(req, res, pathname) {
  const rel = pathname.replace(/^\/assets\//, "").replace(/\\/g, "/");
  /* one flat allow-list — no traversal, no surprises */
  if (!/^[a-z0-9][a-z0-9\-./]*$/i.test(rel) || rel.includes("..") || rel.includes("//")) {
    return fail(res, 404, "not_found", "NO SUCH ASSET.");
  }
  const file = path.join(ASSETS_DIR, rel);
  if (!file.startsWith(ASSETS_DIR)) return fail(res, 404, "not_found", "NO SUCH ASSET.");
  let data;
  try { data = fs.readFileSync(file); } catch { return fail(res, 404, "not_found", "NO SUCH ASSET."); }
  const etag = '"' + crypto.createHash("sha1").update(data).digest("hex").slice(0, 24) + '"';
  const inm = String(req.headers["if-none-match"] || "");
  const cache = rel.endsWith(".js") || rel.endsWith(".json")
    ? "public, max-age=86400"
    : "public, max-age=2592000";
  if (inm.indexOf(etag.slice(1, -1)) >= 0) {
    res.writeHead(304, { ETag: etag, "Cache-Control": cache, ...SECURITY_HEADERS });
    return res.end();
  }
  res.writeHead(200, {
    "Content-Type": ASSET_TYPES[path.extname(file).toLowerCase()] || "application/octet-stream",
    "Cache-Control": cache,
    ETag: etag,
    ...SECURITY_HEADERS,
  });
  return res.end(data);
}

/* robots.txt — allow everything, point at the sitemap */
function serveRobots(res) {
  const body = "User-agent: *\nAllow: /\n\nSitemap: " + SITE_ORIGIN + "/sitemap.xml\n";
  res.writeHead(200, {
    "Content-Type": "text/plain; charset=utf-8",
    "Cache-Control": "public, max-age=3600",
    ...SECURITY_HEADERS,
  });
  return res.end(body);
}

/* sitemap.xml — clean path routes plus every live product and collection */
async function serveSitemap(req, res) {
  let productUrls = "";
  let collectionUrls = "";
  try {
    const { connect } = require("./ipc-pay/mongo");
    const d = await connect();
    const prods = await d.collection("products").find({ active: { $ne: false } })
      .project({ id: 1, updatedAt: 1 }).limit(500).toArray();
    productUrls = prods.map((p) =>
      "  <url><loc>" + SITE_ORIGIN + "/p/" + encodeURIComponent(p.id) + "</loc><priority>0.8</priority></url>"
    ).join("\n");
    const cols = await d.collection("collections").find({})
      .project({ slug: 1 }).limit(200).toArray();
    collectionUrls = cols.map((c) =>
      "  <url><loc>" + SITE_ORIGIN + "/collection/" + encodeURIComponent(c.slug) + "</loc><priority>0.7</priority></url>"
    ).join("\n");
  } catch { /* sitemap still serves the static routes */ }
  /* the baked-in shelf always rides in the sitemap too */
  const bakedUrls = PRODUCTS.map((p) =>
    "  <url><loc>" + SITE_ORIGIN + "/p/" + encodeURIComponent(p.id) + "</loc><priority>0.8</priority></url>"
  ).join("\n");
  productUrls = bakedUrls + (productUrls ? "\n" + productUrls : "");
  const now = new Date().toISOString().slice(0, 10);
  const xml = '<?xml version="1.0" encoding="UTF-8"?>\n' +
    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n' +
    '  <url><loc>' + SITE_ORIGIN + '/</loc><priority>1.0</priority></url>\n' +
    '  <url><loc>' + SITE_ORIGIN + '/shop</loc><priority>0.9</priority></url>\n' +
    '  <url><loc>' + SITE_ORIGIN + '/story</loc><priority>0.6</priority></url>\n' +
    '  <url><loc>' + SITE_ORIGIN + '/faq</loc><priority>0.5</priority></url>\n' +
    '  <url><loc>' + SITE_ORIGIN + '/terms</loc><priority>0.3</priority></url>\n' +
    '  <url><loc>' + SITE_ORIGIN + '/privacy</loc><priority>0.3</priority></url>\n' +
    '  <url><loc>' + SITE_ORIGIN + '/contact</loc><priority>0.5</priority></url>\n' +
    collectionUrls + "\n" + productUrls + "\n" +
    '</urlset>';
  res.writeHead(200, {
    "Content-Type": "application/xml; charset=utf-8",
    "Cache-Control": "public, max-age=3600",
    ...SECURITY_HEADERS,
  });
  return res.end(xml);
}

/* Clean app paths → SPA. /shop, /p/<id>, /collection/<slug>, /track/<ref>, … */
const APP_PATHS = new Set(["shop", "story", "faq", "terms", "privacy", "contact",
  "account", "admin", "bag", "checkout", "login", "signup", "lookbook", "collections"]);
function looksLikeAppPath(p) {
  const seg = p.replace(/^\/+|\/+$/g, "").split("/");
  if (seg.length === 0) return false;
  if (APP_PATHS.has(seg[0])) return true;
  /* /p/<id>, /collection/<slug>, /pay/<ref>, /track/<ref>, /receipt/<ref> */
  return (seg.length === 2 && ["p", "collection", "pay", "track", "receipt"].includes(seg[0]));
}

/* --------------------------------------------------------------- */
/* Small helpers                                                    */
/* --------------------------------------------------------------- */

function send(res, status, obj) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    ...CORS,
    ...SECURITY_HEADERS,
  });
  res.end(JSON.stringify(obj));
}

function fail(res, status, reason, message) {
  send(res, status, { ok: false, reason, message: message || reason });
}

function mongoError(res, err, fallback) {
  if (err && err.code === "MONGO_NOT_CONFIGURED") {
    console.error("Mongo not configured:", err.message);
    return fail(res, 503, "mongo_not_configured",
      "ACCOUNT SERVER NOT REACHABLE — TRY AGAIN IN A FEW MINUTES.");
  }
  console.error(fallback, err && err.message);
  return fail(res, 500, "server_error", fallback);
}

function readBody(req, res, maxBytes) {
  return new Promise((resolve) => {
    let raw = "";
    let dead = false;
    req.on("data", (chunk) => {
      raw += chunk;
      if (raw.length > maxBytes) {
        dead = true;
        req.destroy();      }
    });
    req.on("end", () => {
      if (dead) return resolve(null);
      try {
        resolve(JSON.parse(raw || "{}"));
      } catch {
        resolve(undefined); // malformed JSON
      }
    });
    req.on("error", () => resolve(null));
  });
}

function bearerToken(req) {
  const h = String(req.headers.authorization || "");
  const m = h.match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : null;
}

function publicUser(u) {
  return { id: String(u._id), email: u.email, name: u.name, phone: u.phone || "", role: u.role, createdAt: u.createdAt, memberId: u.memberId || null };
}

/** Escape a raw admin search term before it goes into a $regex. */
function escapeRegex(s) {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/* Membership levels — computed from VERIFIED payments only. */
const TIERS = [
  { key: "ROOKIE", minPaidCentavos: 0 },
  { key: "HOMIE", minPaidCentavos: 250000 },
  { key: "OG", minPaidCentavos: 750000 },
  { key: "VIP", minPaidCentavos: 1500000 },
];

function tierForPaid(centavos) {
  let tier = TIERS[0].key;
  for (const x of TIERS) if (centavos >= x.minPaidCentavos) tier = x.key;
  return tier;
}

/** Lifetime paid totals for one member email (paid orders only). */
async function paidSummary(d, email) {
  const agg = await d.collection("orders").aggregate([
    { $match: { email, status: "paid" } },
    { $group: { _id: null, spent: { $sum: "$totalCentavos" }, orders: { $sum: 1 } } },
  ]).toArray();
  return { spentCentavos: agg[0] ? agg[0].spent : 0, paidOrders: agg[0] ? agg[0].orders : 0 };
}

/** Resolve the logged-in user from the Authorization header, or null. */
async function userFromReq(req) {
  const token = bearerToken(req);
  if (!token) return null;
  const session = await findSession(token);
  if (!session) return null;
  const user = await findUserById(session.userId);
  if (!user || user.status === "removed") return null;
  return { user, token };
}

/* --------------------------------------------------------------- */
/* Order / payment shaping                                          */
/* --------------------------------------------------------------- */

function orderView(o, payment) {
  return {
    reference: o.reference,
    customerName: o.customerName,
    email: o.email,
    phone: o.phone || "",
    addressLine: o.addressLine || "",
    barangay: o.barangay || "",
    city: o.city || "",
    province: o.province || "",
    postalCode: o.postalCode || "",
    notes: o.notes || "",
    items: o.items,
    subtotalCentavos: o.subtotalCentavos,
    discountCentavos: o.discountCentavos || 0,
    voucherCode: o.voucherCode || null,
    shippingCentavos: o.shippingCentavos,
    totalCentavos: o.totalCentavos,
    status: o.status,
    tracking: o.tracking || null,
    createdAt: o.createdAt,
    payment: payment ? {
      paymentReference: payment.paymentReference,
      status: payment.status,
      method: payment.method || "qr",
      refNo: payment.refNo || null,
      proofPresent: Boolean(payment.proofDataUrl),
      verifiedAt: payment.verifiedAt || null,
    } : null,
  };
}

function paymentView(p, order, includeProof) {
  const out = {
    paymentReference: p.paymentReference,
    orderReference: p.orderReference,
    amountCentavos: p.amountCentavos,
    currency: p.currency,
    status: p.status,
    method: p.method,
    refNo: p.refNo || null,
    createdAt: p.createdAt,
    updatedAt: p.updatedAt,
    verifiedAt: p.verifiedAt || null,
    /* customers read "IPC TEAM" — the reviewer's email stays admin-only */
    reviewedBy: includeProof ? (p.reviewedBy || null) : (p.reviewedBy ? "IPC TEAM" : null),
  };
  if (includeProof) {
    out.proofDataUrl = p.proofDataUrl || null;
    /* the machine's full read — verdict, forensic signals and all — is
       admin-only. Customer views never receive it. */
    out.autoRead = p.autoRead || null;
    out.proofHash = p.proofHash || null;
  }
  else {
    out.proofPresent = Boolean(p.proofDataUrl);
    /* the machine's verdict sentence on an auto-rejected proof — the
       customer gets the reason (it is written for them), never the
       forensic panel. */
    if (p.status === "failed" && p.autoRead &&
        p.autoRead.verdict === "AUTO_REJECTED" && p.autoRead.reason) {
      out.machineNote = String(p.autoRead.reason).slice(0, 400);
    }
  }
  if (order) {
    out.order = {
      reference: order.reference,
      customerName: order.customerName,
      email: order.email,
      phone: order.phone || "",
      addressLine: order.addressLine || "",
      barangay: order.barangay || "",
      city: order.city || "",
      province: order.province || "",
      postalCode: order.postalCode || "",
      notes: order.notes || "",
      items: order.items,
      subtotalCentavos: order.subtotalCentavos,
      discountCentavos: order.discountCentavos || 0,
      voucherCode: order.voucherCode || null,
      shippingCentavos: order.shippingCentavos,
      totalCentavos: order.totalCentavos,
      status: order.status,
      tracking: order.tracking || null,
      createdAt: order.createdAt,
    };
  }
  return out;
}

/* Receipt view — everything the printed/onscreen receipt needs, pulled
   straight from the order + payment records. Nothing is invented here:
   the stamp the customer sees is derived from the REAL payment status,
   and the money lines are the exact numbers the order locked in. */
function receiptView(o, pay) {
  const shippingCentavos = (o.shippingCentavos == null && o.subtotalCentavos != null && o.totalCentavos != null)
    ? o.totalCentavos - o.subtotalCentavos + (o.discountCentavos || 0)
    : (o.shippingCentavos == null ? null : o.shippingCentavos);
  return {
    kind: "receipt",
    reference: o.reference,
    createdAt: o.createdAt,
    issuedAt: (pay && pay.verifiedAt) || o.updatedAt || o.createdAt,
    orderStatus: o.status,
    paymentStatus: pay ? pay.status : null,
    customer: {
      name: o.customerName || "",
      email: o.email || "",
      phone: o.phone || "",
      addressLine: o.addressLine || "",
      barangay: o.barangay || "",
      city: o.city || "",
      province: o.province || "",
      postalCode: o.postalCode || "",
    },
    items: (o.items || []).map((it) => ({
      name: it.name,
      size: it.size,
      color: it.color || null,
      qty: it.qty,
      priceCentavos: it.priceCentavos,
    })),
    subtotalCentavos: o.subtotalCentavos,
    discountCentavos: o.discountCentavos || 0,
    voucherCode: o.voucherCode || null,
    shippingCentavos,
    shippingZone: o.shippingZone || null,
    totalCentavos: o.totalCentavos,
    payment: pay ? {
      paymentReference: pay.paymentReference,
      status: pay.status,
      method: pay.method || "qr",
      refNo: pay.refNo || null,
      proofPresent: Boolean(pay.proofDataUrl),
      verifiedAt: pay.verifiedAt || null,
      amountCentavos: pay.amountCentavos,
      currency: pay.currency || "PHP",
      /* customers read "IPC TEAM" — the reviewer's identity stays admin-only */
      reviewedBy: pay.reviewedBy ? "IPC TEAM" : null,
    } : null,
    tracking: o.tracking ? {
      number: o.tracking.number || null,
      courier: o.tracking.courier || null,
      status: o.tracking.status || null,
    } : null,
  };
}

/* --------------------------------------------------------------- */
/* ORDER TRACKING — fulfillment lives beside the payment machine.   */
/* order.status keeps meaning paid/failed (membership + revenue     */
/* aggregations depend on it); the delivery journey lives in        */
/* order.tracking and opens automatically when payment is accepted. */
/* --------------------------------------------------------------- */

const TRACKING_STAGES = ["processing", "packed", "shipped", "delivered"];

/** The auto reader switch — settings collection, default ON. */
async function getPaySettings(d) {
  try {
    const doc = await d.collection("settings").findOne({ _id: "ipcpay" });
    return { autoVerify: !doc || doc.autoVerify !== false };
  } catch {
    return { autoVerify: true };
  }
}

/** Create the tracking record the moment a payment is accepted. */
async function ensureTracking(d, orderReference, source) {
  const order = await d.collection("orders").findOne({ reference: orderReference });
  if (!order || order.tracking) return;
  const now = new Date();
  const number = await nextReference("track");
  const tracking = {
    number,
    status: "processing",
    courier: "",
    trackingUrl: "",
    history: [{ status: "processing", note: "PAYMENT CONFIRMED — ORDER IS BEING PROCESSED.", at: now, by: source }],
    createdAt: now,
    updatedAt: now,
  };
  await d.collection("orders").updateOne(
    { reference: orderReference, tracking: { $exists: false } },
    { $set: { tracking, updatedAt: now } }
  );
  console.log("[ipc-pay] tracking opened for " + orderReference + " — " + number);
}

/** IPC PAY VERDICT ENGINE — reads the screenshot a member submits,
    reads the screenshot itself, and GIVES ITS OWN VERDICT. No human
    prompt on a proof the machine could read:

    LAYER 1 — WHAT IT SAYS (OCR gates):
      (1) a Maya/PayMaya marker in the screenshot,
      (2) the exact order amount as a money figure (labeled line first),
      (3) the Maya transaction reference the member typed in — with
          OCR-confusion folding (O/0, I/1, S/5, B/8, Z/2) so an honest
          screenshot is not failed over a misread character.
      A blurry read gets a SECOND PASS on a cleaned copy of the image
      (grayscale-stretched, 2x upscaled) before giving up.

    LAYER 2 — IS IT HONEST (ipc-pay/forensics.js):
      proof fingerprint reuse across orders, photo-editor signatures,
      AI-generator and provenance-manifest signatures, error-level
      splice analysis, PNG metadata reads.

    THE VERDICT — the machine decides, three ways:
      AUTO_VERIFIED  → every gate green AND the honesty scan clean.
                       Payment goes PAID with no admin tap.
      AUTO_REJECTED  → decisive bad evidence: reused receipt, editor or
                       AI-generator signature, splice, wrong/missing
                       amount or reference, non-Maya receipt, or an
                       image too unclear to read. Payment goes FAILED
                       with the exact reason on the customer's screen.
      NEEDS_REVIEW   → only when the MACHINE ITSELF couldn't run (OCR
                       engine down, forensic scan error). The club sees
                       those — that is a broken reader, never a shy one.

    The CAS guard means it can never override an admin decision that
    lands meanwhile. The full read (autoRead) is persisted even when
    the auto switch is OFF — the club sees the machine's reading on
    every manual review too. */
let __ocrWorker = null;
async function getOcrWorker() {
  if (__ocrWorker) return __ocrWorker;
  const { createWorker } = require("tesseract.js");
  __ocrWorker = await createWorker("eng", 1, { cachePath: "/tmp/ipc-ocr" });
  return __ocrWorker;
}

/** One OCR pass with a hard timeout — a slow reader falls back. */
async function ocrPass(buf, ms) {
  const work = (async () => {
    const worker = await getOcrWorker();
    const { data } = await worker.recognize(buf);
    return String((data && data.text) || "");
  })();
  return Promise.race([
    work,
    new Promise((resolve, reject) => setTimeout(() => reject(new Error("ocr timeout")), ms)),
  ]);
}

/* Below this many OCR characters even after the cleaned second pass,
   the machine treats the screenshot as unreadable — a payment nobody
   can read is a payment nobody can claim from. */
const OCR_READABLE_MIN = 120;

/* The machine's rejection sentences — written for the customer's own
   screen. Each maps to a decisive failure, and the same text lands in
   the rejection email and the payment page's verdict line. */
const REJECT_COPY = {
  ai_generated: "THIS IMAGE CARRIES AN AI-GENERATOR SIGNATURE — AI-MADE PAYMENT PROOFS ARE REJECTED ON SIGHT. SUBMIT THE ORIGINAL SCREENSHOT FROM YOUR MAYA APP.",
  editor_detected: "THIS IMAGE WAS SAVED THROUGH AN EDITING APP — SUBMIT THE RAW SCREENSHOT STRAIGHT FROM YOUR MAYA APP, UNCROPPED AND UNRETOUCHED.",
  ela_splice: "THE TAMPER SCAN FOUND INCONSISTENT COMPRESSION AROUND A REGION OF THIS IMAGE — IT LOOKS LIKE CONTENT WAS PASTED IN. SUBMIT THE ORIGINAL SCREENSHOT.",
  proof_reused_paid: "THIS EXACT SCREENSHOT ALREADY PAID FOR ANOTHER ORDER — ONE RECEIPT COVERS ONE ORDER ONLY.",
  proof_reused_pending: "THIS EXACT SCREENSHOT IS ALREADY ATTACHED TO ANOTHER OPEN ORDER.",
  not_maya: "THIS SCREENSHOT DOESN'T READ AS A MAYA RECEIPT — SUBMIT THE RECEIPT FROM YOUR MAYA APP FOR THIS PAYMENT.",
  ref_missing: "THE MAYA TRANSACTION REFERENCE YOU SUBMITTED DOESN'T APPEAR IN THIS SCREENSHOT — CHECK THE REFERENCE AND RESUBMIT.",
  amount_missing: "THE ORDER TOTAL DOESN'T APPEAR IN THIS SCREENSHOT — SEND THE EXACT ORDER AMOUNT AND RESUBMIT THE RECEIPT.",
  unreadable: "THIS SCREENSHOT IS TOO BLURRY OR CROPPED TO READ — SUBMIT THE FULL, UNEDITED SCREENSHOT FROM YOUR MAYA APP.",
};

/** OCR + gates + forensics. Never throws: { pass:false, reason } on any problem. */
async function readMayaProof(payment, d) {
  const summary = {
    pass: false, decided: false, mayaOk: false, refOk: false, amountOk: false, nameOk: false,
    cleanOk: true, ocrChars: 0, ocrPasses: 0, prepPass: false, machineReadable: false,
    refFuzzy: false, amountReadCentavos: null, amountSource: null,
    verdict: "NEEDS_REVIEW", signals: [], forensics: null, reason: "", rejectReasons: [],
  };
  try {
    const m = String(payment.proofDataUrl || "").match(/^data:image\/(?:jpeg|jpg|png);base64,([A-Za-z0-9+\/=\s]+)$/);
    if (!m) { summary.reason = "no readable image"; return summary; }
    const buf = Buffer.from(m[1], "base64");
    if (buf.length < 2048) {
      /* a file this small is not a screenshot — nothing to judge */
      summary.rejectReasons = [REJECT_COPY.unreadable];
      summary.verdict = "AUTO_REJECTED";
      summary.decided = true;
      summary.reason = summary.rejectReasons.join(" ");
      return summary;
    }

    /* LAYER 2 first — the fingerprint and metadata reads are cheap and
       deterministic; they gate the decision before OCR even runs. */
    let scan = null;
    let scanFailed = false;
    try {
      scan = forensics.scanProofImage(buf);
      const reuse = await forensics.findProofReuse(d, payment._id, scan.hash);
      summary.forensics = {
        hashShort: scan.hashShort, format: scan.format,
        width: scan.width, height: scan.height,
        editor: scan.editor || null,
        ela: scan.ela && scan.ela.verdict ? { verdict: scan.ela.verdict, ratio: scan.ela.ratio || null, hotBlocks: scan.ela.hotBlocks || 0, hotArea: scan.ela.hotArea || null, reason: scan.ela.reason || null } : null,
        reuse,
        notes: (scan.notes || []).slice(0, 4),
      };
      summary.signals = forensics.forensicSignals(scan, reuse);
      summary.cleanOk = !summary.signals.some((s) => forensics.SEVERITY[s.severity] >= forensics.SEVERITY.medium);
    } catch (err) {
      scanFailed = true;
      summary.forensics = { reuse: "unknown", notes: ["forensic scan error: " + (err && err.message)] };
    }
    if (summary.forensics && scan) {
      summary.forensics.aiGenerator = scan.aiGenerator || null;
    }

    /* LAYER 1 — OCR, pass 1 on the original, pass 2 on the cleaned copy */
    const evaluate = (text) => {
      const norm = String(text || "").toUpperCase().replace(/\s+/g, " ");
      const ev = { ocrChars: norm.length, mayaOk: false, refOk: false, amountOk: false, nameOk: false, refFuzzy: false, amountReadCentavos: null, amountSource: null };
      /* gate 1 — it has to be a Maya screenshot at all */
      ev.mayaOk = /MAYA|PAYMAYA/.test(norm);
      /* gate 2 — the submitted reference must appear in the screenshot
         (exact first, then under OCR confusions, then inside long digit runs) */
      const ref = forensics.refMatchesOCR(payment.refNo, norm);
      ev.refOk = ref.found; ev.refFuzzy = ref.fuzzy;
      /* gate 3 — the exact order amount must appear as a money figure.
         The labeled line ("AMOUNT / TOTAL / PRICE") is read first; the
         whole image is scanned as the fallback. */
      const target = Math.round(Number(payment.amountCentavos) || 0);
      if (target > 0) {
        const labeled = forensics.labeledAmount(norm);
        if (labeled && labeled.cents === target) {
          ev.amountOk = true;
          ev.amountReadCentavos = labeled.cents;
          ev.amountSource = "labeled-line";
        } else {
          const toks = forensics.extractMoneyTokens(norm);
          for (const t of toks) {
            if (t.cents === target) { ev.amountOk = true; ev.amountReadCentavos = t.cents; ev.amountSource = "full-scan"; break; }
          }
          if (!ev.amountOk && labeled) ev.amountReadCentavos = labeled.cents;
        }
      }
      /* extra signal for the admins — the account holder name on the QR */
      ev.nameOk = /CLAUDIO|ANCEL JAMES/.test(norm);
      return ev;
    };

    let ev = null;
    try {
      const t1 = await ocrPass(buf, 45000);
      ev = evaluate(t1);
      summary.ocrPasses = 1;
      if (!ev.mayaOk || !ev.refOk || !ev.amountOk) {
        const fmt = summary.forensics && summary.forensics.format;
        const prep = fmt === "unknown" ? null : forensics.preprocessForOCR(buf, fmt);
        if (prep) {
          const t2 = await ocrPass(prep.buffer, 30000);
          const ev2 = evaluate(t2);
          summary.ocrPasses = 2;
          summary.prepPass = true;
          const score = (e) => (e.mayaOk ? 4 : 0) + (e.refOk ? 2 : 0) + (e.amountOk ? 1 : 0) + (e.nameOk ? 1 : 0);
          if (score(ev2) > score(ev)) ev = ev2;
        }
      }
      summary.ocrChars = ev.ocrChars;
      summary.mayaOk = ev.mayaOk; summary.refOk = ev.refOk; summary.amountOk = ev.amountOk;
      summary.nameOk = ev.nameOk; summary.refFuzzy = ev.refFuzzy;
      summary.amountReadCentavos = ev.amountReadCentavos; summary.amountSource = ev.amountSource;
    } catch (err) {
      summary.reason = "ocr unavailable: " + (err && err.message);
    }

    /* THE VERDICT — the machine decides on its own read. */
    const gatesGreen = Boolean(summary.mayaOk && summary.refOk && summary.amountOk);
    const readable = summary.ocrChars >= OCR_READABLE_MIN;
    summary.machineReadable = readable;
    const rejects = [];
    for (const s of summary.signals) {
      if (forensics.SEVERITY[s.severity] >= forensics.SEVERITY.medium && REJECT_COPY[s.code]) {
        rejects.push(REJECT_COPY[s.code]);
      }
    }
    if (readable) {
      if (!summary.mayaOk) rejects.push(REJECT_COPY.not_maya);
      if (!summary.refOk) rejects.push(REJECT_COPY.ref_missing);
      if (!summary.amountOk) rejects.push(REJECT_COPY.amount_missing);
    } else if (!rejects.length && summary.ocrPasses > 0 && !gatesGreen) {
      /* the read found too little text to trust a negative — every gate
         it could not check might just be text the OCR missed. A proof
         that carries every gate green on its face is judged by those
         gates, never by its character count. */
      rejects.push(REJECT_COPY.unreadable);
    }
    summary.rejectReasons = rejects;
    summary.pass = gatesGreen && summary.cleanOk && !rejects.length;
    if (rejects.length) {
      summary.verdict = "AUTO_REJECTED";
      summary.decided = true;
      summary.reason = rejects.join(" ");
    } else if (summary.pass && !scanFailed) {
      summary.verdict = "AUTO_VERIFIED";
      summary.decided = true;
    } else {
      /* the machine itself could not complete its read — a broken reader,
         never a shy one. This alone is what a club admin still sees. */
      summary.verdict = "NEEDS_REVIEW";
      const failing = [];
      if (!summary.mayaOk) failing.push("maya-marker");
      if (!summary.refOk) failing.push("reference");
      if (!summary.amountOk) failing.push("amount");
      if (!summary.cleanOk) failing.push("forensics(" + summary.signals.filter((s) => forensics.SEVERITY[s.severity] >= forensics.SEVERITY.medium).map((s) => s.code).join(",") + ")");
      const parts = [];
      if (scanFailed) parts.push("forensic scan incomplete");
      if (failing.length) parts.push("mismatch: " + failing.join(", "));
      if (!summary.reason && parts.length) summary.reason = parts.join("; ");
      if (!summary.reason) summary.reason = "reader could not complete its read";
    }
    return summary;
  } catch (err) {
    summary.reason = "reader error: " + (err && err.message);
    return summary;
  }
}

/* Two rejections inside the window cool the account down — one shared
   rule for the club's hand and the machine's verdict alike. */
async function registerRejection(d, userId, at) {
  const stamp = new Date(at);
  await d.collection("users").updateOne(
    { _id: userId },
    { $push: { paymentRejections: { $each: [stamp], $slice: -5 } } }
  );
  const account = await d.collection("users").findOne(
    { _id: userId },
    { projection: { paymentRejections: 1 } }
  );
  const cutoff = stamp.getTime() - PAYMENT_REJECTION_WINDOW_MS;
  const recent = (account && Array.isArray(account.paymentRejections)
    ? account.paymentRejections : []).filter((s) => new Date(s).getTime() >= cutoff);
  if (recent.length >= 2) {
    await d.collection("users").updateOne(
      { _id: userId },
      { $set: { paymentCooldownUntil: new Date(stamp.getTime() + PAYMENT_COOLDOWN_MS) } }
    );
  }
}

async function autoVerifyPayment(d, pay) {
  try {
    /* fresh read — the payment may already have been decided by an admin */
    const fresh = await d.collection("payments").findOne({ _id: pay._id });
    if (!fresh || !fresh.proofDataUrl || !fresh.refNo) return false;

    /* READ the screenshot — the full read is persisted on EVERY proof
       (even with the auto switch off, so the club sees the machine's
       reading during manual reviews). */
    const read = await readMayaProof(fresh, d);
    console.log("[ipc-pay] AUTO READER read " + fresh.paymentReference +
      " — pass=" + read.pass + " maya=" + read.mayaOk + " ref=" + read.refOk +
      (read.refFuzzy ? "(fuzzy)" : "") + " amount=" + read.amountOk +
      " clean=" + read.cleanOk + " passes=" + read.ocrPasses +
      " verdict=" + read.verdict +
      (read.forensics && read.forensics.reuse && read.forensics.reuse !== "none"
        ? " REUSE=" + read.forensics.reuse : "") +
      (read.forensics && read.forensics.editor ? " EDITOR=" + read.forensics.editor : "") +
      (read.reason ? " (" + read.reason + ")" : ""));
    await d.collection("payments").updateOne(
      { _id: fresh._id },
      { $set: { autoRead: { ...read, at: new Date() } } }
    ).catch(() => {});

    const settings = await getPaySettings(d);
    if (!settings.autoVerify) return false;   /* switch off — the club reviews by hand */
    if (fresh.status !== "under_verification") return false;

    if (read.verdict === "AUTO_REJECTED") {
      /* the machine's verdict: decisive bad evidence — fail it here,
         spell the reason out to the customer, count it like any
         other rejection. */
      const now = new Date();
      const decision = await d.collection("payments").updateOne(
        { _id: fresh._id, status: "under_verification" },
        { $set: {
          status: "failed",
          updatedAt: now,
          verifiedAt: now,
          reviewedBy: "IPC PAY AUTO READER",
          decisionSource: "auto_reject_maya_reader",
        } }
      );
      if (decision.modifiedCount !== 1) return false;
      await d.collection("orders").updateOne(
        { reference: fresh.orderReference },
        { $set: { status: "failed", updatedAt: now } }
      );
      await registerRejection(d, fresh.userId, now);
      const orderForEmail = await d.collection("orders").findOne({ reference: fresh.orderReference });
      await sendPaymentEmail({ ...fresh, status: "failed" }, orderForEmail, "FAILED",
        "IPC Pay read your payment screenshot and rejected it automatically. " +
        (read.reason || "The proof could not be verified against your order.") +
        " Your unpaid items are back in your bag — resubmit the original, unedited Maya receipt.");
      console.log("[ipc-pay] AUTO READER rejected " + fresh.paymentReference +
        " — " + String(read.reason || "").slice(0, 160));
      return true;
    }

    if (!read.pass) return false;             /* NEEDS_REVIEW — broken read, human decides */

    /* compare-and-set — never overrides an admin decision that landed meanwhile */
    const now = new Date();
    const decision = await d.collection("payments").updateOne(
      { _id: fresh._id, status: "under_verification" },
      { $set: {
        status: "paid",
        updatedAt: now,
        verifiedAt: now,
        reviewedBy: "IPC PAY AUTO READER",
        decisionSource: "auto_verify_maya_reader",
      } }
    );
    if (decision.modifiedCount !== 1) return false;
    await d.collection("orders").updateOne(
      { reference: fresh.orderReference },
      { $set: { status: "paid", updatedAt: now } }
    );
    await d.collection("users").updateOne(
      { _id: fresh.userId },
      { $set: { paymentRejections: [] }, $unset: { paymentCooldownUntil: "" } }
    );
    await ensureTracking(d, fresh.orderReference, "IPC TEAM");
    await creditReferralIfAny(d, fresh.orderReference);
    const orderForEmail = await d.collection("orders").findOne({ reference: fresh.orderReference });
    await sendPaymentEmail({ ...fresh, status: "paid" }, orderForEmail, "PAID",
      "IPC Pay read your payment screenshot — the Maya amount and transaction reference matched your order. Your order is confirmed and order tracking is now live in your account.");
    console.log("[ipc-pay] AUTO READER verified " + fresh.paymentReference + " — tracking opened.");
    return true;
  } catch (err) {
    console.error("[ipc-pay] auto reader failed (falls back to manual review):", err && err.message);
    return false;
  }
}

/* =============================================================== */
/* The server                                                       */
/* =============================================================== */

/* ---------- MAINTENANCE MODE — the club closes the floor ----------
   The state lives in the settings doc and is read through a short
   cache, so gating costs nothing while the site is open. While the
   wall is up: admins always pass, logged-in members pass only when
   the club allows it, guests and everyone else get a 503. The config
   and auth endpoints stay open so the stand-by screen can render and
   admins can still sign in. If the database is unreachable the site
   stays OPEN — a closed store must never be a state the shop can't
   recover from. ---------------------------------------------------- */
let maintCache = { at: 0, state: { enabled: false, allowMembers: true, message: "" } };
/* The wall read is bounded: if Mongo can't answer within 1.5s the gate
   uses the last known state (default open) instead of stalling every API
   call behind a server-selection timeout. A closed store must never be a
   state the shop can't recover from. */
function boundedRead(promise, ms) {
  let timer;
  const timeout = new Promise((resolve) => { timer = setTimeout(() => resolve("timeout"), ms); });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}
async function maintenanceState() {
  const now = Date.now();
  if (maintCache.state && now - maintCache.at < 10000) return maintCache.state;
  try {
    const read = (async () => {
      const { connect } = require("./ipc-pay/mongo");
      const d = await connect();
      return d.collection("settings").findOne({ _id: "club" });
    })();
    const cfg = await boundedRead(read, 1500);
    if (cfg === "timeout") return maintCache.state; /* Mongo slow/down — last known state */
    const m = (cfg && cfg.maintenance) || {};
    maintCache = {
      at: now,
      state: {
        enabled: !!m.enabled,
        allowMembers: m.allowMembers !== false,
        message: String(m.message || "").slice(0, 240),
      },
    };
  } catch { /* keep the last known state — default open */ }
  return maintCache.state;
}
function maintenanceExempt(p) {
  return p === "/api/config" || p === "/healthz" || p === "/api/ipc-pay/health" ||
    p.indexOf("/api/auth/") === 0 || p.indexOf("/api/admin/") === 0;
}
async function maintenanceGate(req, res, p) {
  const st = await maintenanceState();
  if (!st.enabled) return false;
  if (maintenanceExempt(p)) return false;
  const found = await userFromReq(req).catch(() => null);
  if (found && found.user && found.user.role === "admin") return false;
  if (st.allowMembers && found) return false;
  fail(res, 503, "maintenance", st.message || "THE CLUB IS SETTING THE FLOOR — STAND BY FOR THE DROP.");
  return true;
}

const server = http.createServer((req, res) => {
  if (req.method === "OPTIONS") {
    res.writeHead(204, CORS);
    return res.end();
  }
  route(req, res).catch((err) => {
    console.error("unhandled:", err && err.message);
    if (!res.headersSent) fail(res, 500, "server_error", "SOMETHING BROKE — TRY AGAIN.");
  });
});

async function route(req, res) {
  const p = (req.url || "").split("?")[0];
  const ip =
    (req.headers["x-forwarded-for"] || "").split(",")[0].trim() ||
    req.socket.remoteAddress ||
    "unknown";

  /* the club can close the floor while it sets up a drop — non-admin API
     traffic gets a 503 while the wall is up. The SPA itself still serves
     so visitors see the stand-by screen, not a dead connection. */
  if (p.indexOf("/api/") === 0 && (await maintenanceGate(req, res, p))) return;

  /* ---------------- GET routes ---------------- */
  if (req.method === "GET") {
    if (p === "/api/ipc-pay/health") {
      return checkConnection()
        .then(() => send(res, 200, { ok: true, database: "connected", build: BUILD_STAMP }))
        .catch((err) => {
          const status = err.code === "MONGO_NOT_CONFIGURED" ? 503 : 502;
          console.error("IPC Pay database check failed:", err.message);
          const hints = (err && err.hints && err.hints.length) ? err.hints : (typeof uriHints === "function" ? uriHints(process.env.MONGODB_URI) : []);
          return send(res, status, {
            ok: false,
            database: "unavailable",
            reason: err.code || "MONGO_REQUEST_FAILED",
            hints: hints,
          });
        });
    }
    if (p === "/healthz") return send(res, 200, HEALTH);
    /* Static build assets — images, the QR encoder, geo suggestions.
       Long-lived caching + ETag revalidation; the HTML itself stays no-cache. */
    if (p.startsWith("/assets/")) return serveStaticAsset(req, res, p);
    if (p === "/robots.txt") return serveRobots(res);
    if (p === "/sitemap.xml") return serveSitemap(req, res);
    if (p === "/" || p === "/index.html") {
      if (serveIndex(req, res)) return;
      return send(res, 200, HEALTH);
    }
    /* Clean path routes — shareable, indexable versions of the hash views.
      The SPA boots, translates the path to its hash route and renders;
      nothing inside the app changes. Unknown extension-less paths fall
      through to the SPA too (deep links never 404). */
    if (looksLikeAppPath(p)) {
      if (serveIndex(req, res)) return;
    }

    /* --- account: who am I --- */
    if (p === "/api/auth/me") {
      const found = await userFromReq(req).catch(() => null);
      if (!found) return fail(res, 401, "unauthorized", "LOG IN TO CONTINUE.");
      /* belt-and-braces member ID: the boot backfill issues IDs to every
         account, but if this one slipped through ( Atlas hiccup at boot,
         account created mid-backfill), the first /me call mints it now.
         The ID never changes after this moment. */
      let doc = found.user;
      if (!doc.memberId) {
        try {
          const { connect, ensureMemberId } = require("./ipc-pay/mongo");
          const d0 = await connect();
          const minted = await ensureMemberId(d0, doc);
          if (minted) doc = { ...doc, memberId: minted };
        } catch { /* member ID never blocks the profile */ }
      }
      const user = publicUser(doc);
      try {
        const { connect } = require("./ipc-pay/mongo");
        const d = await connect();
        const paid = await paidSummary(d, user.email);
        const tier = tierForPaid(paid.spentCentavos);
        const idx = TIERS.findIndex((x) => x.key === tier);
        const next = TIERS[idx + 1] || null;
        user.membership = {
          tier,
          spentCentavos: paid.spentCentavos,
          paidOrders: paid.paidOrders,
          nextTier: next ? { key: next.key, minPaidCentavos: next.minPaidCentavos } : null,
          nextTierGapCentavos: next ? Math.max(0, next.minPaidCentavos - paid.spentCentavos) : 0,
        };
      } catch (err) {
        user.membership = null; /* DB hiccup — the profile still loads */
      }
      /* club extras: personal referral code (auto-issued on first look),
         birthday voucher trigger, and whether 2FA is armed */
      try {
        const { connect } = require("./ipc-pay/mongo");
        const d = await connect();
        /* fresh = the full document userFromReq already loaded this request.
           This used to re-fetch with findUserById(user.id) — a STRING id that
           never matches the ObjectId _id, so fresh was always null and
           twoFAEnabled / referral / birthdayVoucher never reached the client:
           the account page kept reading TWO-FACTOR OFF after the
           authenticator was armed. */
        const fresh = found.user;
        if (fresh) {
          user.twoFAEnabled = !!fresh.twoFAEnabled;
          const code = await ensureReferralCode(d, fresh);
          user.referral = { code: code || fresh.referralCode, count: fresh.referralCount || 0 };
          const bdayCode = await ensureBirthdayVoucher(d, fresh);
          if (bdayCode) user.birthdayVoucher = bdayCode;
        }
      } catch { /* profile extras never block the profile */ }
      return send(res, 200, { ok: true, user });
    }

    /* --- my order history --- */
    if (p === "/api/orders/mine") {
      const found = await userFromReq(req).catch(() => null);
      if (!found) return fail(res, 401, "unauthorized", "LOG IN TO CONTINUE.");
      try {
        const { connect } = require("./ipc-pay/mongo");
        const d = await connect();
        const orders = await d.collection("orders")
          .find({ userId: found.user._id })
          .sort({ createdAt: -1 })
          .limit(100)
          .toArray();
        const refs = orders.map((o) => o.reference);
        const payments = await d.collection("payments")
          .find({ orderReference: { $in: refs } })
          .toArray();
        const byOrder = new Map(payments.map((pay) => [pay.orderReference, pay]));
        return send(res, 200, {
          ok: true,          orders: orders.map((o) => orderView(o, byOrder.get(o.reference))),        });
      } catch (err) {
        return mongoError(res, err, "order history failed");
      }
    }

    /* --- one payment (owner, admin, or the guest with the receipt token) --- */
    const payMatch = p.match(/^\/api\/payments\/([A-Za-z0-9-]+)$/);
    if (payMatch) {
      const found = await userFromReq(req).catch(() => null);
      const guestToken = new URL(req.url, "http://x").searchParams.get("guestToken") || "";
      const guestOk = /^[a-f0-9]{32,128}$/.test(guestToken);
      if (!found && !guestOk) return fail(res, 401, "unauthorized", "LOG IN TO CONTINUE.");
      try {
        const { connect } = require("./ipc-pay/mongo");
        const d = await connect();
        const pay = await d.collection("payments")
          .findOne({ paymentReference: payMatch[1].toUpperCase() });
        if (!pay) return fail(res, 404, "not_found", "NO PAYMENT FOUND FOR THAT REFERENCE.");
        const order = await d.collection("orders").findOne({ reference: pay.orderReference });
        const isOwner = (found && (String(pay.userId) === String(found.user._id) ||
          (order && String(order.userId) === String(found.user._id))));
        /* guests prove ownership with the one-off receipt token */
        const guestMatch = !found && order && order.guestToken === guestToken;
        if (!isOwner && !guestMatch && (!found || found.user.role !== "admin")) {
          return fail(res, 403, "forbidden", "THIS PAYMENT BELONGS TO ANOTHER ACCOUNT.");
        }
        return send(res, 200, {
          ok: true,
          payment: paymentView(pay, order, found && found.user.role === "admin"),
        });
      } catch (err) {
        return mongoError(res, err, "payment lookup failed");
      }
    }

    /* --- one receipt — owner, admin, or the guest with the receipt token.
           Same ownership law as the payment screen: nobody pulls a receipt
           for an order they can't prove is theirs. --- */
    const rcMatch = p.match(/^\/api\/receipt\/([A-Za-z0-9-]+)$/);
    if (rcMatch) {
      const found = await userFromReq(req).catch(() => null);
      const guestToken = new URL(req.url, "http://x").searchParams.get("guestToken") || "";
      const guestOk = /^[a-f0-9]{32,128}$/.test(guestToken);
      if (!found && !guestOk) return fail(res, 401, "unauthorized", "LOG IN TO CONTINUE.");
      try {
        const { connect } = require("./ipc-pay/mongo");
        const d = await connect();
        const order = await d.collection("orders")
          .findOne({ reference: rcMatch[1].toUpperCase() });
        if (!order) return fail(res, 404, "not_found", "NO ORDER FOUND FOR THAT NUMBER.");
        const isOwner = found && (String(order.userId) === String(found.user._id) ||
          (order.email && found.user.email && String(order.email).toLowerCase() === String(found.user.email).toLowerCase()));
        const guestMatch = !found && order.guestToken && order.guestToken === guestToken;
        if (!isOwner && !guestMatch && (!found || found.user.role !== "admin")) {
          return fail(res, 403, "forbidden", "THIS RECEIPT BELONGS TO ANOTHER ACCOUNT.");
        }
        const pay = await d.collection("payments")
          .findOne({ orderReference: order.reference });
        return send(res, 200, { ok: true, receipt: receiptView(order, pay) });
      } catch (err) {
        return mongoError(res, err, "receipt lookup failed");
      }
    }

    /* --- public order tracking — minimal view, no personal data --- */
    const trkMatch = p.match(/^\/api\/track\/([A-Za-z0-9-]+)$/);
    if (trkMatch) {
      try {
        const { connect } = require("./ipc-pay/mongo");
        const d = await connect();
        const q = trkMatch[1].toUpperCase();
        const order = await d.collection("orders").findOne(
          { $or: [{ reference: q }, { "tracking.number": q }] },
          { projection: { reference: 1, status: 1, createdAt: 1, tracking: 1 } }
        );
        if (!order || !order.tracking) {
          return fail(res, 404, "not_found",
            "NO TRACKING RECORD YET — TRACKING OPENS THE MOMENT PAYMENT IS ACCEPTED.");
        }
        return send(res, 200, {
          ok: true,
          tracking: {
            reference: order.reference,
            number: order.tracking.number,
            status: order.tracking.status,
            courier: order.tracking.courier || "",
            trackingUrl: order.tracking.trackingUrl || "",
            history: order.tracking.history || [],
            updatedAt: order.tracking.updatedAt,
          },
        });
      } catch (err) {
        return mongoError(res, err, "tracking lookup failed");
      }
    }

    /* --- public catalog — custom pieces added from the admin inventory --- */
    if (p === "/api/products") {
      try {
        const { connect } = require("./ipc-pay/mongo");
        const d = await boundedRead(connect(), 1500);
        if (d === "timeout") throw new Error("mongo_slow");
        const docs = await d.collection("products")
          .find({ active: { $ne: false } })
          .sort({ createdAt: -1 }).limit(200).toArray();
        const cols = await d.collection("collections")
          .find({}).sort({ createdAt: -1 }).limit(50).toArray();
        /* honest scarcity: units sold per piece from PAID orders */
        const soldRows = await d.collection("orders").aggregate([
          { $match: { status: "paid" } },
          { $unwind: "$items" },
          { $group: { _id: "$items.productId", units: { $sum: "$items.qty" } } },
        ]).toArray();
        const soldMap = {};
        soldRows.forEach((s) => { soldMap[s._id] = s.units; });
        /* surface visibility rides with the catalog — the client filters the
           shop, the home gallery showcase and the collection pages with it.
           The map also covers baked-in pieces the client already carries. */
        const visMap = await visibilityMap(d).catch(() => ({}));
        const metaMap = await productMetaMap(d).catch(() => ({}));
        /* baked pieces can be edited (price/photo/description) and archived
           without a code deploy — the overrides ride to the client in a
           side map that merges onto the baked-in shelf, and archived pieces
           lose every surface until the club restores them */
        const bakedMeta = {};
        Object.keys(BAKED_META).forEach((pid) => {
          const m = metaMap[pid];
          if (!m) return;
          const entry = {};
          META_FIELDS.forEach((f) => {
            if (m[f] === undefined) return;
            /* the client shelf prices in priceC — match its field names */
            entry[f === "priceCentavos" ? "priceC" : f] = m[f];
          });
          if (m.featured !== undefined || BAKED_DEFAULT_HOME[pid] !== undefined) {
            entry.featured = bakedIsFeatured(m, pid);
            entry.homeMain = (BAKED_DEFAULT_HOME[pid] === "main") && entry.featured;
          }
          if (m.archived !== undefined) entry.archived = !!m.archived;
          if (Object.keys(entry).length) bakedMeta[pid] = entry;
        });
        return send(res, 200, {
          ok: true,
          products: docs.map((doc) => {
            const view = productView(doc, soldMap[doc.id] || 0);
            const v = visMap[doc.id] || defaultVisibility();
            view.shopVisible = v.shopVisible;
            view.galleryVisible = v.galleryVisible;
            view.collectionVisible = v.collectionVisible;
            view.hidden = isFullyHidden(v);
            return view;
          }),
          visibility: visMap,
          bakedMeta,
          collections: cols.map((c) => ({
            slug: c.slug,
            title: c.title,
            blurb: c.blurb || "",
            soon: !!c.soon,
            launchState: c.launchState || "none",
            tierGate: c.tierGate || "none",
            launchAt: c.launchAt || null,
            storyNote: c.storyNote || "",
          })),
        });
      } catch (err) {
        return mongoError(res, err, "catalog failed");
      }
    }

    /* --- growth platform: reviews, community wall, config, admin views --- */
    if (p === "/api/reviews") return handleReviewsGet(req, res, req.url);
    if (p === "/api/streets") return handleStreetsGet(req, res);
    if (p === "/api/config") return handleConfigGet(req, res);
    if (p === "/api/admin/reviews") return handleAdminReviews(req, res);
    if (p === "/api/admin/funnel") return handleAdminFunnel(req, res);
    if (p === "/api/admin/activity") return handleAdminActivity(req, res);
    if (p === "/api/admin/analytics") return handleAdminAnalytics(req, res);
    if (p === "/api/admin/support") return handleAdminSupport(req, res);
    if (p === "/api/support/mine") return handleSupportMine(req, res);

    /* ---------------- admin GETs ---------------- */
    if (p === "/api/admin/overview" || p === "/api/admin/payments" ||
        p === "/api/admin/orders" || p === "/api/admin/users" ||
        p === "/api/admin/member" ||
        p === "/api/admin/vouchers" || p === "/api/admin/inquiries" ||
        p === "/api/admin/inventory" || p === "/api/admin/products") {
      const found = await userFromReq(req).catch(() => null);
      if (!found) return fail(res, 401, "unauthorized", "LOG IN TO CONTINUE.");
      if (found.user.role !== "admin") {
        return fail(res, 403, "forbidden", "ADMIN ONLY — THIS AREA IS FOR THE CLUB ADMINS.");
      }
      try {
        const { connect } = require("./ipc-pay/mongo");
        const d = await connect();
        if (p === "/api/admin/vouchers") {
          const vouchers = await d.collection("vouchers")
            .find({}, { projection: { code: 1, label: 1, type: 1, value: 1, minSubtotalCentavos: 1, maxUses: 1, uses: 1, active: 1, firstOrderOnly: 1, startsAt: 1, expiresAt: 1, createdAt: 1 } })
            .sort({ createdAt: -1 }).limit(200).toArray();
          return send(res, 200, { ok: true, vouchers });
        }
        if (p === "/api/admin/inquiries") {
          const rows = await d.collection("inquiries").find({})
            .sort({ createdAt: -1 }).limit(200).toArray();
          return send(res, 200, { ok: true, inquiries: rows });
        }
        if (p === "/api/admin/products") {
          const docs = await d.collection("products")
            .find({}).sort({ createdAt: -1 }).limit(200).toArray();
          const visMap = await visibilityMap(d).catch(() => ({}));
          return send(res, 200, {
            ok: true,
            products: docs.map((doc) => {
              const v = visMap[doc.id] || defaultVisibility();
              return {
                id: doc.id,
                name: doc.name,
                priceCentavos: doc.priceCentavos,
                tag: doc.tag || "",
                collection: doc.collection || "",
                sizes: doc.sizes || [],
                colors: doc.colors || [],
                desc: doc.desc || "",
                fabric: doc.fabric || "",
                fit: doc.fit || "",
                alt: doc.alt || "",
                modelInfo: doc.modelInfo || "",
                batchSize: doc.batchSize || 0,
                home: !!doc.home,
                active: doc.active !== false,
                shopVisible: v.shopVisible,
                galleryVisible: v.galleryVisible,
                collectionVisible: v.collectionVisible,
                hidden: isFullyHidden(v),
                createdAt: doc.createdAt,
              };
            }),
          });
        }
        if (p === "/api/admin/inventory") {
          const sold = await d.collection("orders").aggregate([
            { $match: { status: "paid" } },
            { $unwind: "$items" },
            { $group: { _id: "$items.productId", units: { $sum: "$items.qty" }, revenue: { $sum: { $multiply: ["$items.priceCentavos", "$items.qty"] } } } },
          ]).toArray();
          const soldMap = {};
          sold.forEach((s) => { soldMap[s._id] = s; });
          const customDocs = await d.collection("products")
            .find({}).sort({ createdAt: -1 }).limit(500).toArray();
          const visMap = await visibilityMap(d).catch(() => ({}));
          const metaMap = await productMetaMap(d).catch(() => ({}));
          const customRows = customDocs.map((doc) => ({
            id: doc.id,
            name: doc.name,
            priceCentavos: doc.priceCentavos,
            tag: doc.tag || "",
            sizes: doc.sizes && doc.sizes.length ? doc.sizes : ["OS"],
            colors: doc.colors || [],
            custom: true,
            active: doc.active !== false,
            featured: !!doc.home,
          }));
          const bakedRows = PRODUCTS.map((p) => {
            const m = metaMap[p.id] || {};
            const merged = applyBakedMeta(p, m);
            return {
              id: merged.id,
              name: merged.name,
              priceCentavos: merged.priceCentavos,
              tag: merged.tag || "",
              sizes: merged.sizes,
              colors: merged.colors,
              custom: false,
              active: true,
              featured: bakedIsFeatured(m, merged.id),
              archived: m.archived === true,
              edited: Object.keys(META_FIELDS).some((f) => m[f] !== undefined && f !== "archived"),
            };
          });
          /* archived core pieces leave the main table (so the tab stops
             stacking) but stay one toggle away — the club never loses track */
          const withArchive = bakedRows.concat(customRows);
          const inventory = withArchive.filter((p) => !p.archived).map((p) => {
            const v = visMap[p.id] || defaultVisibility();
            const active = p.active !== false;
            return {
              id: p.id,
              name: p.name,
              priceCentavos: p.priceCentavos,
              tag: p.tag || "",
              sizes: p.sizes,
              colors: p.colors,
              unitsSold: (soldMap[p.id] && soldMap[p.id].units) || 0,
              revenueCentavos: (soldMap[p.id] && soldMap[p.id].revenue) || 0,
              custom: !!p.custom,
              active,
              featured: !!p.featured,
              archived: !!p.archived,
              edited: !!p.edited,
              shopVisible: v.shopVisible,
              galleryVisible: v.galleryVisible,
              collectionVisible: v.collectionVisible,
              hidden: isFullyHidden(v),
              /* publication status in plain words for the inventory table */
              publicationStatus: !active ? "pulled" : (isFullyHidden(v) ? "hidden" : "live"),
            };
          });
          const archivedRows = withArchive.filter((p) => p.archived).map((p) => {
            const v = visMap[p.id] || defaultVisibility();
            return {
              id: p.id,
              name: p.name,
              priceCentavos: p.priceCentavos,
              tag: p.tag || "",
              sizes: p.sizes,
              colors: p.colors,
              unitsSold: (soldMap[p.id] && soldMap[p.id].units) || 0,
              revenueCentavos: (soldMap[p.id] && soldMap[p.id].revenue) || 0,
              custom: !!p.custom,
              active: p.active !== false,
              featured: !!p.featured,
              archived: true,
              edited: !!p.edited,
              shopVisible: v.shopVisible,
              galleryVisible: v.galleryVisible,
              collectionVisible: v.collectionVisible,
              hidden: isFullyHidden(v),
              publicationStatus: "archived",
            };
          });
          return send(res, 200, { ok: true, inventory, archived: archivedRows, archivedCount: archivedRows.length });
        }
        if (p === "/api/admin/overview") {
          const [users, orders, payments, paidAgg, underAgg, activeVouchers, voucherRedemptions, trackAgg, paySettings, dailyRevenue] = await Promise.all([
            d.collection("users").countDocuments(),
            d.collection("orders").countDocuments(),
            d.collection("payments").aggregate([
              { $group: { _id: "$status", n: { $sum: 1 } } },
            ]).toArray(),
            d.collection("payments").aggregate([
              { $match: { status: "paid" } },
              { $group: { _id: null, total: { $sum: "$amountCentavos" } } },
            ]).toArray(),
            d.collection("payments").aggregate([
              { $match: { status: "under_verification" } },
              { $group: { _id: null, total: { $sum: "$amountCentavos" } } },
            ]).toArray(),
            d.collection("vouchers").countDocuments({ active: true }),
            d.collection("voucherRedemptions").countDocuments(),
            d.collection("orders").aggregate([
              { $match: { "tracking.status": { $exists: true } } },
              { $group: { _id: "$tracking.status", n: { $sum: 1 } } },
            ]).toArray(),
            getPaySettings(d),
            dailyPaidRevenue(d),
          ]);
          const trackingStages = {};
          trackAgg.forEach((s) => { trackingStages[s._id] = s.n; });
          const payStatus = {};
          payments.forEach((s) => { payStatus[s._id] = s.n; });
          return send(res, 200, {
            ok: true,
            overview: {
              users,
              orders,
              paymentsPending: payStatus.pending || 0,
              paymentsUnderVerification: payStatus.under_verification || 0,
              paymentsPaid: payStatus.paid || 0,
              paymentsFailed: payStatus.failed || 0,
              paidRevenueCentavos: (paidAgg[0] && paidAgg[0].total) || 0,
              underVerificationCentavos: (underAgg[0] && underAgg[0].total) || 0,
              activeVouchers,
              voucherRedemptions,
              tracking: trackingStages,
              dailyRevenue,
              autoVerify: paySettings.autoVerify,
              rootAdmin: (process.env.ADMIN_EMAIL || "").trim().toLowerCase(),
            },
          });
        }
        if (p === "/api/admin/payments") {
          /* ?scope=all → the full record (paid + failed + waiting). Nothing is
             ever deleted — a failed purchase stays visible to the admins. */
          const scopeAll = /([?&])scope=all(&|$)/.test(req.url || "");
          const filter = scopeAll ? {} : { status: { $in: ["under_verification", "pending"] } };
          const pays = await d.collection("payments")
            .find(filter)
            .sort({ createdAt: -1 })
            .limit(200)
            .toArray();
          const orders = await d.collection("orders")
            .find({ reference: { $in: pays.map((x) => x.orderReference) } })
            .toArray();
          const byRef = new Map(orders.map((o) => [o.reference, o]));
          return send(res, 200, {
            ok: true,
            payments: pays.map((x) => paymentView(x, byRef.get(x.orderReference), true)),
          });
        }
        if (p === "/api/admin/orders") {
          const ords = await d.collection("orders")
            .find().sort({ createdAt: -1 }).limit(200).toArray();
          const pays = await d.collection("payments")
            .find({ orderReference: { $in: ords.map((o) => o.reference) } })
            .toArray();
          const byOrder = new Map(pays.map((x) => [x.orderReference, x]));
          return send(res, 200, {
            ok: true,
            orders: ords.map((o) => orderView(o, byOrder.get(o.reference))),
          });
        }
        /* /api/admin/users — the member roster with search + status filter.
           ?q= matches Member ID (with or without the PLAYA prefix), name,
           email and the digits of a mobile number. ?status= narrows to
           "active" or "removed" — the two states the accounts system
           actually carries. Both filters run in the DATABASE, so a big
           roster stays fast and the admin sees real records, not a
           client-side trick. */
        if (p === "/api/admin/users") {
          const q = new URL(req.url, "http://ipc.local").searchParams.get("q") || "";
          const status = (new URL(req.url, "http://ipc.local").searchParams.get("status") || "all").toLowerCase();
          const filter = {};
          if (status === "active" || status === "removed") filter.status = status;
          const term = String(q).trim().slice(0, 80);
          if (term) {
            const rx = new RegExp(escapeRegex(term), "i");
            const or = [{ name: rx }, { email: rx }, { memberId: rx }];
            /* Member ID lookup without the prefix — "K7M9XQ42" finds
               PLAYAK7M9XQ42; a bare "PLAYA" search still matches the prefix */
            const bare = term.replace(/^PLAYA/i, "");
            if (bare && /^[A-Z0-9]{1,8}$/i.test(bare)) or.push({ memberId: new RegExp(escapeRegex(bare), "i") });
            /* mobile: stored normalized (+639…), so search the digits only */
            const digits = term.replace(/\D/g, "");
            if (digits.length >= 7) or.push({ phone: new RegExp(escapeRegex(digits), "i") });
            filter.$or = or;
          }
          const [us, totalMembers, paidAgg, allAgg] = await Promise.all([
            d.collection("users")
              .find(filter, { projection: { email: 1, name: 1, phone: 1, role: 1, createdAt: 1, updatedAt: 1, status: 1, removedAt: 1, memberId: 1, memberIdAt: 1, twoFAEnabled: 1, passwordChangedAt: 1, birthMonth: 1 } })
              .sort({ createdAt: -1 }).limit(500).toArray(),
            d.collection("users").countDocuments({}),
            d.collection("orders").aggregate([
              { $match: { status: "paid" } },
              { $group: { _id: "$email", paidOrders: { $sum: 1 }, spent: { $sum: "$totalCentavos" } } },
            ]).toArray(),
            d.collection("orders").aggregate([
              { $group: { _id: "$email", orders: { $sum: 1 }, last: { $max: "$createdAt" } } },
            ]).toArray(),
          ]);
          const paidByEmail = new Map(paidAgg.map((x) => [x._id, x]));
          const allByEmail = new Map(allAgg.map((x) => [x._id, x]));
          return send(res, 200, {
            ok: true,
            counts: { returned: us.length, totalMembers },
            users: us.map((u) => {
              const paid = paidByEmail.get(u.email) || {};
              const all = allByEmail.get(u.email) || {};
              return {
                memberId: u.memberId || null, memberIdAt: u.memberIdAt || null,
                email: u.email, name: u.name, phone: u.phone || "", role: u.role, createdAt: u.createdAt,
                updatedAt: u.updatedAt || null, status: u.status || "active", removedAt: u.removedAt || null,
                twoFAEnabled: !!u.twoFAEnabled, passwordChangedAt: u.passwordChangedAt || null,
                birthMonth: u.birthMonth || null,
                tier: tierForPaid(paid.spent || 0),
                orders: all.orders || 0,
                paidOrders: paid.paidOrders || 0,
                spentCentavos: paid.spent || 0,
                lastOrderAt: all.last || null,
              };
            }),
          });
        }

        /* /api/admin/member — the full record for ONE member, for the
           expandable Members-tab profile. Everything comes straight from
           the database; sections the member has no records in come back
           empty and the UI says so honestly. Admin-only (the gate above). */
        if (p === "/api/admin/member") {
          const email = String(new URL(req.url, "http://ipc.local").searchParams.get("email") || "").trim().toLowerCase().slice(0, 120);
          if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return fail(res, 422, "invalid", "DROP THE MEMBER'S EMAIL.");
          }
          const u = await d.collection("users").findOne({ email });
          if (!u) return fail(res, 404, "not_found", "NO IPC ACCOUNT WITH THAT EMAIL.");
          const [orders, signIns, activity, redemptions, tickets] = await Promise.all([
            d.collection("orders").find({ $or: [{ email }, { userId: u._id }] })
              .sort({ createdAt: -1 }).limit(25).toArray(),
            d.collection("sessions").find({ userId: u._id })
              .sort({ createdAt: -1 }).limit(12).toArray(),
            d.collection("activityLogs").find({ $or: [{ actorEmail: email }, { targetType: "member", targetId: email }] })
              .sort({ createdAt: -1 }).limit(20).toArray(),
            d.collection("voucherRedemptions").find({ $or: [{ userId: u._id }, { phone: u.phone || "___none___" }] })
              .sort({ createdAt: -1 }).limit(20).toArray(),
            d.collection("supportTickets").find({ email })
              .sort({ createdAt: -1 }).limit(10).toArray(),
          ]);
          const refs = orders.map((o) => o.reference);
          const pays = refs.length
            ? await d.collection("payments").find({ orderReference: { $in: refs } })
              .sort({ createdAt: -1 }).limit(25).toArray()
            : [];
          const payByOrder = new Map(pays.map((x) => [x.orderReference, x]));
          return send(res, 200, {
            ok: true,
            member: {
              memberId: u.memberId || null, memberIdAt: u.memberIdAt || null,
              name: u.name, email: u.email, phone: u.phone || "",
              role: u.role, status: u.status || "active",
              createdAt: u.createdAt, updatedAt: u.updatedAt || null,
              removedAt: u.removedAt || null, removedBy: u.removedBy || null,
              removalReason: u.removalReason || null,
              twoFAEnabled: !!u.twoFAEnabled,
              passwordChangedAt: u.passwordChangedAt || null,
              passwordResetBy: u.passwordResetBy || null,
              birthMonth: u.birthMonth || null,
              referralCode: u.referralCode || null, referralCount: u.referralCount || 0,
            },
            orders: orders.map((o) => ({
              reference: o.reference,
              createdAt: o.createdAt,
              status: o.status,
              guest: !!o.guest,
              itemCount: (o.items || []).reduce((n, it) => n + (it.qty || 0), 0),
              items: (o.items || []).slice(0, 6).map((it) => ({ name: it.name, size: it.size, color: it.color || "", qty: it.qty, priceCentavos: it.priceCentavos })),
              subtotalCentavos: o.subtotalCentavos,
              discountCentavos: o.discountCentavos || 0,
              voucherCode: o.voucherCode || null,
              shippingCentavos: o.shippingCentavos,
              totalCentavos: o.totalCentavos,
              city: o.city || "", province: o.province || "",
              paymentStatus: payByOrder.get(o.reference) ? payByOrder.get(o.reference).status : null,
            })),
            payments: pays.map((x) => ({
              paymentReference: x.paymentReference,
              orderReference: x.orderReference,
              status: x.status,
              method: x.method || "qr",
              amountCentavos: x.amountCentavos,
              refNo: x.refNo || null,
              proofPresent: !!x.proofDataUrl,
              createdAt: x.createdAt,
              verifiedAt: x.verifiedAt || null,
              reviewedBy: x.reviewedBy || null,
            })),
            vouchers: redemptions.map((r) => ({
              code: r.code, orderReference: r.orderReference, createdAt: r.createdAt,
            })),
            signIns: signIns.map((s) => ({ createdAt: s.createdAt, expiresAt: s.expiresAt })),
            activity: activity.map((a) => ({
              action: a.action, targetType: a.targetType, targetId: a.targetId,
              targetLabel: a.targetLabel, details: a.details, createdAt: a.createdAt,
            })),
            tickets: tickets.map((t) => ({
              ref: t.ref || t.id, subject: t.subject, status: t.status,
              createdAt: t.createdAt, updatedAt: t.updatedAt,
            })),
          });
        }

      } catch (err) {
        return mongoError(res, err, "admin query failed");
      }    }

    return send(res, 404, { ok: false, reason: "not_found" });
  }

  /* ---------------- POST routes ---------------- */
  if (req.method !== "POST") {
    return send(res, 405, { ok: false, reason: "method_not_allowed" });
  }

  /* --- contact relay: body limit 20KB (unchanged) --- */
  const isContact = /^\/(api\/)?contact\/?$/.test(p);
  if (isContact) return handleContact(req, res, ip);

  /* --- auth endpoints: 20KB, small bodies --- */
  if (p === "/api/auth/register" || p === "/api/auth/login" || p === "/api/auth/logout") {
    return handleAuth(req, res, ip, p);
  }

  /* --- self-service password reset + admin two-factor --- */
  if (p === "/api/auth/forgot") return handleForgotPassword(req, res, ip);
  if (p === "/api/auth/reset") return handleResetPassword(req, res, ip);
  if (p === "/api/auth/2fa/setup") return handle2faSetup(req, res);
  if (p === "/api/auth/2fa/enable") return handle2faEnable(req, res);
  if (p === "/api/auth/2fa/disable") return handle2faDisable(req, res);
  if (p === "/api/auth/2fa/verify") return handle2faVerify(req, res, ip);

  if (p === "/api/auth/password") return handlePasswordChange(req, res);

  /* --- newsletter signup: small body, self rate-limited --- */
  if (p === "/api/newsletter") return handleNewsletter(req, res, ip);

  /* --- admin role management: 20KB --- */
  if (p === "/api/admin/role") return handleAdminRole(req, res);

  /* --- voucher validation + admin voucher management: 20KB --- */
  if (p === "/api/vouchers/validate") {
    if (rateLimited(ip, 20, 15 * 60 * 1000, "voucher")) {
      return fail(res, 429, "rate_limited", "TOO MANY VOUCHER CHECKS — GIVE IT A FEW MINUTES.");
    }
    return handleValidateVoucher(req, res);
  }
  if (p === "/api/admin/vouchers") return handleAdminVoucherCreate(req, res);
  if (p === "/api/admin/vouchers/toggle") return handleAdminVoucherToggle(req, res);

  /* --- orders: 20KB — rate limited against scripted order spam --- */
  if (p === "/api/orders") {
    if (rateLimited(ip, 12, 15 * 60 * 1000, "orders")) {
      return fail(res, 429, "rate_limited", "TOO MANY ORDERS IN A ROW — TAKE A BREATH AND TRY AGAIN.");
    }
    return handleCreateOrder(req, res);
  }
  /* attach a guest order to a freshly created account */
  if (p === "/api/orders/link") return handleOrdersLink(req, res);

  /* --- proof upload: the ONE route allowed a big body (8MB covers a
         5MB image after base64 inflation) — rate limited + capped per order --- */
  if (p === "/api/payments/proof") {
    if (rateLimited(ip, 10, 15 * 60 * 1000, "proof")) {
      return fail(res, 429, "rate_limited", "TOO MANY PROOF UPLOADS — TRY AGAIN IN A FEW MINUTES.");
    }
    return handleProof(req, res);
  }

  /* --- admin decision: 20KB --- */
  if (p === "/api/admin/decision") return handleDecision(req, res);

  /* --- tracking / settings / emergency member removal + restore / maya webhook --- */
  if (p === "/api/admin/settings") return handleAdminSettings(req, res);
  if (p === "/api/admin/tracking") return handleAdminTracking(req, res);
  if (p === "/api/admin/members/remove") return handleMemberRemove(req, res);
  if (p === "/api/admin/members/restore") return handleMemberRestore(req, res);
  if (p === "/api/admin/members/password") return handleAdminMemberPassword(req, res);
  if (p === "/api/ipc-pay/maya-webhook") return handleMayaWebhook(req, res);

  /* --- club inventory: the team adds their own pieces straight to the shop --- */
  if (p === "/api/admin/products/remove") return handleAdminProductRemove(req, res);
  if (p === "/api/admin/products/delete") return handleAdminProductDelete(req, res);
  if (p === "/api/admin/products/featured") return handleAdminProductFeatured(req, res);
  if (p === "/api/admin/products") return handleAdminProductSave(req, res);
  if (p === "/api/admin/products/visibility") return handleAdminProductVisibility(req, res);
  if (p === "/api/admin/products/restore") return handleAdminProductRestore(req, res);
  if (p === "/api/admin/support/reply") return handleAdminSupportReply(req, res);
  if (p === "/api/admin/support/status") return handleAdminSupportStatus(req, res);
  if (p === "/api/support") return handleSupportCreate(req, res, ip);
  if (p === "/api/support/reply") return handleSupportReply(req, res);
  if (p === "/api/support/read") return handleSupportRead(req, res);

  /* --- growth platform: reviews, streets, funnel, config, launch states --- */
  if (p === "/api/reviews") return handleReviewCreate(req, res);
  if (p === "/api/admin/reviews/moderate") return handleAdminReviewModerate(req, res);
  if (p === "/api/admin/streets") return handleAdminStreetAdd(req, res);
  if (p === "/api/admin/streets/remove") return handleAdminStreetRemove(req, res);
  if (p === "/api/analytics/event") return handleAnalyticsEvent(req, res, ip);
  if (p === "/api/admin/config") return handleConfigSet(req, res);
  if (p === "/api/admin/maintenance") return handleMaintenanceSet(req, res);
  if (p === "/api/admin/collections/state") return handleCollectionState(req, res);

  return send(res, 404, { ok: false, reason: "not_found" });
}

/* --------------------------------------------------------------- */
/* PAYMENT EMAIL — EmailJS template configured separately from the contact form. */
async function sendPaymentEmail(pay, order, status, detail) {
  const publicKey = process.env.EMAILJS_PUBLIC_KEY || "";
  const serviceId = process.env.EMAILJS_SERVICE_ID || "";
  const templateId = process.env.EMAILJS_PAYMENT_TEMPLATE_ID || "";
  if (!publicKey || !serviceId || !templateId) {
    console.warn("[ipc-pay] payment email skipped: EMAILJS_PAYMENT_TEMPLATE_ID or EmailJS credentials missing.");
    return false;
  }
  const amount = new Intl.NumberFormat("en-PH", { style: "currency", currency: "PHP" })
    .format((pay.amountCentavos || 0) / 100);
  try {
    const response = await fetch(EMAILJS_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        service_id: serviceId,
        template_id: templateId,
        user_id: publicKey,
        template_params: {
          to_email: pay.email || (order && order.email) || "",
          customer_name: (order && order.customerName) || "IPC customer",
          order_reference: pay.orderReference || "",
          payment_reference: pay.paymentReference || "",
          amount: amount,
          payment_status: status,
          status_detail: detail,
          reply_to: "INDULGE PLAYAS CLUB",
        },
      }),
      signal: AbortSignal.timeout(15000),
    });
    if (!response.ok) throw new Error("EmailJS responded " + response.status);
    return true;
  } catch (err) {
    console.error("[ipc-pay] payment email failed:", err.message);
    return false;
  }
}

/* CONTACT RELAY — behavior preserved exactly                       */
/* --------------------------------------------------------------- */

const recentContactSubmissions = new Map();

function handleContact(req, res, ip) {
  let raw = "";
  let dead = false;
  req.on("data", (chunk) => {
    raw += chunk;
    if (raw.length > 20000) {
      dead = true;
      req.destroy();
    }
  });

  req.on("end", async () => {
    if (dead) return;

    let body = {};
    try {
      body = JSON.parse(raw || "{}");
    } catch {
      return send(res, 400, { ok: false, reason: "bad_request" });
    }

    /* Honeypot — bots receive a fake success. */
    if (typeof body.cf_hp === "string" && body.cf_hp.trim() !== "") {
      return send(res, 200, { ok: true });
    }

    const fromName = String(body.from_name ?? "").trim();
    const replyTo = String(body.reply_to ?? "").trim();
    const message = String(body.message ?? "").trim();
    const sentAt = String(body.sent_at ?? "").trim();
    const valid =
      fromName.length > 0 && fromName.length <= 80 &&
      replyTo.length > 0 && replyTo.length <= 120 &&
      message.length > 0 && message.length <= 2000;
    if (!valid) {
      return send(res, 422, { ok: false, reason: "invalid" });
    }

    /* Ignore accidental double-clicks/retries for the same message. */
    const duplicateKey = [ip, fromName.toLowerCase(), replyTo.toLowerCase(), message].join("|");
    const lastSent = recentContactSubmissions.get(duplicateKey);
    if (lastSent && Date.now() - lastSent < 90000) {
      return send(res, 200, { ok: true, duplicate: true });
    }

    /* No hourly contact-form cap: valid customer inquiries may be submitted.
       The 90-second duplicate guard above still prevents accidental repeat sends. */

    const publicKey = process.env.EMAILJS_PUBLIC_KEY || "";
    const serviceId = process.env.EMAILJS_SERVICE_ID || "";
    const templateId = process.env.EMAILJS_TEMPLATE_ID || "";
    const confirmationTemplateId = process.env.EMAILJS_CONFIRMATION_TEMPLATE_ID || "";
    /* The business notification is the essential flow. A missing customer
       confirmation template must never block a valid contact message. */
    if (!publicKey || !serviceId || !templateId) {
      console.error("[contact] missing required EmailJS configuration:", {
        publicKey: Boolean(publicKey),
        serviceId: Boolean(serviceId),
        businessTemplateId: Boolean(templateId),
      });
      return send(res, 503, { ok: false, reason: "not_configured" });
    }

    const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const hasCustomerEmail = emailPattern.test(replyTo);
    const templateParams = {
      from_name: fromName,
      reply_to: replyTo,
      message: message,
      sent_at: sentAt || new Date().toLocaleString("en-PH"),
    };

    async function sendContactEmail(targetTemplateId) {
      const response = await fetch(EMAILJS_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          service_id: serviceId,
          template_id: targetTemplateId,
          user_id: publicKey,
          template_params: templateParams,
        }),
        signal: AbortSignal.timeout(15000),
      });
      const detail = await response.text().catch(() => "");
      if (!response.ok) {
        throw new Error("EmailJS HTTP " + response.status + (detail ? ": " + detail.slice(0, 400) : ""));
      }
      return detail;
    }

    try {
      /* Store the inquiry for the admin dashboard FIRST — the club keeps
         the lead even when the EmailJS relay is down or misconfigured. */
      /* Store the inquiry for the admin dashboard — the club keeps the lead
         even when the email relay is unavailable. */
      try {
        const { connect } = require("./ipc-pay/mongo");
        const d = await connect();
        await d.collection("inquiries").insertOne({
          name: fromName,
          contact: replyTo,
          message,
          ip,
          createdAt: new Date(),
          businessEmailSent: true,
        });
      } catch (dbErr) {
        console.warn("[contact] inquiry not stored:", dbErr.message);
      }
      /* Send the IPC inbox notification next. This is the primary success
         condition shown to the visitor. */
      await sendContactEmail(templateId);
      recentContactSubmissions.set(duplicateKey, Date.now());      if (recentContactSubmissions.size > 1000) {
        const cutoff = Date.now() - 90000;        for (const [key, timestamp] of recentContactSubmissions) {
          if (timestamp < cutoff) recentContactSubmissions.delete(key);
        }
      }

      /* Send the customer acknowledgement only when an actual email address
         was supplied. Facebook names/handles remain valid contact details
         for the business notification but cannot receive email. */
      let confirmationSent = false;
      if (confirmationTemplateId && hasCustomerEmail) {
        try {
          await sendContactEmail(confirmationTemplateId);
          confirmationSent = true;
        } catch (err) {
          console.error("[contact] customer confirmation failed after business email succeeded:", err.message);
        }
      } else if (!confirmationTemplateId) {
        console.warn("[contact] customer confirmation skipped: EMAILJS_CONFIRMATION_TEMPLATE_ID is not configured.");
      } else {
        console.info("[contact] customer confirmation skipped: contact detail is not an email address.");
      }

      return send(res, 200, {
        ok: true,
        businessEmailSent: true,
        customerConfirmationSent: confirmationSent,
      });
    } catch (err) {
      console.error("[contact] business notification failed:", err.message);
      return send(res, 502, { ok: false, reason: "business_email_failed" });
    }
  });
}

/* --------------------------------------------------------------- */
/* AUTH — register / login / logout                                 */
/* --------------------------------------------------------------- */

async function handleAuth(req, res, ip, p) {
  if (rateLimited(ip, 30, 15 * 60 * 1000, "auth")) {
    return fail(res, 429, "rate_limited", "TOO MANY ATTEMPTS — WAIT A FEW MINUTES.");
  }
  const body = await readBody(req, res, 20000);
  if (body === null) return; // socket destroyed
  if (body === undefined) return fail(res, 400, "bad_request", "MALFORMED REQUEST BODY.");

  try {
    /* ---- register ---- */
    if (p === "/api/auth/register") {
      const name = String(body.name ?? "").trim().slice(0, 80);
      const email = String(body.email ?? "").trim().toLowerCase().slice(0, 120);
      const password = String(body.password ?? "");
      let phone;
      try { phone = normalizePhilippineMobile(body.phone); }
      catch (err) { return fail(res, 422, "invalid_phone", err.message); }
      /* optional birth month — powers the birthday voucher (1-12) */
      let birthMonth = Math.round(Number(body.birthMonth));
      if (!Number.isFinite(birthMonth) || birthMonth < 1 || birthMonth > 12) birthMonth = 0;
      if (!name) return fail(res, 422, "invalid", "DROP YOUR NAME TO JOIN THE CLUB.");
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return fail(res, 422, "invalid", "THAT EMAIL DOESN'T LOOK RIGHT.");
      }
      if (password.length < 8 || password.length > 72) {
        return fail(res, 422, "invalid", "PASSWORD NEEDS AT LEAST 8 CHARACTERS.");
      }
      const existing = await findUserByEmail(email);
      if (existing && existing.status === "removed") {
        return fail(res, 403, "account_removed",
          "THIS ACCOUNT WAS REMOVED BY THE CLUB AND CANNOT RE-JOIN. MESSAGE @INDULGEPLAYASCLUB IF YOU THINK THIS IS A MISTAKE.");
      }
      if (existing) {
        return fail(res, 409, "email_taken", "EMAIL ALREADY REGISTERED — LOG IN INSTEAD.");
      }
      const { connect } = require("./ipc-pay/mongo");
      const d = await connect();
      const phoneOwner = await d.collection("users").findOne({ phone });
      if (phoneOwner) {
        return fail(res, 409, "phone_taken", "THIS MOBILE NUMBER IS ALREADY LINKED TO AN IPC ACCOUNT. LOG IN INSTEAD.");
      }
      const user = await insertUser({ email, name, password, phone, role: "customer", birthMonth });
      const token = await createSession(user);
      return send(res, 200, { ok: true, token, user: publicUser(user) });
    }

    /* ---- login: email OR the member's linked mobile number ---- */
    if (p === "/api/auth/login") {
      const identifier = String(body.email ?? "").trim();
      const password = String(body.password ?? "");
      const { verifyPassword, findUserByPhone } = require("./ipc-pay/mongo");
      let user = null;
      if (identifier.includes("@")) {
        user = await findUserByEmail(identifier.toLowerCase().slice(0, 120));
      } else if (identifier) {
        /* no @ — treat it as the mobile number the member joined with */
        try { user = await findUserByPhone(normalizePhilippineMobile(identifier)); }
        catch (err) { user = null; }
      }
      if (!user || !verifyPassword(password, user.salt, user.hash)) {
        return fail(res, 401, "bad_credentials", "WRONG EMAIL, MOBILE OR PASSWORD.");
      }
      if (user.status === "removed") {
        return fail(res, 403, "account_removed",
          "THIS ACCOUNT WAS REMOVED BY THE CLUB. MESSAGE @INDULGEPLAYASCLUB IF YOU THINK THIS IS A MISTAKE.");
      }
      /* admin two-factor: password alone never issues a session */
      if (user.twoFAEnabled && user.twoFASecret) {
        const challenge = crypto.randomBytes(24).toString("hex");
        try {
          const { connect } = require("./ipc-pay/mongo");
          const d = await connect();
          await d.collection("twoFALogins").insertOne({
            challenge,
            userId: user._id,
            createdAt: new Date(),
            expiresAt: new Date(Date.now() + 5 * 60 * 1000),
          });
        } catch (err) {
          return mongoError(res, err, "2fa challenge failed");
        }
        return send(res, 200, { ok: false, twoFactorRequired: true, challenge,
          message: "ENTER THE 6-DIGIT CODE FROM YOUR AUTHENTICATOR APP." });
      }
      const token = await createSession(user);
      return send(res, 200, { ok: true, token, user: publicUser(user) });
    }

    /* ---- logout ---- */
    const token = bearerToken(req);
    if (token) await deleteSession(token);
    return send(res, 200, { ok: true });
  } catch (err) {
    if (err && err.code === 11000) {
      return fail(res, 409, "account_already_exists",
        "THAT EMAIL OR MOBILE NUMBER IS ALREADY LINKED TO AN IPC ACCOUNT.");
    }
    return mongoError(res, err, "auth failed");
  }
}

/* --------------------------------------------------------------- */
/* VOUCHERS — server-side validation and one-per-customer redemption */
/* --------------------------------------------------------------- */

function subtotalFromCart(rawItems) {
  if (!Array.isArray(rawItems) || rawItems.length < 1 || rawItems.length > 30) {
    throw new Error("YOUR BAG IS EMPTY OR HAS TOO MANY ITEMS.");
  }
  let subtotal = 0;
  for (const raw of rawItems) {
    const product = PRODUCTS.find((x) => x.id === String(raw.productId ?? ""));
    if (!product) throw new Error("UNKNOWN PRODUCT IN YOUR BAG — REFRESH AND TRY AGAIN.");
    const size = String(raw.size ?? "").trim();
    const color = String(raw.color ?? "").trim();
    const qty = Math.floor(Number(raw.qty ?? 0));
    if (!product.sizes.includes(size) || !product.colors.includes(color) ||        !Number.isFinite(qty) || qty < 1 || qty > 99) {
      throw new Error("CHECK YOUR PRODUCT OPTIONS AND QUANTITIES BEFORE APPLYING A VOUCHER.");
    }
    subtotal += product.priceCentavos * qty;
  }
  return subtotal;
}

async function linkAccountPhone(d, user, rawPhone) {
  const phone = normalizePhilippineMobile(rawPhone);
  if (user.phone && user.phone !== phone) {
    throw new Error("USE THE MOBILE NUMBER LINKED TO YOUR IPC ACCOUNT.");
  }
  const owner = await d.collection("users").findOne({ phone, _id: { $ne: user._id } });
  if (owner) throw new Error("THIS MOBILE NUMBER IS ALREADY LINKED TO ANOTHER IPC ACCOUNT.");
  if (!user.phone) {
    const update = await d.collection("users").updateOne(
      { _id: user._id, $or: [{ phone: { $exists: false } }, { phone: null }, { phone: "" }] },
      { $set: { phone } }
    );
    if (update.modifiedCount !== 1) {
      const fresh = await d.collection("users").findOne({ _id: user._id });
      if (!fresh || fresh.phone !== phone) throw new Error("COULD NOT LINK THIS MOBILE NUMBER TO YOUR ACCOUNT.");
    }
    user.phone = phone;
  }
  return phone;
}

async function resolveVoucher(d, codeInput, user, phone, subtotalCentavos) {
  const code = normalizeVoucherCode(codeInput);
  const voucher = await d.collection("vouchers").findOne({ code });
  if (!voucher || !voucher.active) throw new Error("THAT VOUCHER IS NOT ACTIVE OR DOES NOT EXIST.");
  const now = new Date();
  if (voucher.startsAt && now < new Date(voucher.startsAt)) throw new Error("THAT VOUCHER IS NOT AVAILABLE YET.");
  if (voucher.expiresAt && now > new Date(voucher.expiresAt)) throw new Error("THAT VOUCHER HAS EXPIRED.");
  if (voucher.maxUses > 0 && (voucher.uses || 0) >= voucher.maxUses) throw new Error("THAT VOUCHER HAS REACHED ITS USE LIMIT.");
  if (subtotalCentavos < (voucher.minSubtotalCentavos || 0)) {
    throw new Error("YOUR BAG DOES NOT MEET THE MINIMUM SPEND FOR THIS VOUCHER.");
  }
  const redeemed = await d.collection("voucherRedemptions").findOne({
    code,
    $or: [{ userId: user._id }, { phone }],
  });
  if (redeemed) throw new Error("THIS VOUCHER HAS ALREADY BEEN USED WITH YOUR ACCOUNT OR MOBILE NUMBER.");
  if (voucher.firstOrderOnly) {
    const nationalDigits = phone.slice(3);
    const legacyPhonePattern = "^(?:\\+?63\\D*)?0?" + nationalDigits.split("").join("\\D*") + "$";
    const priorOrder = await d.collection("orders").findOne({
      $or: [
        { userId: user._id },
        { phoneNormalized: phone },
        { phone: { $regex: legacyPhonePattern, $options: "i" } },
      ],
    });
    if (priorOrder) throw new Error("THIS OFFER IS RESERVED FOR YOUR FIRST IPC ORDER.");
  }
  const discountCentavos = calculateVoucherDiscount(subtotalCentavos, voucher);
  if (discountCentavos <= 0) throw new Error("THIS VOUCHER DOES NOT APPLY TO YOUR CURRENT BAG.");
  /* shipping is priced from the delivery address at order time — the
     voucher check here judges the pieces alone */
  if (subtotalCentavos - discountCentavos < 100) {
    throw new Error("THE VOUCHER MUST LEAVE AT LEAST ₱1.00 TO PAY.");
  }
  return { voucher, code, discountCentavos };
}

async function handleValidateVoucher(req, res) {
  const found = await userFromReq(req).catch(() => null);
  if (!found) return fail(res, 401, "unauthorized", "LOG IN TO APPLY A VOUCHER.");
  const body = await readBody(req, res, 20000);
  if (body === null) return;
  if (body === undefined) return fail(res, 400, "bad_request", "MALFORMED REQUEST BODY.");
  try {
    const { connect } = require("./ipc-pay/mongo");
    const d = await connect();
    const phone = await linkAccountPhone(d, found.user, body.phone);
    const subtotalCentavos = subtotalFromCart(body.items);
    const result = await resolveVoucher(d, body.code, found.user, phone, subtotalCentavos);
    /* with the member's city + province in, the estimate carries the real
       zone rate; before that, shipping stays out of the math */
    const ship = body.city
      ? computeShipping(String(body.city), String(body.province || body.city))
      : { fee: 0, zone: null, key: "unknown" };
    return send(res, 200, {
      ok: true,
      code: result.code,
      label: result.voucher.label || result.code,
      subtotalCentavos,
      discountCentavos: result.discountCentavos,
      shippingCentavos: ship.fee,
      shippingZone: ship.zone,
      totalCentavos: Math.max(0, subtotalCentavos + ship.fee - result.discountCentavos),
      message: "VOUCHER APPLIED — YOUR DISCOUNT IS RESERVED WHEN YOU PLACE THE ORDER.",
    });
  } catch (err) {
    return fail(res, 422, "voucher_invalid", err.message || "VOUCHER COULD NOT BE APPLIED.");
  }
}

/* Grant or revoke ADMIN for a member by email. The seeded club-owner
   account (ADMIN_EMAIL) and the developer account (ancel.claudio1@gmail.com)
   can never be demoted. */
async function handleAdminRole(req, res) {
  const found = await userFromReq(req).catch(() => null);
  if (!found) return fail(res, 401, "unauthorized", "LOG IN TO CONTINUE.");
  if (found.user.role !== "admin") return fail(res, 403, "forbidden", "ADMIN ONLY.");
  const body = await readBody(req, res, 20000);
  if (body === null) return;
  if (body === undefined) return fail(res, 400, "bad_request", "MALFORMED REQUEST BODY.");
  try {
    const email = String(body.email ?? "").trim().toLowerCase().slice(0, 120);
    const role = String(body.role ?? "").toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return fail(res, 422, "invalid", "DROP THE MEMBER'S EMAIL.");
    }
    if (role !== "admin" && role !== "customer") {
      return fail(res, 422, "invalid", "ROLE IS ADMIN OR MEMBER ONLY.");
    }
    const root = (process.env.ADMIN_EMAIL || "").trim().toLowerCase();
    /* ancel.claudio1@gmail.com is the club owner / developer account —
       it can never be demoted to a member, even if ADMIN_EMAIL is unset
       or points somewhere else. */
    if (email === "ancel.claudio1@gmail.com" || (root && email === root)) {
      if (role !== "admin") {
        return fail(res, 403, "root_admin", "THE CLUB OWNER ACCOUNT STAYS ADMIN.");
      }
    }
    const { connect } = require("./ipc-pay/mongo");
    const d = await connect();
    const target = await d.collection("users").findOne({ email });
    if (!target) return fail(res, 404, "not_found", "NO IPC ACCOUNT WITH THAT EMAIL.");
    if (target.role === role) {
      return send(res, 200, { ok: true, user: publicUser(target), message: "ALREADY " + (role === "admin" ? "AN ADMIN" : "A MEMBER") + "." });
    }
    await d.collection("users").updateOne({ _id: target._id }, { $set: { role, updatedAt: new Date() } });
    await logActivity(d, found.user.email, "member_role", "member", email, email,
      "ROLE " + target.role.toUpperCase() + " → " + role.toUpperCase());
    const fresh = await d.collection("users").findOne({ _id: target._id });
    return send(res, 200, {
      ok: true,
      user: publicUser(fresh),
      message: fresh.role === "admin" ? "ADMIN GRANTED." : "ADMIN REMOVED.",
    });
  } catch (err) {
    return mongoError(res, err, "role change failed");
  }
}

async function handleAdminVoucherCreate(req, res) {
  const found = await userFromReq(req).catch(() => null);
  if (!found) return fail(res, 401, "unauthorized", "LOG IN TO CONTINUE.");
  if (found.user.role !== "admin") return fail(res, 403, "forbidden", "ADMIN ONLY.");
  const body = await readBody(req, res, 20000);
  if (body === null) return;
  if (body === undefined) return fail(res, 400, "bad_request", "MALFORMED REQUEST BODY.");
  try {
    const code = normalizeVoucherCode(body.code);
    const label = String(body.label || code).trim().slice(0, 80);
    const type = String(body.type || "").toLowerCase();
    const rawValue = Number(body.value);
    const minOrderPhp = Number(body.minOrderPhp || 0);
    const maxUses = Math.floor(Number(body.maxUses || 0));
    if (type !== "percent" && type !== "fixed") return fail(res, 422, "invalid", "CHOOSE PERCENTAGE OR FIXED AMOUNT.");
    if (!Number.isFinite(rawValue) || rawValue <= 0 ||
        (type === "percent" && (!Number.isInteger(rawValue) || rawValue > 100)) ||
        (type === "fixed" && rawValue > 100000)) {
      return fail(res, 422, "invalid", "ENTER A VALID VOUCHER VALUE.");
    }
    if (!Number.isFinite(minOrderPhp) || minOrderPhp < 0 || minOrderPhp > 1000000 ||
        !Number.isFinite(maxUses) || maxUses < 0 || maxUses > 1000000) {
      return fail(res, 422, "invalid", "CHECK THE MINIMUM SPEND AND USE LIMIT.");
    }
    const expiresAt = body.expiresAt ? new Date(String(body.expiresAt).slice(0, 10) + "T23:59:59.999") : null;
    if (expiresAt && (!Number.isFinite(expiresAt.getTime()) || expiresAt <= new Date())) {
      return fail(res, 422, "invalid", "EXPIRY MUST BE A FUTURE DATE.");
    }
    const doc = {
      code, label, type,
      value: type === "fixed" ? Math.round(rawValue * 100) : rawValue,
      minSubtotalCentavos: Math.round(minOrderPhp * 100),
      maxUses,
      uses: 0,
      firstOrderOnly: body.firstOrderOnly !== false,
      active: true,
      startsAt: body.startsAt ? new Date(body.startsAt) : null,
      expiresAt,
      createdAt: new Date(),
      createdBy: found.user.email,
    };
    const { connect } = require("./ipc-pay/mongo");
    const d = await connect();
    await d.collection("vouchers").insertOne(doc);
    await logActivity(d, found.user.email, "voucher_create", "voucher", code,
      "VOUCHER " + code,
      (type === "percent" ? value + "% OFF" : "₱" + (value / 100).toFixed(2) + " OFF") +
        " · MAX USES " + maxUses + (expiresAt ? " · EXPIRES " + expiresAt.toISOString().slice(0, 10) : ""));
    return send(res, 201, { ok: true, voucher: doc });
  } catch (err) {
    if (err && err.code === 11000) return fail(res, 409, "voucher_exists", "THAT VOUCHER CODE ALREADY EXISTS.");
    return fail(res, 422, "invalid", err.message || "COULD NOT CREATE VOUCHER.");
  }
}

async function handleAdminVoucherToggle(req, res) {
  const found = await userFromReq(req).catch(() => null);
  if (!found) return fail(res, 401, "unauthorized", "LOG IN TO CONTINUE.");
  if (found.user.role !== "admin") return fail(res, 403, "forbidden", "ADMIN ONLY.");
  const body = await readBody(req, res, 20000);
  if (body === null) return;
  if (body === undefined) return fail(res, 400, "bad_request", "MALFORMED REQUEST BODY.");
  try {
    const code = normalizeVoucherCode(body.code);
    if (typeof body.active !== "boolean") return fail(res, 422, "invalid", "ACTIVE MUST BE TRUE OR FALSE.");
    const { connect } = require("./ipc-pay/mongo");
    const d = await connect();
    const result = await d.collection("vouchers").updateOne({ code }, { $set: { active: body.active, updatedAt: new Date() } });
    if (!result.matchedCount) return fail(res, 404, "not_found", "VOUCHER NOT FOUND.");
    await logActivity(d, found.user.email, "voucher_toggle", "voucher", code,
      "VOUCHER " + code, body.active ? "VOUCHER SWITCHED ON" : "VOUCHER SWITCHED OFF");
    return send(res, 200, { ok: true, code, active: body.active });
  } catch (err) {
    return fail(res, 422, "invalid", err.message || "COULD NOT UPDATE VOUCHER.");
  }
}

/* --------------------------------------------------------------- */
/* ORDERS — create (prices recomputed server-side, always)          */
/* --------------------------------------------------------------- */

async function handleCreateOrder(req, res) {
  const found = await userFromReq(req).catch(() => null);
  const body = await readBody(req, res, 20000);
  if (body === null) return;
  if (body === undefined) return fail(res, 400, "bad_request", "MALFORMED REQUEST BODY.");
  /* guest checkout: no account required — the order still stores the full
     customer block and carries a one-off receipt token for the pay screen */
  const guestMode = !found && body.guest === true;
  if (!found && !guestMode) return fail(res, 401, "unauthorized", "LOG IN TO CHECK OUT.");

  const rawItems = Array.isArray(body.items) ? body.items : [];
  if (rawItems.length === 0) {
    return fail(res, 422, "empty_bag", "YOUR BAG IS EMPTY — ADD A PIECE BEFORE CHECKING OUT.");
  }
  if (rawItems.length > 30) {
    return fail(res, 422, "invalid", "TOO MANY LINES IN ONE ORDER — SPLIT IT UP.");
  }
  const lines = [];
  let dbForCatalog = null;
  let dbMetaMap = null;
  for (const raw of rawItems) {
    let product = PRODUCTS.find((x) => x.id === String(raw.productId ?? ""));
    /* baked pieces can carry club edits (price/name/sizes) in productMeta —
       the checkout always prices against the merged catalog */
    if (product) {
      try {
        if (!dbForCatalog) {
          const { connect } = require("./ipc-pay/mongo");
          dbForCatalog = await connect();
        }
        if (!dbMetaMap) dbMetaMap = await productMetaMap(dbForCatalog);
        const m = dbMetaMap[product.id];
        if (m && m.archived === true) {
          return fail(res, 422, "unavailable", (m.name || product.name).toUpperCase() + " IS NO LONGER CARRIED BY THE CLUB — REMOVE IT FROM YOUR BAG.");
        }
        product = applyBakedMeta(product, m);
      } catch { /* baked defaults stay the price of record */ }
    }
    /* club-added pieces live in Atlas — the baked-in catalog is not enough */
    if (!product) {
      try {
        if (!dbForCatalog) {
          const { connect } = require("./ipc-pay/mongo");
          dbForCatalog = await connect();
        }
        const doc = await dbForCatalog.collection("products")
          .findOne({ id: String(raw.productId ?? ""), active: { $ne: false } });
        if (doc) {
          product = {
            id: doc.id, name: doc.name, priceCentavos: doc.priceCentavos,
            sizes: doc.sizes || ["OS"], colors: doc.colors || [],
            collection: doc.collection || "",
            batchSize: doc.batchSize || 0,
          };
        }
      } catch { /* falls through to the unknown-product error */ }
    }
    if (!product) {
      return fail(res, 422, "invalid", "UNKNOWN PRODUCT IN YOUR BAG — REFRESH AND TRY AGAIN.");
    }
    const size = String(raw.size ?? "").trim();
    const color = String(raw.color ?? "").trim();
    const qty = Math.floor(Number(raw.qty ?? 0));
    if (!size || !product.sizes.includes(size)) {
      return fail(res, 422, "invalid", `PICK A SIZE FOR ${product.name}.`);
    }
    if (!color || !product.colors.includes(color)) {
      return fail(res, 422, "invalid", `PICK A COLORWAY FOR ${product.name}.`);
    }
    if (!Number.isFinite(qty) || qty < 1 || qty > 99) {
      return fail(res, 422, "invalid", `INVALID QUANTITY FOR ${product.name}.`);
    }
    lines.push({
      productId: product.id,
      name: product.name,
      size,
      color,
      qty,
      priceCentavos: product.priceCentavos,
      collection: product.collection || "",
      batch: Math.round(Number(product.batchSize) || 0),
    });
  }

  const subtotalCentavos = lines.reduce((s, l) => s + l.priceCentavos * l.qty, 0);

  /* CART ACCURACY — the last word on availability and stock happens here,
     at the moment of checkout, against live data: a piece the club fully
     hidden cannot be bought, and a batched piece cannot be oversold.
     Baked-in pieces without a batch are open stock. */
  try {
    if (!dbForCatalog) {
      const { connect } = require("./ipc-pay/mongo");
      dbForCatalog = await connect();
    }
    const [vis, metaRows, soldRows] = await Promise.all([
      visibilityMap(dbForCatalog).catch(() => ({})),
      productMetaMap(dbForCatalog).catch(() => ({})),
      dbForCatalog.collection("orders").aggregate([
        { $match: { status: "paid" } },
        { $unwind: "$items" },
        { $group: { _id: "$items.productId", units: { $sum: "$items.qty" } } },
      ]).toArray(),
    ]);
    const soldMap = {};
    soldRows.forEach((s) => { soldMap[s._id] = s.units; });
    const perProduct = {};
    lines.forEach((l) => { perProduct[l.productId] = (perProduct[l.productId] || 0) + l.qty; });
    for (const l of lines) {
      if (metaRows[l.productId] && metaRows[l.productId].archived === true) {
        return fail(res, 422, "unavailable", l.name.toUpperCase() + " IS NO LONGER CARRIED — REMOVE IT FROM YOUR BAG.");
      }
      if (isFullyHidden(vis[l.productId])) {
        return fail(res, 422, "unavailable", l.name.toUpperCase() + " IS NO LONGER AVAILABLE — REMOVE IT FROM YOUR BAG.");
      }
      if (l.batch > 0) {
        const remaining = Math.max(0, l.batch - (soldMap[l.productId] || 0));
        if (perProduct[l.productId] > remaining) {
          return fail(res, 422, "out_of_stock", remaining > 0
            ? "ONLY " + remaining + " OF " + l.name.toUpperCase() + " LEFT — ADJUST THE QUANTITY IN YOUR BAG."
            : l.name.toUpperCase() + " IS SOLD OUT — NOTHING LEFT THIS BATCH.");
        }
      }
    }
  } catch { /* stock context is best-effort — the authoritative price and product checks above still ran */ }

  const c = body.customer ?? {};
  const name = String(c.name ?? "").trim().slice(0, 120);
  const rawPhone = String(c.phone ?? "").trim().slice(0, 40);
  const addressLine = String(c.addressLine ?? "").trim().slice(0, 240);
  const city = String(c.city ?? "").trim().slice(0, 80);
  const province = String(c.province ?? "").trim().slice(0, 80);
  const barangay = String(c.barangay ?? "").trim().slice(0, 120);
  const postalCode = String(c.postalCode ?? "").trim().slice(0, 12);
  const notes = String(c.notes ?? "").trim().slice(0, 400);
  if (!name || !rawPhone || !addressLine || !city || !province) {
    return fail(res, 422, "invalid", "COMPLETE THE DELIVERY DETAILS BEFORE PLACING THE ORDER.");
  }

  /* shipping is the server's call, priced from the delivery address —
     the client's number is an estimate, this one is the order */
  const ship = computeShipping(city, province);
  const shippingCentavos = ship.fee;

  let voucherReservation = null;
  let voucherDatabase = null;
  let orderSaved = false;
  try {
    const { connect } = require("./ipc-pay/mongo");
    const d = await connect();
    voucherDatabase = d;

    /* tier-gated drops: a collection in its announced window only sells
       to the tiers the club granted early access. Guests count as ROOKIE. */
    const gateSlugs = [...new Set(lines.map((l) => l.collection).filter(Boolean))];
    if (gateSlugs.length) {
      const gatedCols = await d.collection("collections")
        .find({ slug: { $in: gateSlugs }, launchState: "announced" }).toArray();
      if (gatedCols.length) {
        let buyerTier = "ROOKIE";
        if (found) {
          const paid = await paidSummary(d, found.user.email);
          buyerTier = tierForPaid(paid.spentCentavos);
        }
        for (const col of gatedCols) {
          const need = TIER_RANK[col.tierGate] || 0;
          if (TIER_RANK[buyerTier] < need) {
            const title = col.title || col.slug.toUpperCase();
            const opensAt = col.launchAt
              ? new Date(col.launchAt).toLocaleString("en-PH", { timeZone: "Asia/Manila" })
              : "the public drop";
            return fail(res, 403, "tier_gate",
              title + " IS IN ITS EARLY-ACCESS WINDOW — " + col.tierGate + " MEMBERS AND ABOVE GET FIRST DIBS. IT OPENS TO EVERYONE AT " + opensAt + ".");
          }
        }
      }
    }

    const guestToken = guestMode ? crypto.randomBytes(24).toString("hex") : null;
    const guestEmail = guestMode
      ? String((c.email ?? "")).trim().toLowerCase().slice(0, 120)
      : found.user.email;
    if (guestMode && !guestEmail) {
      return fail(res, 422, "invalid", "DROP YOUR EMAIL SO THE CLUB CAN SEND YOUR RECEIPT.");
    }
    const cooldownSeconds = found ? await paymentCooldownSeconds(d, found.user._id) : 0;
    if (cooldownSeconds > 0) return rejectPaymentDuringCooldown(res, cooldownSeconds);
    const phone = found ? await linkAccountPhone(d, found.user, rawPhone) : normalizePhilippineMobile(rawPhone);
    const reference = await nextReference("order");
    const paymentReference = await nextReference("payment");
    const now = new Date();
    const voucherCodeInput = String(body.voucherCode || "").trim();
    let voucherResult = null;
    if (voucherCodeInput && !found) {
      return fail(res, 422, "voucher_needs_account", "VOUCHERS WORK WITH A CLUB ACCOUNT — LOG IN OR CREATE ONE AND YOUR BAG COMES WITH YOU.");
    }
    if (voucherCodeInput) {
      voucherResult = await resolveVoucher(d, voucherCodeInput, found.user, phone, subtotalCentavos);
      const v = voucherResult.voucher;
      const claimFilter = v.maxUses > 0
        ? { _id: v._id, active: true, uses: { $lt: v.maxUses } }
        : { _id: v._id, active: true };
      const claimed = await d.collection("vouchers").updateOne(claimFilter, { $inc: { uses: 1 } });
      if (claimed.modifiedCount !== 1) return fail(res, 409, "voucher_limit", "THAT VOUCHER HAS JUST REACHED ITS USE LIMIT.");
      try {
        await d.collection("voucherRedemptions").insertOne({
          code: voucherResult.code,
          userId: found.user._id,
          phone,
          orderReference: reference,
          createdAt: now,
        });
        voucherReservation = { voucherId: v._id, orderReference: reference };
      } catch (claimErr) {
        await d.collection("vouchers").updateOne({ _id: v._id }, { $inc: { uses: -1 } });
        if (claimErr && claimErr.code === 11000) {
          return fail(res, 409, "voucher_used", "THIS VOUCHER HAS ALREADY BEEN USED WITH YOUR ACCOUNT OR MOBILE NUMBER.");
        }
        throw claimErr;
      }
    }
    const discountCentavos = voucherResult ? voucherResult.discountCentavos : 0;
    const totalCentavos = subtotalCentavos + shippingCentavos - discountCentavos;
    if (totalCentavos < 100) return fail(res, 422, "voucher_too_large", "THE VOUCHER MUST LEAVE AT LEAST ₱1.00 TO PAY.");

    const orderDoc = {
      reference,
      userId: found ? found.user._id : null,
      email: guestEmail,
      guest: guestMode,
      ...(guestToken ? { guestToken } : {}),
      customerName: name,
      phone,
      phoneNormalized: phone,
      addressLine,
      barangay,
      city,
      province,
      postalCode,
      notes,
      items: lines.map((l) => ({
        productId: l.productId, name: l.name, size: l.size, color: l.color,
        qty: l.qty, priceCentavos: l.priceCentavos, collection: l.collection,
      })),
      subtotalCentavos,
      discountCentavos,
      voucherCode: voucherResult ? voucherResult.code : null,
      shippingCentavos,
      shippingZone: ship.zone,
      totalCentavos,
      status: "awaiting_payment",
      createdAt: now,
      updatedAt: now,
    };
    await d.collection("orders").insertOne(orderDoc);
    orderSaved = true;

    const paymentDoc = {
      paymentReference,
      orderReference: reference,
      userId: found ? found.user._id : null,
      email: guestEmail,
      ...(guestToken ? { guestToken } : {}),
      amountCentavos: totalCentavos,
      currency: "PHP",
      status: "pending",      method: "qr",
      refNo: null,
      proofDataUrl: null,
      createdAt: now,
      updatedAt: now,
      verifiedAt: null,
      reviewedBy: null,
    };
    await d.collection("payments").insertOne(paymentDoc);

    return send(res, 200, {
      ok: true,
      reference,
      paymentReference,
      amountCentavos: totalCentavos,
      subtotalCentavos,
      discountCentavos,
      voucherCode: voucherResult ? voucherResult.code : null,
      shippingCentavos,
      shippingZone: ship.zone,
      guest: guestMode,
      ...(guestToken ? { guestToken } : {}),
    });
  } catch (err) {
    if (voucherReservation && voucherDatabase && !orderSaved) {
      await voucherDatabase.collection("voucherRedemptions").deleteOne({
        orderReference: voucherReservation.orderReference,
      }).catch(() => {});
      await voucherDatabase.collection("vouchers").updateOne(
        { _id: voucherReservation.voucherId }, { $inc: { uses: -1 } }
      ).catch(() => {});
    }
    if (err && err.code === 11000) {
      return fail(res, 409, "account_or_voucher_conflict",
        "THIS MOBILE NUMBER OR VOUCHER HAS ALREADY BEEN USED. REFRESH AND TRY AGAIN.");
    }
    if (err && /mobile number|voucher|first ipc order|first order/i.test(err.message || "")) {
      return fail(res, 422, "voucher_or_phone_invalid", err.message);
    }
    return mongoError(res, err, "order creation failed");
  }
}

/* --------------------------------------------------------------- */
/* PAYMENT PROOF — moves the payment to UNDER VERIFICATION, and     */
/* NEVER further. Only an admin decision can mark it paid/failed.   */
/* --------------------------------------------------------------- */

async function handleProof(req, res) {
  const body = await readBody(req, res, 8 * 1024 * 1024);
  if (body === null) return; // oversize → socket destroyed
  if (body === undefined) return fail(res, 400, "bad_request", "MALFORMED UPLOAD — SEND THE FORM AGAIN.");

  const found = await userFromReq(req).catch(() => null);
  /* guests submit proof with their one-off receipt token */
  const guestToken = String(body.guestToken ?? "").trim();
  const guestOk = /^[a-f0-9]{32,128}$/.test(guestToken);
  if (!found && !guestOk) return fail(res, 401, "unauthorized", "LOG IN TO CONTINUE.");

  const reference = String(body.reference ?? "").trim().toUpperCase();
  const refNo = String(body.refNo ?? "").trim().slice(0, 40);
  const proofDataUrl = String(body.proofDataUrl ?? "");
  if (!reference) return fail(res, 422, "invalid", "MISSING PAYMENT REFERENCE.");
  if (!/^[A-Za-z0-9][A-Za-z0-9\-_]{3,39}$/.test(refNo)) {
    return fail(res, 422, "invalid",
      "ENTER THE REFERENCE NUMBER FROM YOUR E-WALLET RECEIPT (AT LEAST 4 CHARACTERS).");
  }

  /* optional proof image — validate hard when present */
  let proofMime = null;
  let decoded = null;
  if (proofDataUrl) {
    const m = proofDataUrl.match(/^data:(image\/(?:jpeg|jpg|png));base64,([A-Za-z0-9+/=\s]+)$/);
    if (!m) return fail(res, 422, "invalid", "PROOF MUST BE A JPG, JPEG OR PNG IMAGE.");
    proofMime = m[1];
    try {
      decoded = Buffer.from(m[2], "base64");
    } catch {
      return fail(res, 422, "invalid", "PROOF IMAGE COULDN'T BE READ.");
    }
    if (decoded.length > PROOF_MAX_BYTES) {
      return fail(res, 422, "invalid", "PROOF IS TOO LARGE — 5MB MAXIMUM.");
    }
    if (decoded.length < 1024) {
      return fail(res, 422, "invalid", "THAT FILE LOOKS EMPTY — UPLOAD THE REAL SCREENSHOT.");
    }
  }

  try {
    const { connect } = require("./ipc-pay/mongo");
    const d = await connect();
    const cooldownSeconds = found ? await paymentCooldownSeconds(d, found.user._id) : 0;
    if (cooldownSeconds > 0) return rejectPaymentDuringCooldown(res, cooldownSeconds);
    const pay = await d.collection("payments").findOne({ paymentReference: reference });
    if (!pay) return fail(res, 404, "not_found", "NO PAYMENT FOUND FOR THAT REFERENCE.");
    if (found) {
      if (String(pay.userId) !== String(found.user._id)) {
        return fail(res, 403, "forbidden", "THIS PAYMENT BELONGS TO ANOTHER ACCOUNT.");
      }
    } else {
      const guestOrder = await d.collection("orders").findOne({ reference: pay.orderReference });
      if (!guestOrder || guestOrder.guestToken !== guestToken) {
        return fail(res, 403, "forbidden", "THIS PAYMENT BELONGS TO ANOTHER ACCOUNT.");
      }
    }
    if (pay.status === "paid") {
      return fail(res, 422, "already_paid", "THIS PAYMENT IS ALREADY VERIFIED AND PAID.");
    }

    /* A Maya transaction reference can only ever pay for ONE order — but
       only claims that are still in play or already accepted lock the ref.
       A REJECTED claim (status failed) never bought anything, so the same
       reference — full number or last-4 — can be resubmitted on a new or
       corrected order without a false "already used" wall. Refs attached
       to PAID orders stay burned forever. */
    const duplicateRef = await d.collection("payments").findOne({
      refNo,
      _id: { $ne: pay._id },
      status: { $in: ["under_verification", "paid"] },
    });
    if (duplicateRef) {
      return fail(res, 409, "duplicate_reference",
        duplicateRef.status === "paid"
          ? "THAT MAYA TRANSACTION REFERENCE ALREADY PAID FOR ANOTHER ORDER — ONE PAYMENT COVERS ONE ORDER ONLY."
          : "THAT MAYA TRANSACTION REFERENCE IS CURRENTLY ATTACHED TO ANOTHER ORDER WAITING FOR VERIFICATION.");
    }

    const now = new Date();
    /* proof submissions are capped per payment — a failing order cannot
       accumulate unlimited screenshots (each carries a fresh OCR pass) */
    if ((pay.proofSubmissions || 0) >= 6) {
      return fail(res, 429, "proof_cap",
        "THIS ORDER HAS HIT ITS PROOF LIMIT — CONTACT THE CLUB AND WE'LL SORT IT OUT.");
    }
    const proofHash = decoded
      ? require("node:crypto").createHash("sha256").update(decoded).digest("hex")
      : null;
    const proofUpdate = await d.collection("payments").updateOne(
      { _id: pay._id, status: { $nin: ["paid", "failed"] } },
      {
        $set: {
          refNo,
          status: "under_verification",
          updatedAt: now,
          proofSubmittedAt: now,
          ...(decoded ? { proofDataUrl: `data:${proofMime};base64,${decoded.toString("base64")}`, proofHash, proofMeta: { mime: proofMime, bytes: decoded.length } } : {}),
        },
        /* a fresh screenshot wipes the previous machine read — the admin
           card must never show a verdict for a proof that is gone */
        $unset: { autoRead: "" },
        $inc: { proofSubmissions: 1 },
      }
    );
    if (proofUpdate.modifiedCount !== 1) {
      return fail(res, 409, "payment_locked",
        "THIS PAYMENT HAS ALREADY BEEN DECIDED. CONTACT THE CLUB IF YOU NEED HELP.");
    }
    await d.collection("orders").updateOne(
      { reference: pay.orderReference },
      { $set: { status: "under_verification", updatedAt: now } }
    );

    /* IPC PAY VERDICT ENGINE — runs in the background (OCR takes seconds):
       the response stays instant and the payment page's live poll picks up
       the verdict. The machine approves matching receipts and rejects
       edited, AI-made, reused or mismatched ones on its own. Reference-only
       claims (no screenshot to read) still go to a club admin. */
    if (decoded) {
      const proofDataUrl = "data:" + proofMime + ";base64," + decoded.toString("base64");
      setImmediate(() => {
        autoVerifyPayment(d, { ...pay, proofDataUrl })
          .catch((e) => console.error("[ipc-pay] auto reader crashed (kept for manual review):", e && e.message));
      });
    }

    const orderForEmail = await d.collection("orders").findOne({ reference: pay.orderReference });
    await sendPaymentEmail(pay, orderForEmail, "UNDER VERIFICATION",
      "We received your Maya transaction reference. IPC Pay reads your screenshot and gives its own verdict — matching receipts confirm automatically, edited or AI-made ones are rejected with the reason. Only reads the machine can't process go to the club.");
    return send(res, 200, {
      ok: true,
      status: "under_verification",
      message: "PROOF RECEIVED — IPC PAY IS READING IT NOW. THE VERDICT LANDS ON THIS PAGE AUTOMATICALLY.",
    });
  } catch (err) {
    return mongoError(res, err, "proof upload failed");
  }
}

/* --------------------------------------------------------------- */
/* ADMIN DECISION — the ONLY path that can mark a payment paid.     */
/* --------------------------------------------------------------- */

/* The machine's reading, in one short note, appended to the activity
   log whenever a human decides — so the record shows what IPC Pay saw
   before the call was made. */
function readNote(pay) {
  const a = pay && pay.autoRead;
  if (!a) return "";
  const top = Array.isArray(a.signals) && a.signals.length
    ? a.signals.find((s) => forensics.SEVERITY[s.severity] >= forensics.SEVERITY.medium)
    : null;
  return " — IPC PAY READ: " + (a.verdict || (a.pass ? "CLEAN" : "NEEDS_REVIEW")) +
    (top ? " (" + top.code.toUpperCase() + ")" : "") +
    (a.verdict === "AUTO_REJECTED" && a.reason ? " — " + String(a.reason).slice(0, 140) : "");
}

async function handleDecision(req, res) {
  const found = await userFromReq(req).catch(() => null);
  if (!found) return fail(res, 401, "unauthorized", "LOG IN TO CONTINUE.");
  if (found.user.role !== "admin") {
    return fail(res, 403, "forbidden", "ADMIN ONLY — THIS AREA IS FOR THE CLUB ADMINS.");
  }
  const body = await readBody(req, res, 20000);
  if (body === null) return;
  if (body === undefined) return fail(res, 400, "bad_request", "MALFORMED REQUEST BODY.");

  const paymentId = String(body.paymentId ?? "").trim().toUpperCase();
  const action = String(body.action ?? "").trim().toLowerCase();
  if (!paymentId) return fail(res, 422, "invalid", "MISSING PAYMENT ID.");
  if (action !== "approve" && action !== "reject") {
    return fail(res, 422, "invalid", "ACTION MUST BE approve OR reject.");
  }

  try {
    const { connect } = require("./ipc-pay/mongo");
    const d = await connect();
    const pay = await d.collection("payments").findOne({ paymentReference: paymentId });
    if (!pay) return fail(res, 404, "not_found", "PAYMENT NOT FOUND.");
    if (pay.status === "paid" || pay.status === "failed") {
      return fail(res, 422, "already_decided",
        `THIS PAYMENT IS ALREADY ${pay.status.toUpperCase()} — NO FURTHER CHANGES.`);
    }
    if (action === "approve" &&
        (pay.status !== "under_verification" || !pay.refNo)) {
      return fail(res, 422, "proof_required",
        "A MAYA TRANSACTION REFERENCE MUST BE SUBMITTED BEFORE A PAYMENT CAN BE APPROVED.");
    }

    const now = new Date();
    const newStatus = action === "approve" ? "paid" : "failed";
    /* Compare-and-set prevents two admins from approving/rejecting the same
       payment concurrently and sending conflicting customer confirmations. */    const decision = await d.collection("payments").updateOne(
      { _id: pay._id, status: { $in: ["pending", "under_verification"] } },
      { $set: {
        status: newStatus,        updatedAt: now,
        verifiedAt: now,
        reviewedBy: found.user.email,
        decisionSource: "admin_manual_maya_check",
      } }
    );
    if (decision.modifiedCount !== 1) {
      return fail(res, 409, "decision_conflict",
        "ANOTHER ADMIN HAS ALREADY UPDATED THIS PAYMENT. REFRESH THE PAYMENT QUEUE.");
    }
    await d.collection("orders").updateOne(
      { reference: pay.orderReference },
      { $set: { status: newStatus, updatedAt: now } }
    );
    await logActivity(d, found.user.email, "order_status", "order", pay.orderReference,
      "ORDER " + pay.orderReference,
      action === "approve" ? "PAYMENT " + paymentId + " VERIFIED — ORDER MARKED PAID (₱" + ((pay.amountCentavos || 0) / 100).toFixed(2) + ")" + readNote(pay)
        : "PAYMENT " + paymentId + " REJECTED — ORDER MARKED " + newStatus.toUpperCase() + readNote(pay));
    if (action === "approve") {
      await ensureTracking(d, pay.orderReference, "IPC TEAM");
      await creditReferralIfAny(d, pay.orderReference);
    }

    if (action === "reject") {
      await registerRejection(d, pay.userId, now);
    } else {
      await d.collection("users").updateOne(
        { _id: pay.userId },
        { $set: { paymentRejections: [] }, $unset: { paymentCooldownUntil: "" } }
      );
    }

    const orderForEmail = await d.collection("orders").findOne({ reference: pay.orderReference });
    await sendPaymentEmail({ ...pay, status: newStatus }, orderForEmail,
      newStatus.toUpperCase(), action === "approve"
        ? "Your Maya payment was checked and verified by the club. Your order is now confirmed."
        : "Your payment could not be verified by the club. Please check your Maya transaction details and contact the club before trying again.");
    return send(res, 200, {
      ok: true,
      status: newStatus,
      verifiedAt: now,
      message: action === "approve"
        ? "PAYMENT MARKED PAID — ORDER UNLOCKED."
        : "PAYMENT REJECTED — CUSTOMER MUST RESUBMIT.",
    });
  } catch (err) {
    return mongoError(res, err, "decision failed");
  }
}

/* --------------------------------------------------------------- */

/* --------------------------------------------------------------- */
/* ADMIN SETTINGS — the IPC PAY AUTO READER switch                   */
/* --------------------------------------------------------------- */

async function handleAdminSettings(req, res) {
  const found = await userFromReq(req).catch(() => null);
  if (!found) return fail(res, 401, "unauthorized", "LOG IN TO CONTINUE.");
  if (found.user.role !== "admin") return fail(res, 403, "forbidden", "ADMIN ONLY.");
  const body = await readBody(req, res, 20000);
  if (body === null) return;
  if (body === undefined) return fail(res, 400, "bad_request", "MALFORMED REQUEST BODY.");
  try {
    if (typeof body.autoVerify !== "boolean") {
      return fail(res, 422, "invalid", "autoVerify MUST BE TRUE OR FALSE.");
    }
    const { connect } = require("./ipc-pay/mongo");
    const d = await connect();
    await d.collection("settings").updateOne(
      { _id: "ipcpay" },
      { $set: { autoVerify: body.autoVerify, updatedAt: new Date(), updatedBy: found.user.email } },
      { upsert: true }
    );
    console.log("[ipc-pay] auto reader switched " + (body.autoVerify ? "ON" : "OFF") + " by " + found.user.email);
    return send(res, 200, {
      ok: true,
      autoVerify: body.autoVerify,
      message: body.autoVerify
        ? "AUTO READER ON — THE MACHINE DECIDES EVERY SCREENSHOT PROOF: MATCHING RECEIPTS APPROVE THEMSELVES, EDITED/AI-MADE/MISMATCHED ONES ARE REJECTED WITH THE REASON. ONLY BROKEN READS GO TO THE QUEUE."
        : "AUTO READER OFF — EVERY SCREENSHOT NEEDS A MANUAL ADMIN DECISION.",
    });
  } catch (err) {
    return mongoError(res, err, "settings update failed");
  }
}

/* --------------------------------------------------------------- */
/* ADMIN TRACKING — move a paid order through fulfillment.           */
/* Legacy paid orders get their tracking opened on first touch.      */
/* --------------------------------------------------------------- */

async function handleAdminTracking(req, res) {
  const found = await userFromReq(req).catch(() => null);
  if (!found) return fail(res, 401, "unauthorized", "LOG IN TO CONTINUE.");
  if (found.user.role !== "admin") return fail(res, 403, "forbidden", "ADMIN ONLY.");
  const body = await readBody(req, res, 20000);
  if (body === null) return;
  if (body === undefined) return fail(res, 400, "bad_request", "MALFORMED REQUEST BODY.");
  const reference = String(body.reference ?? "").trim().toUpperCase();
  const status = String(body.status ?? "").trim().toLowerCase();
  if (!reference) return fail(res, 422, "invalid", "MISSING ORDER REFERENCE.");
  const allowed = TRACKING_STAGES.concat(["cancelled"]);
  if (!allowed.includes(status)) {
    return fail(res, 422, "invalid", "STATUS MUST BE PROCESSING, PACKED, SHIPPED, DELIVERED OR CANCELLED.");
  }
  try {
    const { connect } = require("./ipc-pay/mongo");
    const d = await connect();
    let order = await d.collection("orders").findOne({ reference });
    if (!order) return fail(res, 404, "not_found", "ORDER NOT FOUND.");
    if (order.status !== "paid") {
      return fail(res, 422, "not_paid", "TRACKING OPENS ONLY AFTER THE PAYMENT IS ACCEPTED.");
    }
    if (!order.tracking) await ensureTracking(d, reference, "IPC TEAM");
    order = await d.collection("orders").findOne({ reference });
    if (order.tracking.status === "delivered") {
      return fail(res, 422, "already_delivered", "THIS ORDER IS ALREADY DELIVERED — THE JOURNEY IS CLOSED.");
    }
    const now = new Date();
    const entry = {
      status,
      note: String(body.note ?? "").trim().slice(0, 200),
      at: now,
      by: "IPC TEAM",
    };
    const update = await d.collection("orders").updateOne(
      { reference, "tracking.status": { $ne: "delivered" } },
      { $set: {
        "tracking.status": status,
        "tracking.updatedAt": now,
        ...(body.courier !== undefined ? { "tracking.courier": String(body.courier).trim().slice(0, 80) } : {}),
        ...(body.trackingUrl !== undefined ? { "tracking.trackingUrl": String(body.trackingUrl).trim().slice(0, 200) } : {}),
      }, $push: { "tracking.history": entry } }
    );
    if (update.modifiedCount !== 1) {
      return fail(res, 409, "tracking_conflict", "TRACKING JUST CHANGED — REFRESH AND TRY AGAIN.");
    }
    const fresh = await d.collection("orders").findOne({ reference });
    console.log("[ipc-pay] tracking " + reference + " (" + fresh.tracking.number + ") → " + status + " by " + found.user.email);
    await logActivity(d, found.user.email, "order_tracking", "order", reference,
      "ORDER " + reference,
      "TRACKING → " + status.toUpperCase() + (body.note ? " — " + String(body.note).slice(0, 120) : ""));
    return send(res, 200, {
      ok: true,
      tracking: fresh.tracking,
      message: "TRACKING UPDATED — " + (status === "cancelled" ? "CANCELLED" : status.toUpperCase()) + ".",
    });
  } catch (err) {
    return mongoError(res, err, "tracking update failed");
  }
}

/* --------------------------------------------------------------- */
/* CLUB INVENTORY — ADD A PIECE. The team types the piece in, drops   */
/* a photo, picks the collection, and it shows up on the shop and    */
/* its collection page on its own. Baked-in pieces stay the core;    */
/* everything saved here lives in the products collection.            */
/* --------------------------------------------------------------- */

async function handleAdminProductSave(req, res) {
  const found = await userFromReq(req).catch(() => null);
  if (!found) return fail(res, 401, "unauthorized", "LOG IN TO CONTINUE.");
  if (found.user.role !== "admin") return fail(res, 403, "forbidden", "ADMIN ONLY.");
  /* the photo rides in the body — 4MB covers a compressed product shot */
  const body = await readBody(req, res, 4 * 1024 * 1024);
  if (body === null) return;
  if (body === undefined) return fail(res, 400, "bad_request", "MALFORMED REQUEST BODY.");

  const name = String(body.name ?? "").trim().replace(/\s+/g, " ").slice(0, 60);
  const priceC = Math.round(Number(body.priceC));
  const tag = String(body.tag ?? "").trim().toUpperCase().slice(0, 24);
  const collection = normalizeProductCollection(body.collection);
  const sizes = (Array.isArray(body.sizes) ? body.sizes : [])
    .map((s) => String(s ?? "").trim().toUpperCase().slice(0, 12)).filter(Boolean).slice(0, 12);
  const colors = (Array.isArray(body.colors) ? body.colors : [])
    .map((s) => String(s ?? "").trim().toUpperCase().slice(0, 24)).filter(Boolean).slice(0, 12);
  const desc = String(body.desc ?? "").trim().slice(0, 1200);
  const fabric = String(body.fabric ?? "").trim().slice(0, 200);
  const fit = String(body.fit ?? "").trim().slice(0, 200);
  const alt = String(body.alt ?? "").trim().slice(0, 200);
  /* honest scarcity + fit confidence: optional batch size and model line */
  const batchSize = Math.max(0, Math.round(Number(body.batchSize) || 0));
  const modelInfo = String(body.modelInfo ?? "").trim().slice(0, 160);
  const home = !!body.home;
  const img = String(body.img ?? "").trim();

  if (name.length < 2) return fail(res, 422, "invalid", "GIVE THE PIECE A NAME — AT LEAST 2 CHARACTERS.");
  if (!Number.isFinite(priceC) || priceC < 100 || priceC > 10000000) {
    return fail(res, 422, "invalid", "THE PRICE MUST SIT BETWEEN \u20B11 AND \u20B1100,000.");
  }
  if (TAG_WHITELIST.indexOf(tag) < 0) tag = "";
  if (!collection) return fail(res, 422, "invalid", "PICK OR NAME A COLLECTION — THE SHOP ORGANIZES BY IT.");
  if (!sizes.length) return fail(res, 422, "invalid", "LIST AT LEAST ONE SIZE — 'OS' COUNTS FOR ONE-SIZE PIECES.");
  if (!colors.length) return fail(res, 422, "invalid", "LIST AT LEAST ONE COLORWAY.");
  if (!img) return fail(res, 422, "invalid", "THE PIECE NEEDS A PHOTO — DROP ONE IN OR PASTE AN IMAGE LINK.");
  const isDataImg = /^data:image\/(?:jpeg|jpg|png);base64,[A-Za-z0-9+/=\s]+$/.test(img);
  const isUrlImg = /^https:\/\/\S{1,480}$/i.test(img);
  if (!isDataImg && !isUrlImg) {
    return fail(res, 422, "invalid", "THE PHOTO MUST BE A JPG/PNG UPLOAD OR AN HTTPS IMAGE LINK.");
  }
  if (isDataImg && img.length > PRODUCT_IMG_MAX_CHARS) {
    return fail(res, 413, "too_large", "THAT PHOTO IS TOO HEAVY — A SMALLER ONE UPLOADS CLEAN.");
  }

  try {
    const { connect } = require("./ipc-pay/mongo");
    const d = await connect();
    const now = new Date();

    /* a brand-new collection gets registered the moment the piece lands */
    const isNewCol = body.newCollection && typeof body.newCollection === "object";
    if (isNewCol) {
      const title = String(body.newCollection.title ?? "").trim().replace(/\s+/g, " ").slice(0, 60) || collection.toUpperCase();
      const blurb = String(body.newCollection.blurb ?? "").trim().slice(0, 240);
      await d.collection("collections").updateOne(
        { slug: collection },
        { $set: { slug: collection, title, blurb, soon: false, updatedAt: now }, $setOnInsert: { createdAt: now } },
        { upsert: true }
      );
    } else {
      const known = IPC_COLLECTION_SLUGS.includes(collection) ||
        (await d.collection("collections").findOne({ slug: collection }));
      if (!known) {
        return fail(res, 422, "invalid", "THAT COLLECTION DOESN'T EXIST YET — ADD IT AS A NEW COLLECTION.");
      }
    }

    let doc;
    const editingId = String(body.id ?? "").trim();
    /* editing a baked-in piece never rewrites its code — the change lands
       in productMeta and rides on top of the baked catalog everywhere
       (shop, product page, share cards, checkout pricing) */
    if (editingId && PRODUCTS.some((x) => x.id === editingId)) {
      const meta = await productMetaMap(d);
      const m = meta[editingId] || {};
      const metaDoc = {
        id: editingId,
        name, priceCentavos: priceC, tag, sizes, colors, desc, fabric, fit,
        alt, batchSize, modelInfo, img, home,
        /* the edit form's featured checkbox is the same switch the
           inventory table's FEATURED chip writes — one state, one place */
        featured: home,
        updatedAt: now, updatedBy: found.user.email,
      };
      await d.collection("productMeta").updateOne(
        { id: editingId },
        { $set: metaDoc, $setOnInsert: { createdAt: now } },
        { upsert: true }
      );
      bakedMetaCache = { at: 0, map: null }; /* share cards re-read meta */
      const merged = applyBakedMeta(PRODUCTS.find((x) => x.id === editingId), metaDoc);
      console.log("[ipc-pay] baked product edited " + editingId + " (" + name + ") by " + found.user.email);
      const editDeltas = [];
      const oldPrice = m.priceCentavos !== undefined ? m.priceCentavos : PRODUCTS.find((x) => x.id === editingId).priceCentavos;
      if (oldPrice !== priceC) editDeltas.push("PRICE " + oldPrice + "→" + priceC + " CENTAVOS");
      if ((m.batchSize || 0) !== batchSize) editDeltas.push("BATCH " + (m.batchSize || 0) + "→" + batchSize);
      if (m.archived === true) editDeltas.push("ARCHIVE LIFTED BY EDIT");
      await logActivity(d, found.user.email, "product_edit", "product", editingId, name.toUpperCase(),
        editDeltas.length ? editDeltas.join(" · ") : "DETAILS UPDATED");
      return send(res, 200, { ok: true, product: merged, message: "PIECE UPDATED — THE SHOP CARRIES IT NOW." });
    }
    if (editingId) {
      const existing = await d.collection("products").findOne({ id: editingId });
      if (!existing) return fail(res, 404, "not_found", "THAT PIECE ISN'T IN THE SAVED CATALOG.");
      const update = await d.collection("products").updateOne(
        { id: editingId },
        { $set: {
          name, priceCentavos: priceC, tag, collection,
          sizes, colors, desc, fabric, fit, alt, home, img,
          batchSize, modelInfo,
          active: body.active === undefined ? existing.active !== false : !!body.active,
          updatedAt: now,
        } }
      );
      if (update.modifiedCount !== 1 && update.matchedCount !== 1) {
        return fail(res, 500, "save_failed", "THE PIECE DIDN'T SAVE — TRY AGAIN.");
      }
      doc = await d.collection("products").findOne({ id: editingId });
      console.log("[ipc-pay] product updated " + editingId + " (" + name + ") by " + found.user.email);
      const editDeltas = [];
      if (existing.priceCentavos !== priceC) editDeltas.push("PRICE " + existing.priceCentavos + "→" + priceC + " CENTAVOS");
      if ((existing.batchSize || 0) !== batchSize) editDeltas.push("BATCH " + (existing.batchSize || 0) + "→" + batchSize);
      if (existing.active !== false && body.active === false) editDeltas.push("ACTIVE → OFF");
      if (existing.active === false && body.active !== false) editDeltas.push("ACTIVE → ON");
      await logActivity(d, found.user.email, "product_edit", "product", editingId, name.toUpperCase(),
        editDeltas.length ? editDeltas.join(" · ") : "DETAILS UPDATED");
      return send(res, 200, { ok: true, product: productView(doc), message: "PIECE UPDATED — THE SHOP CARRIES IT NOW." });
    }

    let id = "ipc-" + collection.slice(0, 16) + "-" + Date.now().toString(36) + Math.random().toString(36).slice(2, 5);
    while (await d.collection("products").findOne({ id })) {
      id = "ipc-" + collection.slice(0, 16) + "-" + Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
    }
    doc = {
      id, name, priceCentavos: priceC, tag, collection,
      sizes, colors, desc, fabric, fit, alt, home, img,
      batchSize, modelInfo,
      active: true,
      createdBy: found.user.email,
      createdAt: now, updatedAt: now,
    };
    await d.collection("products").insertOne(doc);
    console.log("[ipc-pay] product added " + id + " (" + name + ") by " + found.user.email);
    await logActivity(d, found.user.email, "product_create", "product", id, name.toUpperCase(),
      "₱" + (priceC / 100).toFixed(2) + " · COLLECTION " + collection.toUpperCase() + (batchSize ? " · BATCH " + batchSize : ""));
    return send(res, 200, { ok: true, product: productView(doc), message: "PIECE ADDED — IT'S LIVE ON THE SHOP AND ITS COLLECTION." });
  } catch (err) {
    return mongoError(res, err, "product save failed");
  }
}

async function handleAdminProductRemove(req, res) {
  const found = await userFromReq(req).catch(() => null);
  if (!found) return fail(res, 401, "unauthorized", "LOG IN TO CONTINUE.");
  if (found.user.role !== "admin") return fail(res, 403, "forbidden", "ADMIN ONLY.");
  const body = await readBody(req, res, 20000);
  if (body === null) return;
  if (body === undefined) return fail(res, 400, "bad_request", "MALFORMED REQUEST BODY.");
  const id = String(body.id ?? "").trim();
  if (!id) return fail(res, 422, "invalid", "MISSING PIECE ID.");
  try {
    const { connect } = require("./ipc-pay/mongo");
    const d = await connect();
    /* soft pull — order history keeps pointing at the piece, the shop just stops carrying it */
    const update = await d.collection("products").updateOne(
      { id },
      { $set: { active: false, updatedAt: new Date() } }
    );
    if (update.matchedCount !== 1) return fail(res, 404, "not_found", "THAT PIECE ISN'T IN THE SAVED CATALOG.");
    console.log("[ipc-pay] product pulled " + id + " by " + found.user.email);
    await logActivity(d, found.user.email, "product_remove", "product", id,
      id.toUpperCase(), "PIECE PULLED FROM THE SHOP — RECORD AND ORDER HISTORY PRESERVED");
    return send(res, 200, { ok: true, message: "PIECE PULLED FROM THE SHOP — PAST ORDERS STAY ON RECORD." });
  } catch (err) {
    return mongoError(res, err, "product remove failed");
  }
}

/* DELETE FOR GOOD — club-added pieces leave the products collection
   entirely (orders keep their line-item snapshots, so history never
   breaks); baked-in pieces can't be un-baked, so "delete" archives them:
   off every public surface AND out of the main inventory table, one
   restore away. Both paths land in the activity log. ---------------- */
async function handleAdminProductDelete(req, res) {
  const found = await userFromReq(req).catch(() => null);
  if (!found) return fail(res, 401, "unauthorized", "LOG IN TO CONTINUE.");
  if (found.user.role !== "admin") return fail(res, 403, "forbidden", "ADMIN ONLY.");
  const body = await readBody(req, res, 20000);
  if (body === null) return;
  if (body === undefined) return fail(res, 400, "bad_request", "MALFORMED REQUEST BODY.");
  const id = String(body.id ?? "").trim();
  if (!id) return fail(res, 422, "invalid", "MISSING PIECE ID.");
  try {
    const { connect } = require("./ipc-pay/mongo");
    const d = await connect();
    const baked = PRODUCTS.some((x) => x.id === id);
    if (baked) {
      await d.collection("productMeta").updateOne(
        { id },
        { $set: { id, archived: true, featured: false, updatedAt: new Date(), updatedBy: found.user.email }, $setOnInsert: { createdAt: new Date() } },
        { upsert: true }
      );
      bakedMetaCache = { at: 0, map: null };
      await logActivity(d, found.user.email, "product_archive", "product", id, id.toUpperCase(),
        "CORE PIECE ARCHIVED — OFF EVERY SURFACE AND OUT OF THE MAIN INVENTORY LIST; RECORD + ORDER HISTORY KEPT");
      return send(res, 200, { ok: true, archived: true, message: "PIECE ARCHIVED — GONE FROM EVERY SURFACE AND THE INVENTORY LIST. RESTORE BRINGS IT BACK." });
    }
    const custom = await d.collection("products").findOne({ id });
    if (!custom) return fail(res, 404, "not_found", "THAT PIECE ISN'T IN THE SAVED CATALOG.");
    await d.collection("products").deleteOne({ id });
    await d.collection("productVisibility").deleteOne({ id });
    await d.collection("productMeta").deleteOne({ id });
    await logActivity(d, found.user.email, "product_delete", "product", id,
      (custom.name || id).toUpperCase(), "PIECE DELETED PERMANENTLY FROM THE CATALOG — PAST ORDERS KEEP THEIR LINE-ITEM RECORDS");
    return send(res, 200, { ok: true, archived: false, message: "PIECE DELETED FOR GOOD — THE INVENTORY TAB STOPS CARRYING IT. PAST ORDERS KEEP THEIR RECORDS." });
  } catch (err) {
    return mongoError(res, err, "product delete failed");
  }
}

/* FEATURED TOGGLE — the club picks what the home drop showcases. Baked
   pieces store the flip in productMeta; club-added pieces flip their own
   home flag. One switch, same effect either way. --------------------- */
async function handleAdminProductFeatured(req, res) {
  const found = await userFromReq(req).catch(() => null);
  if (!found) return fail(res, 401, "unauthorized", "LOG IN TO CONTINUE.");
  if (found.user.role !== "admin") return fail(res, 403, "forbidden", "ADMIN ONLY.");
  const body = await readBody(req, res, 20000);
  if (body === null) return;
  if (body === undefined) return fail(res, 400, "bad_request", "MALFORMED REQUEST BODY.");
  const id = String(body.id ?? "").trim();
  const featured = !!body.featured;
  if (!id) return fail(res, 422, "invalid", "MISSING PIECE ID.");
  try {
    const { connect } = require("./ipc-pay/mongo");
    const d = await connect();
    const baked = PRODUCTS.some((x) => x.id === id);
    let label = id.toUpperCase();
    if (baked) {
      await d.collection("productMeta").updateOne(
        { id },
        { $set: { id, featured, updatedAt: new Date(), updatedBy: found.user.email }, $setOnInsert: { createdAt: new Date() } },
        { upsert: true }
      );
      bakedMetaCache = { at: 0, map: null };
    } else {
      const custom = await d.collection("products").findOne({ id });
      if (!custom) return fail(res, 404, "not_found", "THAT PIECE ISN'T IN THE SAVED CATALOG.");
      label = (custom.name || id).toUpperCase();
      await d.collection("products").updateOne({ id }, { $set: { home: featured, updatedAt: new Date() } });
    }
    await logActivity(d, found.user.email, "product_featured", "product", id, label,
      featured ? "ADDED TO THE FEATURED ROTATION" : "TAKEN OUT OF THE FEATURED ROTATION");
    return send(res, 200, { ok: true, featured, message: featured
      ? "PIECE JOINED THE FEATURED ROTATION — THE HOME DROP PICKS IT UP."
      : "PIECE LEFT THE FEATURED ROTATION." });
  } catch (err) {
    return mongoError(res, err, "featured toggle failed");
  }
}

/* --------------------------------------------------------------- */
/* EMERGENCY MEMBER REMOVAL — not recommended, kept for worst-case   */
/* situations only. Soft-delete: sessions die, re-join is blocked,   */
/* orders and payments stay on record forever.                       */
/* --------------------------------------------------------------- */

async function handleMemberRemove(req, res) {
  const found = await userFromReq(req).catch(() => null);
  if (!found) return fail(res, 401, "unauthorized", "LOG IN TO CONTINUE.");
  if (found.user.role !== "admin") return fail(res, 403, "forbidden", "ADMIN ONLY.");
  const body = await readBody(req, res, 20000);
  if (body === null) return;
  if (body === undefined) return fail(res, 400, "bad_request", "MALFORMED REQUEST BODY.");
  const email = String(body.email ?? "").trim().toLowerCase().slice(0, 120);
  const confirm = String(body.confirm ?? "").trim().toLowerCase();
  const reason = String(body.reason ?? "").trim().slice(0, 200);
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return fail(res, 422, "invalid", "DROP THE MEMBER'S EMAIL.");
  if (confirm !== email) return fail(res, 422, "confirm_mismatch", "TYPE THE MEMBER'S EMAIL EXACTLY TO CONFIRM THE REMOVAL.");
  const root = (process.env.ADMIN_EMAIL || "").trim().toLowerCase();
  /* the club owner / developer account can never be removed either */
  if (email === "ancel.claudio1@gmail.com") return fail(res, 403, "root_admin", "THE CLUB OWNER ACCOUNT CAN NEVER BE REMOVED.");
  if (root && email === root) return fail(res, 403, "root_admin", "THE CLUB OWNER ACCOUNT CAN NEVER BE REMOVED.");
  if (email === found.user.email) return fail(res, 422, "self_remove", "YOU CANNOT REMOVE THE ACCOUNT YOU ARE LOGGED INTO.");
  try {
    const { connect } = require("./ipc-pay/mongo");
    const d = await connect();
    const target = await d.collection("users").findOne({ email });
    if (!target) return fail(res, 404, "not_found", "NO IPC ACCOUNT WITH THAT EMAIL.");
    if (target.status === "removed") return fail(res, 422, "already_removed", "THAT ACCOUNT IS ALREADY REMOVED.");
    const now = new Date();
    await d.collection("users").updateOne(
      { _id: target._id },
      { $set: {
        status: "removed",
        removedAt: now,
        removedBy: found.user.email,
        removalReason: reason || "EMERGENCY REMOVAL BY " + found.user.email,
        role: "customer",
      } }
    );
    await d.collection("sessions").deleteMany({ userId: target._id });
    console.log("[ipc-pay] EMERGENCY member removed:", email, "by", found.user.email);
    await logActivity(d, found.user.email, "member_remove", "member", email, email,
      "EMERGENCY REMOVAL — SESSIONS KILLED" + (reason ? " · REASON: " + reason.slice(0, 120) : ""));
    return send(res, 200, {
      ok: true,
      message: "MEMBER REMOVED — SESSIONS KILLED AND RE-JOINING BLOCKED. ORDERS AND PAYMENTS STAY ON RECORD.",
    });
  } catch (err) {
    return mongoError(res, err, "member removal failed");
  }
}

/* RESTORE — the admin escape hatch for an emergency removal done by   */
/* mistake. Removed members themselves still cannot re-join on their    */
/* own; only the club can let them back in. Restored members come back  */
/* as regular customers (re-grant ADMIN from the role form if needed).  */
async function handleMemberRestore(req, res) {
  const found = await userFromReq(req).catch(() => null);
  if (!found) return fail(res, 401, "unauthorized", "LOG IN TO CONTINUE.");
  if (found.user.role !== "admin") return fail(res, 403, "forbidden", "ADMIN ONLY.");
  const body = await readBody(req, res, 20000);
  if (body === null) return;
  if (body === undefined) return fail(res, 400, "bad_request", "MALFORMED REQUEST BODY.");
  const email = String(body.email ?? "").trim().toLowerCase().slice(0, 120);
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return fail(res, 422, "invalid", "DROP THE MEMBER'S EMAIL.");
  try {
    const { connect } = require("./ipc-pay/mongo");
    const d = await connect();
    const target = await d.collection("users").findOne({ email });
    if (!target) return fail(res, 404, "not_found", "NO IPC ACCOUNT WITH THAT EMAIL.");
    if (target.status !== "removed") return fail(res, 422, "not_removed", "THAT ACCOUNT IS NOT REMOVED — NOTHING TO RESTORE.");
    await d.collection("users").updateOne(
      { _id: target._id },
      { $set: { status: "active" }, $unset: { removedAt: "", removedBy: "", removalReason: "" } }
    );
    console.log("[ipc-pay] member restored:", email, "by", found.user.email);
    await logActivity(d, found.user.email, "member_restore", "member", email, email, "REMOVED ACCOUNT RESTORED TO ACTIVE");
    return send(res, 200, {
      ok: true,
      message: "MEMBER RESTORED — " + email.toUpperCase() + " CAN LOG IN AND ORDER AGAIN.",
    });
  } catch (err) {
    return mongoError(res, err, "member restore failed");
  }
}

/* ADMIN PASSWORD RESET — a member forgot theirs. The club sets a fresh  */
/* one straight from the members tab: the scrypt hash rotates, every      */
/* session of that member dies, and the next sign-in uses the new word.   */
/* The member should change it to their own from the account page after.  */
async function handleAdminMemberPassword(req, res) {
  const found = await userFromReq(req).catch(() => null);
  if (!found) return fail(res, 401, "unauthorized", "LOG IN TO CONTINUE.");
  if (found.user.role !== "admin") return fail(res, 403, "forbidden", "ADMIN ONLY.");
  const body = await readBody(req, res, 20000);
  if (body === null) return;
  if (body === undefined) return fail(res, 400, "bad_request", "MALFORMED REQUEST BODY.");
  const email = String(body.email ?? "").trim().toLowerCase().slice(0, 120);
  const newPassword = String(body.newPassword ?? "");
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return fail(res, 422, "invalid", "DROP THE MEMBER'S EMAIL.");
  if (newPassword.length < 8 || newPassword.length > 72) {
    return fail(res, 422, "invalid", "THE NEW PASSWORD NEEDS 8 TO 72 CHARACTERS.");
  }
  try {
    const { connect, hashPassword } = require("./ipc-pay/mongo");
    const d = await connect();
    const target = await d.collection("users").findOne({ email });
    if (!target) return fail(res, 404, "not_found", "NO IPC ACCOUNT WITH THAT EMAIL.");
    if (target.status === "removed") return fail(res, 422, "removed", "THAT ACCOUNT IS REMOVED — RESTORE IT FIRST.");
    const next = hashPassword(newPassword);
    await d.collection("users").updateOne(
      { _id: target._id },
      { $set: {
        salt: next.salt,
        hash: next.hash,
        passwordChangedAt: new Date(),
        passwordResetBy: found.user.email,
      } }
    );
    /* every sign-in of the member dies — the next login uses the new word */
    await d.collection("sessions").deleteMany({ userId: target._id });
    console.log("[ipc-pay] admin password reset:", email, "by", found.user.email);
    await logActivity(d, found.user.email, "member_password_reset", "member", email, email,
      "ADMIN SET A NEW PASSWORD — ALL SESSIONS SIGNED OUT");
    return send(res, 200, {
      ok: true,
      message: "PASSWORD SET — EVERY SIGN-IN OF " + email.toUpperCase() + " WAS SIGNED OUT. HAND THE NEW ONE OVER AND HAVE THEM CHANGE IT FROM THE ACCOUNT PAGE.",
    });
  } catch (err) {
    return mongoError(res, err, "member password reset failed");
  }
}

/* --------------------------------------------------------------- */
/* NEWSLETTER — the mailing list. Validated, deduped, honeypotted,   */
/* rate limited per IP. Mongo down never blocks a friendly reply.    */
/* --------------------------------------------------------------- */

const recentNewsletter = new Map();

async function handleNewsletter(req, res, ip) {
  let raw = "";
  let dead = false;
  req.on("data", (chunk) => {
    raw += chunk;
    if (raw.length > 20000) { dead = true; req.destroy(); }
  });
  req.on("end", async () => {
    if (dead) return;
    let body = {};
    try { body = JSON.parse(raw || "{}"); }
    catch { return send(res, 400, { ok: false, reason: "bad_request" }); }
    if (typeof body.hp === "string" && body.hp.trim() !== "") {
      return send(res, 200, { ok: true, message: "YOU'RE ON THE LIST — FIRST ACCESS LANDS IN YOUR INBOX." });
    }
    const email = String(body.email ?? "").trim().toLowerCase().slice(0, 120);
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return fail(res, 422, "invalid", "THAT EMAIL DOESN'T LOOK RIGHT — CHECK IT AND SEND AGAIN.");
    }
    try {
      const { connect } = require("./ipc-pay/mongo");
      const d = await connect();
      const col = d.collection("newsletter");
      /* duplicates answer friendly even inside the cooldown window — it is a
         read, not a write, so the rate limit has nothing to protect here */
      const existing = await col.findOne({ email });
      if (existing) {
        return send(res, 200, { ok: true, message: "YOU'RE ALREADY ON THE LIST — FIRST ACCESS LANDS IN YOUR INBOX." });
      }
      const now = Date.now();
      const last = recentNewsletter.get(ip) || 0;
      if (now - last < 30000) {
        return fail(res, 429, "rate_limited", "EASY — THE LIST JUST SAVED YOU. TRY AGAIN IN A MOMENT.");
      }
      recentNewsletter.set(ip, now);
      if (recentNewsletter.size > 5000) {
        for (const [k, v] of recentNewsletter) if (now - v > 600000) recentNewsletter.delete(k);
      }
      await col.insertOne({ email, ip, createdAt: new Date(), source: String(body.source ?? "website").slice(0, 40) });
      console.log("[ipc-pay] newsletter subscriber added:", email);
      return send(res, 200, { ok: true, message: "YOU'RE ON THE LIST — FIRST ACCESS LANDS IN YOUR INBOX." });
    } catch (err) {
      return mongoError(res, err, "newsletter signup failed");
    }
  });
}

/* --------------------------------------------------------------- */
/* PASSWORD CHANGE — signed-in members only. Verifies the current    */
/* password, rotates the scrypt hash, kills every OTHER session.     */
/* --------------------------------------------------------------- */

async function handlePasswordChange(req, res) {
  const found = await userFromReq(req).catch(() => null);
  if (!found) return fail(res, 401, "unauthorized", "LOG IN TO CONTINUE.");
  const body = await readBody(req, res, 20000);
  if (body === null) return;
  if (body === undefined) return fail(res, 400, "bad_request", "MALFORMED REQUEST BODY.");
  const currentPassword = String(body.currentPassword ?? "");
  const newPassword = String(body.newPassword ?? "");
  const { verifyPassword, hashPassword, findUserById } = require("./ipc-pay/mongo");
  const user = await findUserById(found.user._id);
  if (!user || user.status === "removed") return fail(res, 401, "unauthorized", "LOG IN TO CONTINUE.");
  if (!verifyPassword(currentPassword, user.salt, user.hash)) {
    return fail(res, 401, "bad_credentials", "YOUR CURRENT PASSWORD IS WRONG — TRY AGAIN.");
  }
  if (newPassword.length < 8 || newPassword.length > 72) {
    return fail(res, 422, "invalid", "NEW PASSWORD NEEDS AT LEAST 8 CHARACTERS.");
  }
  if (newPassword === currentPassword) {
    return fail(res, 422, "invalid", "THE NEW PASSWORD MUST BE DIFFERENT FROM THE CURRENT ONE.");
  }
  try {
    const { connect } = require("./ipc-pay/mongo");
    const d = await connect();
    const next = hashPassword(newPassword);
    await d.collection("users").updateOne(
      { _id: user._id },
      { $set: { salt: next.salt, hash: next.hash, passwordChangedAt: new Date() } }
    );
    /* security: every OTHER session dies; this device stays logged in */
    await d.collection("sessions").deleteMany({ userId: user._id, token: { $ne: found.token } });
    console.log("[ipc-pay] password changed:", user.email);
    return send(res, 200, { ok: true, message: "PASSWORD UPDATED — OTHER DEVICES WERE SIGNED OUT." });
  } catch (err) {
    return mongoError(res, err, "password change failed");
  }
}

/* Last 7 days of verified revenue, keyed by Asia/Manila calendar day.
   Days with no paid payments report 0 so the chart never lies. */
function dailyPaidRevenue(d) {
  const manila = (dt) => new Date(dt.getTime() + 8 * 3600000).toISOString().slice(0, 10);
  const days = [];
  for (let i = 6; i >= 0; i--) {
    days.push({ day: manila(new Date(Date.now() - i * 86400000)), centavos: 0 });
  }
  const since = new Date(Date.now() - 6 * 86400000);
  since.setUTCHours(0, 0, 0, 0);
  return d.collection("payments").aggregate([
    { $match: { status: "paid", verifiedAt: { $gte: since } } },
    { $group: { _id: { $dateToString: { format: "%Y-%m-%d", date: "$verifiedAt", timezone: "Asia/Manila" } }, total: { $sum: "$amountCentavos" } } },
  ]).toArray().then((rows) => {
    const map = {};
    rows.forEach((r) => { map[r._id] = r.total; });
    days.forEach((day) => { day.centavos = map[day.day] || 0; });
    return days;
  });
}

/* --------------------------------------------------------------- */
/* MAYA WEBHOOK — real automatic payment reading once the club       */
/* upgrades to Maya Business. Guarded by IPC_WEBHOOK_SECRET.         */
/* --------------------------------------------------------------- */

async function handleMayaWebhook(req, res) {
  const secret = (process.env.IPC_WEBHOOK_SECRET || "").trim();
  if (!secret) {
    return fail(res, 503, "not_configured", "WEBHOOK OFF — SET IPC_WEBHOOK_SECRET ON THE HOST TO ENABLE IT.");
  }
  const provided = String(req.headers["x-ipc-signature"] || "");
  const a = Buffer.from(provided);
  const b = Buffer.from(secret);
  if (!provided || a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return fail(res, 401, "unauthorized", "BAD WEBHOOK SIGNATURE.");
  }
  const body = await readBody(req, res, 20000);
  if (body === null) return;
  if (body === undefined) return fail(res, 400, "bad_request", "MALFORMED WEBHOOK BODY.");
  const orderRef = String(body.orderReference ?? "").trim().toUpperCase();
  const paymentRef = String(body.paymentReference ?? "").trim().toUpperCase();
  const refNo = String(body.refNo ?? "").trim().slice(0, 40);
  if (!orderRef && !paymentRef) return fail(res, 422, "invalid", "orderReference OR paymentReference IS REQUIRED.");
  try {
    const { connect } = require("./ipc-pay/mongo");
    const d = await connect();
    const pay = await d.collection("payments").findOne(paymentRef
      ? { paymentReference: paymentRef }
      : { orderReference: orderRef });
    if (!pay) return fail(res, 404, "not_found", "NO PAYMENT FOR THAT REFERENCE.");
    if (pay.status === "paid" || pay.status === "failed") {
      return send(res, 200, { ok: true, status: pay.status, duplicate: true });
    }
    if (body.amountCentavos !== undefined && Number(body.amountCentavos) !== pay.amountCentavos) {
      return fail(res, 409, "amount_mismatch", "WEBHOOK AMOUNT DOES NOT MATCH THE ORDER TOTAL.");
    }
    const now = new Date();
    const decision = await d.collection("payments").updateOne(
      { _id: pay._id, status: { $in: ["pending", "under_verification"] } },
      { $set: {
        status: "paid",
        updatedAt: now,
        verifiedAt: now,
        reviewedBy: "MAYA WEBHOOK",
        decisionSource: "maya_webhook",
        ...(refNo && !pay.refNo ? { refNo } : {}),
      } }
    );
    if (decision.modifiedCount !== 1) {
      return fail(res, 409, "decision_conflict", "PAYMENT JUST CHANGED — NO ACTION TAKEN.");
    }
    await d.collection("orders").updateOne(
      { reference: pay.orderReference },
      { $set: { status: "paid", updatedAt: now } }
    );
    await ensureTracking(d, pay.orderReference, "IPC TEAM");
    await creditReferralIfAny(d, pay.orderReference);
    const orderForEmail = await d.collection("orders").findOne({ reference: pay.orderReference });
    await sendPaymentEmail({ ...pay, status: "paid" }, orderForEmail, "PAID",
      "Maya confirmed your payment automatically. Your order is confirmed and order tracking is now live in your account.");
    console.log("[ipc-pay] maya webhook verified " + pay.paymentReference + " — tracking opened.");
    return send(res, 200, { ok: true, status: "paid" });
  } catch (err) {
    return mongoError(res, err, "webhook failed");
  }
}

/* =============================================================== */
/* GROWTH PLATFORM — reviews, referral, birthday, 2FA, forgot-      */
/* password, guest checkout, launch gates, community, funnel        */
/* analytics, club config. Everything lives in the same Atlas db    */
/* and follows the same handler style as the rest of this file.     */
/* =============================================================== */

/* ---------- TOTP (RFC 6238) — standard library only, no deps ----- */

function b32Encode(buf) {
  const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, value = 0, out = "";
  for (const b of buf) {
    value = (value << 8) | b; bits += 8;
    while (bits >= 5) { out += A[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += A[(value << (5 - bits)) & 31];
  return out;
}

function b32Decode(s) {
  const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, value = 0; const out = [];
  for (const c of String(s || "").toUpperCase().replace(/=+$/, "")) {
    const idx = A.indexOf(c);
    if (idx < 0) continue;
    value = (value << 5) | idx; bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(out);
}

function totpCode(secretB32, timeStep) {
  const key = b32Decode(secretB32);
  if (!key.length) return "";
  const buf = Buffer.alloc(8);
  buf.writeUInt32BE(Math.floor(timeStep / 2 ** 32), 0);
  buf.writeUInt32BE(timeStep >>> 0, 4);
  const hmac = crypto.createHmac("sha1", key).update(buf).digest();
  const off = hmac[hmac.length - 1] & 0xf;
  const code = ((hmac[off] & 0x7f) << 24) | (hmac[off + 1] << 16) | (hmac[off + 2] << 8) | hmac[off + 3];
  return String(code % 1000000).padStart(6, "0");
}

function verifyTotp(secretB32, code) {
  const step = Math.floor(Date.now() / 30000);
  const want = String(code ?? "").trim();
  for (const s of [step - 1, step, step + 1]) {
    if (totpCode(secretB32, s) === want) return true;
  }
  return false;
}

/* ---------- generic EmailJS send (server-side) ------------------- */

async function sendClubEmail(templateId, params) {
  const publicKey = process.env.EMAILJS_PUBLIC_KEY || "";
  const serviceId = process.env.EMAILJS_SERVICE_ID || "";
  if (!publicKey || !serviceId || !templateId) return false;
  try {
    const response = await fetch(EMAILJS_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        service_id: serviceId,
        template_id: templateId,
        user_id: publicKey,
        template_params: params,
      }),
      signal: AbortSignal.timeout(15000),
    });
    if (!response.ok) throw new Error("EmailJS responded " + response.status);
    return true;
  } catch (err) {
    console.error("[ipc-email] send failed:", err.message);
    return false;
  }
}

/* ---------- MEMBER SELF-SERVICE FORGOT PASSWORD ------------------ */
/* Request → single-use hashed token (30 min) → emailed link.
   The response is identical whether or not the email exists, so the
   endpoint can never be used to probe accounts. */

async function handleForgotPassword(req, res, ip) {
  if (rateLimited(ip, 5, 15 * 60 * 1000, "forgot")) {
    return fail(res, 429, "rate_limited", "TOO MANY RESET REQUESTS — TRY AGAIN IN A FEW MINUTES.");
  }
  const body = await readBody(req, res, 20000);
  if (body === null) return;
  if (body === undefined) return fail(res, 400, "bad_request", "MALFORMED REQUEST BODY.");
  const email = String(body.email ?? "").trim().toLowerCase().slice(0, 120);
  const okMsg = "IF THAT EMAIL IS IN THE CLUB, A RESET LINK IS ON ITS WAY. CHECK YOUR INBOX (AND SPAM) — THE LINK WORKS ONCE FOR 30 MINUTES.";
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return send(res, 200, { ok: true, message: okMsg });
  try {
    const user = await findUserByEmail(email).catch(() => null);
    if (!user || user.status === "removed") return send(res, 200, { ok: true, message: okMsg });
    const { connect } = require("./ipc-pay/mongo");
    const d = await connect();
    const token = crypto.randomBytes(24).toString("hex");
    await d.collection("passwordResets").insertOne({
      userId: user._id,
      email,
      tokenHash: crypto.createHash("sha256").update(token).digest("hex"),
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 30 * 60 * 1000),
      usedAt: null,
    });
    const sent = await sendClubEmail(process.env.EMAILJS_RESET_TEMPLATE_ID || "", {
      to_email: email,
      customer_name: user.name || "IPC member",
      reset_link: SITE_ORIGIN + "/reset?token=" + token,
      reset_token: token,
      reply_to: "INDULGE PLAYAS CLUB",
    });
    if (!sent) console.warn("[ipc-auth] reset email skipped — set EMAILJS_RESET_TEMPLATE_ID on the host to enable it. Token still valid: " + SITE_ORIGIN + "/reset?token=" + token);
    return send(res, 200, { ok: true, message: okMsg, emailSent: sent });
  } catch (err) {
    return mongoError(res, err, "reset request failed");
  }
}

async function handleResetPassword(req, res, ip) {
  if (rateLimited(ip, 10, 15 * 60 * 1000, "reset")) {
    return fail(res, 429, "rate_limited", "TOO MANY ATTEMPTS — WAIT A FEW MINUTES.");
  }
  const body = await readBody(req, res, 20000);
  if (body === null) return;
  if (body === undefined) return fail(res, 400, "bad_request", "MALFORMED REQUEST BODY.");
  const token = String(body.token ?? "").trim();
  const newPassword = String(body.password ?? "");
  if (!/^[a-f0-9]{48}$/.test(token)) return fail(res, 422, "invalid", "THAT RESET LINK IS NOT VALID.");
  if (newPassword.length < 8 || newPassword.length > 72) {
    return fail(res, 422, "invalid", "PASSWORD NEEDS AT LEAST 8 CHARACTERS.");
  }
  try {
    const { connect, hashPassword } = require("./ipc-pay/mongo");
    const d = await connect();
    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
    const rec = await d.collection("passwordResets").findOne({
      tokenHash,
      usedAt: null,
      expiresAt: { $gt: new Date() },
    });
    if (!rec) {
      return fail(res, 422, "invalid_token", "THAT RESET LINK EXPIRED OR WAS ALREADY USED — REQUEST A FRESH ONE.");
    }
    const user = await findUserById(rec.userId);
    if (!user || user.status === "removed") {
      return fail(res, 422, "invalid_token", "THAT ACCOUNT NO LONGER EXISTS.");
    }
    const next = hashPassword(newPassword);
    await d.collection("users").updateOne(
      { _id: user._id },
      { $set: { salt: next.salt, hash: next.hash, passwordChangedAt: new Date() } }
    );
    /* single-use — burn the token and kill every session */
    await d.collection("passwordResets").updateOne(
      { _id: rec._id },
      { $set: { usedAt: new Date() } }
    );
    await d.collection("sessions").deleteMany({ userId: user._id });
    console.log("[ipc-auth] self-service password reset completed for " + user.email);
    return send(res, 200, { ok: true, message: "PASSWORD UPDATED — LOG IN WITH YOUR NEW PASSWORD." });
  } catch (err) {
    return mongoError(res, err, "reset failed");
  }
}

/* ---------- ADMIN TWO-FACTOR (TOTP) ------------------------------ */
/* Setup → secret + otpauth URI (QR drawn client-side) → enable with
   a live code → every admin login now demands the rotating code. */

async function handle2faSetup(req, res) {
  const found = await userFromReq(req).catch(() => null);
  if (!found) return fail(res, 401, "unauthorized", "LOG IN TO CONTINUE.");
  if (found.user.role !== "admin") return fail(res, 403, "forbidden", "ADMIN ONLY.");
  const { connect } = require("./ipc-pay/mongo");
  const d = await connect();
  const user = await findUserById(found.user._id);
  if (user && user.twoFAEnabled) {
    return fail(res, 409, "already_enabled", "TWO-FACTOR IS ALREADY ON — DISABLE IT FIRST TO RE-ENROLL.");
  }
  const secret = b32Encode(crypto.randomBytes(20));
  await d.collection("users").updateOne(
    { _id: found.user._id },
    { $set: { twoFASecret: secret, twoFAEnabled: false, twoFASetupAt: new Date() } }
  );
  const otpauth = "otpauth://totp/IPC:" + encodeURIComponent(found.user.email) +
    "?issuer=Indulge%20Playas%20Club&secret=" + secret + "&algorithm=SHA1&digits=6&period=30";
  return send(res, 200, { ok: true, secret, otpauth, message: "SCAN OR TYPE THE KEY INTO YOUR AUTHENTICATOR APP, THEN CONFIRM WITH A LIVE CODE." });
}

async function handle2faEnable(req, res) {
  const found = await userFromReq(req).catch(() => null);
  if (!found) return fail(res, 401, "unauthorized", "LOG IN TO CONTINUE.");
  if (found.user.role !== "admin") return fail(res, 403, "forbidden", "ADMIN ONLY.");
  const body = await readBody(req, res, 20000);
  if (body === null) return;
  if (body === undefined) return fail(res, 400, "bad_request", "MALFORMED REQUEST BODY.");
  const { connect } = require("./ipc-pay/mongo");
  const d = await connect();
  const user = await findUserById(found.user._id);
  if (!user || !user.twoFASecret) return fail(res, 422, "no_setup", "RUN SETUP FIRST.");
  if (!verifyTotp(user.twoFASecret, body.code)) {
    return fail(res, 422, "bad_code", "THAT CODE DIDN'T MATCH — CHECK YOUR AUTHENTICATOR AND TRY THE NEXT ONE.");
  }
  await d.collection("users").updateOne(
    { _id: user._id },
    { $set: { twoFAEnabled: true, twoFAEnabledAt: new Date() } }
  );
  await d.collection("sessions").deleteMany({ userId: user._id, token: { $ne: found.token } });
  console.log("[ipc-auth] 2FA enabled for " + user.email);
  return send(res, 200, { ok: true, message: "TWO-FACTOR IS ON — EVERY ADMIN LOGIN NOW NEEDS YOUR AUTHENTICATOR CODE." });
}

async function handle2faDisable(req, res) {
  const found = await userFromReq(req).catch(() => null);
  if (!found) return fail(res, 401, "unauthorized", "LOG IN TO CONTINUE.");
  if (found.user.role !== "admin") return fail(res, 403, "forbidden", "ADMIN ONLY.");
  const body = await readBody(req, res, 20000);
  if (body === null) return;
  if (body === undefined) return fail(res, 400, "bad_request", "MALFORMED REQUEST BODY.");
  const { connect, verifyPassword } = require("./ipc-pay/mongo");
  const d = await connect();
  const user = await findUserById(found.user._id);
  if (!user) return fail(res, 401, "unauthorized", "LOG IN TO CONTINUE.");
  if (!verifyPassword(String(body.password ?? ""), user.salt, user.hash)) {
    return fail(res, 401, "bad_credentials", "PASSWORD CHECK FAILED — TWO-FACTOR STAYS ON.");
  }
  if (user.twoFAEnabled && !verifyTotp(user.twoFASecret, body.code)) {
    return fail(res, 422, "bad_code", "THAT CODE DIDN'T MATCH — TWO-FACTOR STAYS ON.");
  }
  await d.collection("users").updateOne(
    { _id: user._id },
    { $unset: { twoFASecret: "", twoFAEnabled: "", twoFAEnabledAt: "", twoFASetupAt: "" } }
  );
  await d.collection("sessions").deleteMany({ userId: user._id, token: { $ne: found.token } });
  console.log("[ipc-auth] 2FA disabled for " + user.email);
  return send(res, 200, { ok: true, message: "TWO-FACTOR IS OFF." });
}

async function handle2faVerify(req, res, ip) {
  if (rateLimited(ip, 10, 15 * 60 * 1000, "2fa")) {
    return fail(res, 429, "rate_limited", "TOO MANY CODE ATTEMPTS — WAIT A FEW MINUTES.");
  }
  const body = await readBody(req, res, 20000);
  if (body === null) return;
  if (body === undefined) return fail(res, 400, "bad_request", "MALFORMED REQUEST BODY.");
  const challenge = String(body.challenge ?? "").trim();
  if (!/^[a-f0-9]{48}$/.test(challenge)) return fail(res, 422, "invalid", "THAT LOGIN CHALLENGE EXPIRED — START AGAIN.");
  try {
    const { connect } = require("./ipc-pay/mongo");
    const d = await connect();
    const rec = await d.collection("twoFALogins").findOne({
      challenge,
      expiresAt: { $gt: new Date() },
    });
    if (!rec) return fail(res, 422, "invalid", "THAT LOGIN CHALLENGE EXPIRED — START AGAIN.");
    const user = await findUserById(rec.userId);
    if (!user || user.status === "removed" || !user.twoFAEnabled || !user.twoFASecret) {
      return fail(res, 422, "invalid", "START THE LOGIN AGAIN.");
    }
    if (!verifyTotp(user.twoFASecret, body.code)) {
      return fail(res, 422, "bad_code", "THAT CODE DIDN'T MATCH — TRY THE NEXT ONE.");
    }
    await d.collection("twoFALogins").deleteOne({ _id: rec._id });
    const token = await createSession(user);
    console.log("[ipc-auth] 2FA login ok: " + user.email);
    return send(res, 200, { ok: true, token, user: publicUser(user) });
  } catch (err) {
    return mongoError(res, err, "2fa verification failed");
  }
}

/* ---------- PRODUCT REVIEWS — verified buyers, admin moderated --- */

async function handleReviewsGet(req, res, p) {
  const q = new URL("http://x" + p.replace(/^#/, "")).searchParams;
  const productId = String(q.get("productId") ?? "").trim().slice(0, 60);
  if (!productId) return fail(res, 422, "invalid", "MISSING productId.");
  try {
    const { connect } = require("./ipc-pay/mongo");
    const d = await boundedRead(connect(), 1500);
    if (d === "timeout") throw new Error("mongo_slow");
    const rows = await d.collection("reviews").find({ productId, status: "approved" })
      .sort({ createdAt: -1 }).limit(50).toArray();
    const agg = await d.collection("reviews").aggregate([
      { $match: { productId, status: "approved" } },
      { $group: { _id: null, n: { $sum: 1 }, avg: { $avg: "$rating" },
        fit5: { $avg: "$fitTrue" } } },
    ]).toArray();
    return send(res, 200, {
      ok: true,
      reviews: rows.map((r) => ({
        id: String(r._id), rating: r.rating, title: r.title || "",
        body: r.body, name: r.displayName, createdAt: r.createdAt, fitTrue: !!r.fitTrue,
      })),
      summary: {
        count: (agg[0] && agg[0].n) || 0,
        avgRating: agg[0] ? Math.round(agg[0].avg * 10) / 10 : 0,
        fitsTruePct: agg[0] ? Math.round(agg[0].fit5 * 100) : 0,
      },
    });
  } catch (err) {
    return mongoError(res, err, "reviews failed");
  }
}

async function handleReviewCreate(req, res) {
  const found = await userFromReq(req).catch(() => null);
  if (!found) return fail(res, 401, "unauthorized", "LOG IN TO CONTINUE.");
  const body = await readBody(req, res, 20000);
  if (body === null) return;
  if (body === undefined) return fail(res, 400, "bad_request", "MALFORMED REQUEST BODY.");
  const productId = String(body.productId ?? "").trim().slice(0, 60);
  const rating = Math.round(Number(body.rating));
  const title = String(body.title ?? "").trim().slice(0, 80);
  const text = String(body.body ?? "").trim().slice(0, 600);
  const fitTrue = !!body.fitTrue;
  if (!productId) return fail(res, 422, "invalid", "MISSING productId.");
  if (!Number.isFinite(rating) || rating < 1 || rating > 5) {
    return fail(res, 422, "invalid", "PICK A RATING FROM 1 TO 5.");
  }
  if (text.length < 4) return fail(res, 422, "invalid", "SAY A LINE ABOUT THE PIECE — AT LEAST A FEW WORDS.");
  try {
    const { connect } = require("./ipc-pay/mongo");
    const d = await connect();
    /* verified buyer: a PAID order containing this piece under this email */
    const bought = await d.collection("orders").countDocuments({
      email: found.user.email,
      status: "paid",
      items: { $elemMatch: { productId } },
    });
    if (!bought) {
      return fail(res, 403, "not_verified", "REVIEWS ARE FOR VERIFIED BUYERS ONLY — PAY FOR THE PIECE FIRST AND IT UNLOCKS.");
    }
    const existing = await d.collection("reviews").findOne({
      productId, email: found.user.email, status: { $ne: "rejected" },
    });
    if (existing) {
      return fail(res, 409, "already_reviewed", "YOU ALREADY REVIEWED THIS PIECE — ONE REVIEW PER MEMBER PER PIECE.");
    }
    await d.collection("reviews").insertOne({
      productId,
      email: found.user.email,
      userId: found.user._id,
      displayName: (found.user.name || "IPC MEMBER").split(" ")[0].toUpperCase().slice(0, 24),
      rating, title, body: text, fitTrue,
      status: "pending",
      createdAt: new Date(),
    });
    return send(res, 200, { ok: true, message: "REVIEW IN — THE CLUB CHECKS EVERY REVIEW BEFORE IT GOES LIVE." });
  } catch (err) {
    return mongoError(res, err, "review failed");
  }
}

async function handleAdminReviews(req, res) {
  const found = await userFromReq(req).catch(() => null);
  if (!found || found.user.role !== "admin") return fail(res, 403, "forbidden", "ADMIN ONLY.");
  try {
    const { connect } = require("./ipc-pay/mongo");
    const d = await connect();
    const rows = await d.collection("reviews").find({}).sort({ createdAt: -1 }).limit(200).toArray();
    return send(res, 200, {
      ok: true,
      reviews: rows.map((r) => ({
        id: String(r._id), productId: r.productId, rating: r.rating,
        title: r.title || "", body: r.body, name: r.displayName,
        email: r.email, status: r.status, createdAt: r.createdAt, fitTrue: !!r.fitTrue,
      })),
    });
  } catch (err) {
    return mongoError(res, err, "admin reviews failed");
  }
}

async function handleAdminReviewModerate(req, res) {
  const found = await userFromReq(req).catch(() => null);
  if (!found || found.user.role !== "admin") return fail(res, 403, "forbidden", "ADMIN ONLY.");
  const body = await readBody(req, res, 20000);
  if (body === null) return;
  if (body === undefined) return fail(res, 400, "bad_request", "MALFORMED REQUEST BODY.");
  const action = String(body.action ?? "").trim().toLowerCase();
  if (!/^[a-f0-9]{24}$/.test(String(body.id ?? "").trim())) {
    return fail(res, 422, "invalid", "MISSING REVIEW ID.");
  }
  if (!["approve", "reject"].includes(action)) {
    return fail(res, 422, "invalid", "ACTION MUST BE approve OR reject.");
  }
  try {
    const { connect } = require("./ipc-pay/mongo");
    const d = await connect();
    const { ObjectId } = require("mongodb");
    await d.collection("reviews").updateOne(
      { _id: new ObjectId(String(body.id).trim()) },
      { $set: { status: action === "approve" ? "approved" : "rejected", moderatedAt: new Date(), moderatedBy: found.user.email } }
    );
    return send(res, 200, { ok: true, message: action === "approve" ? "REVIEW IS LIVE." : "REVIEW HIDDEN." });
  } catch (err) {
    return mongoError(res, err, "moderation failed");
  }
}

/* ---------- ON THE STREETS — club-curated community wall ---------- */

async function handleStreetsGet(req, res) {
  try {
    const { connect } = require("./ipc-pay/mongo");
    const d = await boundedRead(connect(), 1500);
    if (d === "timeout") throw new Error("mongo_slow");
    const rows = await d.collection("streets").find({ active: { $ne: false } })
      .sort({ createdAt: -1 }).limit(24).toArray();
    return send(res, 200, {
      ok: true,
      posts: rows.map((r) => ({
        id: String(r._id), name: r.name, city: r.city || "",
        caption: r.caption || "", img: r.img, createdAt: r.createdAt,
      })),
    });
  } catch (err) {
    return mongoError(res, err, "streets failed");
  }
}

async function handleAdminStreetAdd(req, res) {
  const found = await userFromReq(req).catch(() => null);
  if (!found || found.user.role !== "admin") return fail(res, 403, "forbidden", "ADMIN ONLY.");
  const body = await readBody(req, res, 4 * 1024 * 1024);
  if (body === null) return;
  if (body === undefined) return fail(res, 400, "bad_request", "MALFORMED REQUEST BODY.");
  const name = String(body.name ?? "").trim().replace(/\s+/g, " ").slice(0, 40);
  const city = String(body.city ?? "").trim().replace(/\s+/g, " ").slice(0, 60);
  const caption = String(body.caption ?? "").trim().slice(0, 240);
  const img = String(body.img ?? "").trim();
  if (name.length < 2) return fail(res, 422, "invalid", "GIVE THE PLAYA A NAME.");
  if (!img) return fail(res, 422, "invalid", "THE POST NEEDS A PHOTO.");
  const isDataImg = /^data:image\/(?:jpeg|jpg|png|webp);base64,[A-Za-z0-9+/=\s]+$/.test(img);
  const isUrlImg = /^https:\/\/\S{1,480}$/i.test(img);
  if (!isDataImg && !isUrlImg) {
    return fail(res, 422, "invalid", "THE PHOTO MUST BE A JPG/PNG UPLOAD OR AN HTTPS IMAGE LINK.");
  }
  try {
    const { connect } = require("./ipc-pay/mongo");
    const d = await connect();
    await d.collection("streets").insertOne({
      name, city, caption, img,
      addedBy: found.user.email,
      active: true,
      createdAt: new Date(),
    });
    return send(res, 200, { ok: true, message: "ON THE STREETS — THE POST IS LIVE." });
  } catch (err) {
    return mongoError(res, err, "streets save failed");
  }
}

async function handleAdminStreetRemove(req, res) {
  const found = await userFromReq(req).catch(() => null);
  if (!found || found.user.role !== "admin") return fail(res, 403, "forbidden", "ADMIN ONLY.");
  const body = await readBody(req, res, 20000);
  if (body === null) return;
  if (body === undefined) return fail(res, 400, "bad_request", "MALFORMED REQUEST BODY.");
  if (!/^[a-f0-9]{24}$/.test(String(body.id ?? "").trim())) {
    return fail(res, 422, "invalid", "MISSING POST ID.");
  }
  try {
    const { connect } = require("./ipc-pay/mongo");
    const d = await connect();
    const { ObjectId } = require("mongodb");
    await d.collection("streets").updateOne(
      { _id: new ObjectId(String(body.id).trim()) },
      { $set: { active: false } }
    );
    return send(res, 200, { ok: true, message: "POST TAKEN DOWN." });
  } catch (err) {
    return mongoError(res, err, "streets removal failed");
  }
}

/* ---------- PRIVACY-FRIENDLY FUNNEL ANALYTICS -------------------- */
/* First-party, no cookies, no PII: one random per-browser id kept in
   localStorage, event name, day. That is the entire record. */

const ANALYTICS_EVENTS = new Set(["view_product", "add_to_bag", "checkout_start", "paid"]);

async function handleAnalyticsEvent(req, res, ip) {
  if (rateLimited(ip, 120, 60 * 1000, "analytics")) {
    return send(res, 200, { ok: true, dropped: true });
  }
  const body = await readBody(req, res, 2000);
  if (body === null) return;
  const name = String(body.name ?? "");
  if (!ANALYTICS_EVENTS.has(name)) return send(res, 200, { ok: true, dropped: true });
  try {
    const { connect } = require("./ipc-pay/mongo");
    const d = await connect();
    await d.collection("analyticsEvents").insertOne({
      name,
      visitor: String(body.visitor ?? "").replace(/[^a-z0-9-]/gi, "").slice(0, 40),
      product: String(body.product ?? "").replace(/[^a-z0-9\-]/gi, "").slice(0, 60),
      valueCentavos: Math.max(0, Math.round(Number(body.valueCentavos) || 0)),
      createdAt: new Date(),
    });
    return send(res, 200, { ok: true });
  } catch { /* analytics never blocks the shop */ return send(res, 200, { ok: true }); }
}

async function handleAdminFunnel(req, res) {
  const found = await userFromReq(req).catch(() => null);
  if (!found || found.user.role !== "admin") return fail(res, 403, "forbidden", "ADMIN ONLY.");
  try {
    const { connect } = require("./ipc-pay/mongo");
    const d = await connect();
    const rows = await d.collection("analyticsEvents").aggregate([
      { $match: { createdAt: { $gte: new Date(Date.now() - 30 * 86400000) } } },
      { $group: { _id: "$name", n: { $sum: 1 }, visitors: { $addToSet: "$visitor" } } },
    ]).toArray();
    const out = {};
    rows.forEach((r) => { out[r._id] = { count: r.n, visitors: r.visitors.length }; });
    ["view_product", "add_to_bag", "checkout_start", "paid"].forEach((k) => {
      if (!out[k]) out[k] = { count: 0, visitors: 0 };
    });
    return send(res, 200, { ok: true, funnel: out });
  } catch (err) {
    return mongoError(res, err, "funnel failed");
  }
}

/* ---------- CLUB CONFIG — shared settings the site reads ---------- */

async function handleConfigGet(req, res) {
  let usdPhpRate = 58;
  let maintenance = { enabled: false, allowMembers: true, message: "" };
  try {
    const { connect } = require("./ipc-pay/mongo");
    const d = await boundedRead(connect(), 1500);
    if (d === "timeout") throw new Error("mongo_slow");
    const cfg = await d.collection("settings").findOne({ _id: "club" });
    if (cfg && Number(cfg.usdPhpRate) > 0) usdPhpRate = Number(cfg.usdPhpRate);
    const m = (cfg && cfg.maintenance) || {};
    maintenance = {
      enabled: !!m.enabled,
      allowMembers: m.allowMembers !== false,
      message: String(m.message || "").slice(0, 240),
    };
  } catch { /* defaults hold */ }
  return send(res, 200, { ok: true, usdPhpRate, maintenance });
}

/* the wall switch — admin-only, logged with who flipped it and when */
async function handleMaintenanceSet(req, res) {
  const found = await userFromReq(req).catch(() => null);
  if (!found || found.user.role !== "admin") return fail(res, 403, "forbidden", "ADMIN ONLY.");
  const body = await readBody(req, res, 20000);
  if (body === null) return;
  if (body === undefined) return fail(res, 400, "bad_request", "MALFORMED REQUEST BODY.");
  const enabled = !!body.enabled;
  const allowMembers = body.allowMembers === undefined ? true : !!body.allowMembers;
  const message = String(body.message ?? "").trim().slice(0, 240);
  try {
    const { connect } = require("./ipc-pay/mongo");
    const d = await connect();
    await d.collection("settings").updateOne(
      { _id: "club" },
      { $set: { maintenance: { enabled, allowMembers, message, updatedAt: new Date(), updatedBy: found.user.email } } },
      { upsert: true }
    );
    maintCache = { at: 0, state: null }; /* the gate re-reads on the next request */
    await logActivity(d, found.user.email, "settings_maintenance", "settings", "site_wall",
      enabled ? "SITE CLOSED — WALL UP" : "SITE REOPENED",
      (enabled ? "WALL UP" : "WALL DOWN") + " · MEMBERS " + (allowMembers ? "LET THROUGH" : "BLOCKED") +
        (message ? " · MESSAGE: " + message.slice(0, 120) : ""));
    return send(res, 200, { ok: true, maintenance: { enabled, allowMembers, message },
      message: enabled
        ? (allowMembers ? "THE WALL IS UP — ADMINS AND LOGGED-IN MEMBERS STILL SEE THE SITE."
          : "THE WALL IS UP — ADMINS ONLY UNTIL IT COMES DOWN.")
        : "THE FLOOR IS OPEN — THE CLUB IS BACK IN BUSINESS." });
  } catch (err) {
    return mongoError(res, err, "maintenance save failed");
  }
}

async function handleConfigSet(req, res) {
  const found = await userFromReq(req).catch(() => null);
  if (!found || found.user.role !== "admin") return fail(res, 403, "forbidden", "ADMIN ONLY.");
  const body = await readBody(req, res, 20000);
  if (body === null) return;
  if (body === undefined) return fail(res, 400, "bad_request", "MALFORMED REQUEST BODY.");
  const rate = Number(body.usdPhpRate);
  if (!Number.isFinite(rate) || rate < 20 || rate > 120) {
    return fail(res, 422, "invalid", "THE RATE MUST SIT BETWEEN 20 AND 120 PESOS PER DOLLAR.");
  }
  try {
    const { connect } = require("./ipc-pay/mongo");
    const d = await connect();
    await d.collection("settings").updateOne(
      { _id: "club" },
      { $set: { usdPhpRate: rate, updatedAt: new Date(), updatedBy: found.user.email } },
      { upsert: true }
    );
    await logActivity(d, found.user.email, "settings_config", "settings", "usd_php_rate", "USD APPROXIMATION",
      "RATE SET TO " + rate + " PHP PER USD");
    return send(res, 200, { ok: true, usdPhpRate: rate, message: "USD APPROXIMATION UPDATED ACROSS THE SHOP." });
  } catch (err) {
    return mongoError(res, err, "config failed");
  }
}

/* ---------- COLLECTION LAUNCH STATES + TIER GATES ---------------- */

const LAUNCH_STATES = ["none", "announced", "live", "soldout"];
const TIER_GATES = ["none", "HOMIE", "OG", "VIP"];
const TIER_RANK = { ROOKIE: 0, HOMIE: 1, OG: 2, VIP: 3 };

async function handleCollectionState(req, res) {
  const found = await userFromReq(req).catch(() => null);
  if (!found || found.user.role !== "admin") return fail(res, 403, "forbidden", "ADMIN ONLY.");
  const body = await readBody(req, res, 20000);
  if (body === null) return;
  if (body === undefined) return fail(res, 400, "bad_request", "MALFORMED REQUEST BODY.");
  const slug = normalizeProductCollection(body.slug);
  const launchState = String(body.launchState ?? "none");
  const tierGate = String(body.tierGate ?? "none").toUpperCase();
  const storyNote = String(body.storyNote ?? "").trim().slice(0, 600);
  if (!slug) return fail(res, 422, "invalid", "MISSING COLLECTION SLUG.");
  if (!LAUNCH_STATES.includes(launchState)) return fail(res, 422, "invalid", "LAUNCH STATE MUST BE none, announced, live OR soldout.");
  if (!TIER_GATES.includes(tierGate)) return fail(res, 422, "invalid", "TIER GATE MUST BE none, HOMIE, OG OR VIP.");
  let launchAt = null;
  if (body.launchAt) {
    const t = new Date(String(body.launchAt));
    if (isNaN(t.getTime())) return fail(res, 422, "invalid", "THAT LAUNCH DATE DIDN'T PARSE.");
    launchAt = t;
  }
  try {
    const { connect } = require("./ipc-pay/mongo");
    const d = await connect();
    await d.collection("collections").updateOne(
      { slug },
      { $set: {
        launchState, tierGate, storyNote,
        ...(launchAt ? { launchAt } : {}),
        ...(body.clearLaunchAt ? { launchAt: null } : {}),
        updatedAt: new Date(),
      }, $setOnInsert: { createdAt: new Date() } },
      { upsert: true }
    );
    await logActivity(d, found.user.email, "collection_state", "collection", slug, slug.toUpperCase(),
      "LAUNCH " + launchState.toUpperCase() + " · GATE " + tierGate.toUpperCase());
    return send(res, 200, { ok: true, message: "COLLECTION STATE SAVED — THE HERO AND SHOP PICK IT UP ON THEIR NEXT LOAD." });
  } catch (err) {
    return mongoError(res, err, "collection state failed");
  }
}

/* ---------- REFERRAL + BIRTHDAY — retention engines --------------- */

async function ensureReferralCode(d, user) {
  if (user.referralCode) return user.referralCode;
  const base = (user.name || "PLAYA").replace(/[^a-zA-Z]/g, "").toUpperCase().slice(0, 6) || "PLAYA";
  for (let i = 0; i < 8; i++) {
    const code = (base + String(Math.floor(1000 + Math.random() * 9000))).slice(0, 14);
    const clash = await d.collection("users").findOne({ referralCode: code });
    if (!clash) {
      await d.collection("users").updateOne({ _id: user._id }, { $set: { referralCode: code } });
      /* the friend's side: a fixed ₱100 voucher keyed to this member */
      await d.collection("vouchers").updateOne(
        { code, kind: "referral" },
        { $set: {
          code,
          kind: "referral",
          label: "REFERRAL — " + (user.name || "IPC MEMBER").toUpperCase().slice(0, 20),
          type: "fixed",
          value: 10000,
          minSubtotalCentavos: 0,
          maxUses: 0,
          uses: 0,
          active: true,
          firstOrderOnly: false,
          ownerEmail: user.email,
          createdAt: new Date(),
        }, $setOnInsert: { createdAt: new Date() } },
        { upsert: true }
      );
      return code;
    }
  }
  return null;
}

async function ensureBirthdayVoucher(d, user) {
  if (!user.birthMonth || user.birthMonth < 1 || user.birthMonth > 12) return null;
  const now = new Date();
  const manilaMonth = Number(new Date(now.getTime() + 8 * 3600000).getMonth()) + 1;
  if (manilaMonth !== user.birthMonth) return null;
  const year = new Date(now.getTime() + 8 * 3600000).getFullYear();
  const flag = "birthdayVoucher" + year;
  if (user[flag]) return null;
  const code = ("BDAY" + year + user.email.replace(/[^a-z0-9]/gi, "").slice(0, 6)).toUpperCase().slice(0, 24);
  await d.collection("vouchers").updateOne(
    { code, kind: "birthday" },
    { $set: {
      code,
      kind: "birthday",
      label: "BIRTHDAY VOUCHER — " + String(user.birthMonth),
      type: "fixed",
      value: 15000,
      minSubtotalCentavos: 0,
      maxUses: 1,
      uses: 0,
      active: true,
      firstOrderOnly: false,
      expiresAt: new Date(now.getFullYear(), now.getMonth() + 1, 1),
      createdAt: new Date(),
    }, $setOnInsert: { createdAt: new Date() } },
    { upsert: true }
  );
  await d.collection("users").updateOne({ _id: user._id }, { $set: { [flag]: true } });
  await sendClubEmail(process.env.EMAILJS_BIRTHDAY_TEMPLATE_ID || "", {
    to_email: user.email,
    customer_name: user.name || "IPC member",
    voucher_code: code,
    reply_to: "INDULGE PLAYAS CLUB",
  });
  return code;
}

/* when a referral voucher's order gets PAID, credit the giver */
async function creditReferralIfAny(d, orderReference) {
  try {
    const order = await d.collection("orders").findOne({ reference: orderReference });
    if (!order || !order.voucherCode) return;
    const voucher = await d.collection("vouchers").findOne({ code: order.voucherCode });
    if (!voucher || voucher.kind !== "referral" || !voucher.ownerEmail) return;
    if (voucher.ownerEmail === order.email) return; /* self-referral does nothing */
    const giver = await d.collection("users").findOne({ email: voucher.ownerEmail });
    if (!giver) return;
    await d.collection("users").updateOne(
      { _id: giver._id },
      { $inc: { referralCount: 1 } }
    );
    /* the giver's thank-you: a fixed ₱100 credit voucher, 60 days */
    const code = ("THANKS" + String(giver.referralCount || 1) + "-" + crypto.randomBytes(3).toString("hex")).toUpperCase().slice(0, 20);
    await d.collection("vouchers").insertOne({
      code,
      kind: "referral_credit",
      label: "REFERRAL CREDIT — FRIEND PAID",
      type: "fixed",
      value: 10000,
      minSubtotalCentavos: 0,
      maxUses: 1,
      uses: 0,
      active: true,
      firstOrderOnly: false,
      ownerEmail: giver.email,
      expiresAt: new Date(Date.now() + 60 * 86400000),
      createdAt: new Date(),
    });
    await sendClubEmail(process.env.EMAILJS_REFERRAL_TEMPLATE_ID || "", {
      to_email: giver.email,
      customer_name: giver.name || "IPC member",
      voucher_code: code,
      reply_to: "INDULGE PLAYAS CLUB",
    });
    console.log("[ipc-club] referral credit " + code + " issued to " + giver.email);
  } catch (err) {
    console.error("[ipc-club] referral credit failed:", err && err.message);
  }
}

/* guest order → account linking after signup */
async function handleOrdersLink(req, res) {
  const found = await userFromReq(req).catch(() => null);
  if (!found) return fail(res, 401, "unauthorized", "LOG IN TO CONTINUE.");
  const body = await readBody(req, res, 20000);
  if (body === null) return;
  if (body === undefined) return fail(res, 400, "bad_request", "MALFORMED REQUEST BODY.");
  const reference = String(body.reference ?? "").trim().toUpperCase();
  const guestToken = String(body.guestToken ?? "").trim();
  if (!/^[A-Za-z0-9-]+$/.test(reference)) return fail(res, 422, "invalid", "THAT ORDER REFERENCE DOESN'T LOOK RIGHT.");
  if (!/^[a-f0-9]{32,128}$/.test(guestToken)) return fail(res, 422, "invalid", "MISSING GUEST RECEIPT TOKEN.");
  try {
    const { connect } = require("./ipc-pay/mongo");
    const d = await connect();
    const order = await d.collection("orders").findOne({ reference });
    if (!order) return fail(res, 404, "not_found", "NO ORDER FOUND FOR THAT REFERENCE.");
    if (order.userId) {
      return fail(res, 409, "already_linked", "THAT ORDER ALREADY BELONGS TO AN ACCOUNT.");
    }
    if (order.guestToken !== guestToken) {
      return fail(res, 403, "forbidden", "THAT RECEIPT TOKEN DOESN'T MATCH THIS ORDER.");
    }
    await d.collection("orders").updateOne(
      { _id: order._id, userId: null },
      { $set: { userId: found.user._id, email: found.user.email, linkedAt: new Date() } }
    );
    await d.collection("payments").updateMany(
      { orderReference: reference, userId: null },
      { $set: { userId: found.user._id } }
    );
    return send(res, 200, { ok: true, message: "ORDER ATTACHED TO YOUR ACCOUNT — IT NOW SHOWS UNDER YOUR HISTORY AND TRACKER." });
  } catch (err) {
    return mongoError(res, err, "order link failed");
  }
}

/* --------------------------------------------------------------- */
/* ADMIN ACTIVITY LOG — read-only. Who did what, when. There is no   */
/* write, edit or delete route for this collection anywhere in the   */
/* API: the record writes itself and nobody can clean it.            */
/* --------------------------------------------------------------- */

async function handleAdminActivity(req, res) {
  const found = await userFromReq(req).catch(() => null);
  if (!found) return fail(res, 401, "unauthorized", "LOG IN TO CONTINUE.");
  if (found.user.role !== "admin") return fail(res, 403, "forbidden", "ADMIN ONLY — THIS RECORD IS FOR THE CLUB ADMINS.");
  try {
    const { connect } = require("./ipc-pay/mongo");
    const d = await connect();
    const rows = await d.collection("activityLogs")
      .find({}).sort({ createdAt: -1 }).limit(200).toArray();
    return send(res, 200, {
      ok: true,
      readOnly: true,
      activity: rows.map((r) => ({
        id: String(r._id),
        actorEmail: r.actorEmail,
        action: r.action,
        targetType: r.targetType,
        targetId: r.targetId,
        targetLabel: r.targetLabel,
        details: r.details || "",
        createdAt: r.createdAt,
      })),
    });
  } catch (err) {
    return mongoError(res, err, "activity log failed");
  }
}

/* --------------------------------------------------------------- */
/* ADMIN ANALYTICS — real aggregates only. Every number here comes   */
/* straight from the orders / payments / analyticsEvents collections */
/* inside the requested date range (Manila days). When the club has  */
/* no data for a window, the dashboard shows zero — never a sample.  */
/* --------------------------------------------------------------- */

function manilaDayStart(dateStr) {
  /* a YYYY-MM-DD typed in Manila means 00:00 PHT that day = 16:00 UTC the day before */
  const t = new Date(dateStr + "T00:00:00+08:00");
  return isNaN(t.getTime()) ? null : t;
}
function manilaDayKey(dt) {
  return new Date(dt.getTime() + 8 * 3600000).toISOString().slice(0, 10);
}

async function handleAdminAnalytics(req, res) {
  const found = await userFromReq(req).catch(() => null);
  if (!found) return fail(res, 401, "unauthorized", "LOG IN TO CONTINUE.");
  if (found.user.role !== "admin") return fail(res, 403, "forbidden", "ADMIN ONLY.");
  try {
    const { connect } = require("./ipc-pay/mongo");
    const d = await connect();
    /* date range: ?days=7|30|90|365 (default 30) or ?from=YYYY-MM-DD&to=YYYY-MM-DD, Manila time */
    const q = new URL(req.url, "http://x").searchParams;
    const now = new Date();
    let from = null;
    let to = null;
    if (q.get("from") && q.get("to")) {
      from = manilaDayStart(q.get("from"));
      to = manilaDayStart(q.get("to"));
      if (to) to = new Date(to.getTime() + 86400000 - 1); /* inclusive end day */
      if (!from || !to || from > to) return fail(res, 422, "invalid", "THAT DATE RANGE DIDN'T PARSE — CHECK FROM AND TO.");
      if (to > now) to = now;
    } else {
      const days = [7, 30, 90, 365].includes(Number(q.get("days"))) ? Number(q.get("days")) : 30;
      from = new Date(now.getTime() - days * 86400000);
      to = now;
    }
    const rangeMatch = { createdAt: { $gte: from, $lte: to } };
    const paidAtMatch = { status: "paid", $expr: { $and: [
      { $gte: [{ $ifNull: ["$verifiedAt", "$createdAt"] }, from] },
      { $lte: [{ $ifNull: ["$verifiedAt", "$createdAt"] }, to] },
    ] } };

    const [salesAgg, ordersPlaced, paidOrders, dailyRows, bestRows, viewRows, funnelRows, emailsInRange, earlierEmails, bagEvents, checkoutEvents] = await Promise.all([
      d.collection("payments").aggregate([
        { $match: paidAtMatch },
        { $group: { _id: null, total: { $sum: "$amountCentavos" }, n: { $sum: 1 } } },
      ]).toArray(),
      d.collection("orders").countDocuments(rangeMatch),
      d.collection("payments").countDocuments(paidAtMatch),
      d.collection("payments").aggregate([
        { $match: paidAtMatch },
        { $group: {
          _id: { $dateToString: { format: "%Y-%m-%d", date: { $ifNull: ["$verifiedAt", "$createdAt"] }, timezone: "Asia/Manila" } },
          revenue: { $sum: "$amountCentavos" }, orders: { $sum: 1 },
        } },
        { $sort: { _id: 1 } },
      ]).toArray(),
      d.collection("orders").aggregate([
        { $match: { status: "paid", ...rangeMatch } },
        { $unwind: "$items" },
        { $group: {
          _id: "$items.productId",
          name: { $first: "$items.name" },
          units: { $sum: "$items.qty" },
          revenue: { $sum: { $multiply: ["$items.priceCentavos", "$items.qty"] } },
        } },
        { $sort: { units: -1 } },
        { $limit: 8 },
      ]).toArray(),
      d.collection("analyticsEvents").aggregate([
        { $match: { name: "view_product", ...rangeMatch } },
        { $group: { _id: "$product", views: { $sum: 1 } } },
        { $sort: { views: -1 } },
        { $limit: 8 },
      ]).toArray(),
      d.collection("analyticsEvents").aggregate([
        { $match: { createdAt: { $gte: from, $lte: to }, name: { $in: ["view_product", "add_to_bag", "checkout_start", "paid"] } } },
        { $group: { _id: "$name", n: { $sum: 1 }, visitors: { $addToSet: "$visitor" } } },
      ]).toArray(),
      d.collection("orders").aggregate([
        { $match: rangeMatch },
        { $group: { _id: "$email", orders: { $sum: 1 }, first: { $min: "$createdAt" } } },
      ]).toArray(),
      d.collection("orders").aggregate([
        { $match: { createdAt: { $lt: from } } },
        { $group: { _id: "$email" } },
      ]).toArray(),
      d.collection("analyticsEvents").aggregate([
        { $match: { createdAt: { $gte: from, $lte: to }, name: "add_to_bag" } },
        { $group: { _id: "$visitor", at: { $max: "$createdAt" } } },
      ]).toArray(),
      d.collection("analyticsEvents").aggregate([
        { $match: { createdAt: { $gte: from, $lte: to }, name: "checkout_start" } },
        { $group: { _id: "$visitor", at: { $max: "$createdAt" } } },
      ]).toArray(),
    ]);

    const funnel = {};
    funnelRows.forEach((r) => { funnel[r._id] = { count: r.n, visitors: r.visitors.length }; });
    ["view_product", "add_to_bag", "checkout_start", "paid"].forEach((k) => {
      if (!funnel[k]) funnel[k] = { count: 0, visitors: 0 };
    });

    /* new vs returning: a customer whose FIRST-EVER order sits inside the
       window is new; anyone who already ordered before the window is back */
    const earlier = new Set(earlierEmails.map((r) => r._id).filter(Boolean));
    let newCount = 0;
    let returningCount = 0;
    emailsInRange.forEach((r) => {
      if (!r._id) return;
      if (earlier.has(r._id)) returningCount++;
      else if (r.first && r.first >= from && r.first <= to) newCount++;
    });

    /* abandoned carts — only what the first-party funnel can honestly see:
       visitors whose checkout_start never turned into a verified payment,
       and baggers who never reached checkout. Anonymous, no profiles. */
    const paidVisitorSet = new Set(
      (await d.collection("analyticsEvents").find(
        { name: "paid", createdAt: { $gte: from } }, { projection: { visitor: 1 } }
      ).toArray()).map((r) => r.visitor)
    );
    const checkoutAbandoned = checkoutEvents.filter((r) => !paidVisitorSet.has(r._id)).length;
    const checkoutVisitorSet = new Set(checkoutEvents.map((r) => r._id));
    const bagAbandoned = bagEvents.filter((r) => !checkoutVisitorSet.has(r._id)).length;

    const salesCentavos = (salesAgg[0] && salesAgg[0].total) || 0;
    const paidCount = paidOrders;
    const dailyMap = {};
    dailyRows.forEach((r) => { dailyMap[r._id] = { revenueCentavos: r.revenue, orders: r.orders }; });
    /* fill the calendar so the chart never lies with gaps */
    const daily = [];
    const dayCount = Math.min(120, Math.max(1, Math.ceil((to - from) / 86400000)));
    for (let i = dayCount - 1; i >= 0; i--) {
      const key = manilaDayKey(new Date(to.getTime() - i * 86400000));
      daily.push({ day: key, revenueCentavos: (dailyMap[key] && dailyMap[key].revenueCentavos) || 0, orders: (dailyMap[key] && dailyMap[key].orders) || 0 });
    }

    return send(res, 200, {
      ok: true,
      range: { from: from.toISOString(), to: to.toISOString(), days: Math.round((to - from) / 86400000) },
      totals: {
        salesCentavos,
        paidOrders: paidCount,
        ordersPlaced,
        aovCentavos: paidCount > 0 ? Math.round(salesCentavos / paidCount) : 0,
      },
      conversion: {
        checkoutToPaidPct: funnel.checkout_start.count > 0 ? Math.round(100 * funnel.paid.count / funnel.checkout_start.count) : null,
        bagToCheckoutPct: funnel.add_to_bag.count > 0 ? Math.round(100 * funnel.checkout_start.count / funnel.add_to_bag.count) : null,
      },
      funnel,
      daily,
      bestSellers: bestRows.map((r) => ({ productId: r._id, name: (r.name || r._id || "").toUpperCase(), units: r.units, revenueCentavos: r.revenue })),
      popular: viewRows.map((r) => ({ productId: r._id || "(home)", views: r.views })),
      customers: { newCount, returningCount },
      abandoned: {
        checkoutAbandoned,
        bagAbandoned,
        note: "FIRST-PARTY FUNNEL ONLY — VISITORS WHO STARTED CHECKOUT WITHOUT A VERIFIED PAYMENT, AND BAGS THAT NEVER REACHED CHECKOUT. NO COOKIES, NO PROFILES.",
      },
    });
  } catch (err) {
    return mongoError(res, err, "analytics failed");
  }
}

/* --------------------------------------------------------------- */
/* PRODUCT VISIBILITY + RESTORE — pull a piece off one surface or    */
/* every surface without touching the record, the orders or the     */
/* inventory history. Restoring flips it back. Both log themselves. */
/* --------------------------------------------------------------- */

async function handleAdminProductVisibility(req, res) {
  const found = await userFromReq(req).catch(() => null);
  if (!found) return fail(res, 401, "unauthorized", "LOG IN TO CONTINUE.");
  if (found.user.role !== "admin") return fail(res, 403, "forbidden", "ADMIN ONLY.");
  const body = await readBody(req, res, 20000);
  if (body === null) return;
  if (body === undefined) return fail(res, 400, "bad_request", "MALFORMED REQUEST BODY.");
  const id = String(body.id ?? "").trim();
  if (!id) return fail(res, 422, "invalid", "MISSING PIECE ID.");
  const vis = normalizeVisibility(body);
  try {
    const { connect } = require("./ipc-pay/mongo");
    const d = await connect();
    const baked = PRODUCTS.some((x) => x.id === id);
    const custom = baked ? null : await d.collection("products").findOne({ id });
    if (!baked && !custom) return fail(res, 404, "not_found", "THAT PIECE ISN'T IN THE SAVED CATALOG.");
    const now = new Date();
    await d.collection("productVisibility").updateOne(
      { id },
      { $set: { ...vis, updatedAt: now, updatedBy: found.user.email }, $setOnInsert: { id, createdAt: now } },
      { upsert: true }
    );
    const label = baked ? id.toUpperCase() : (custom.name || id).toUpperCase();
    const surfaces = ["shop", "gallery", "collection"].map((s) =>
      s.toUpperCase() + " " + (vis[s + "Visible"] ? "ON" : "OFF")).join(" · ");
    await logActivity(d, found.user.email, "product_visibility", "product", id, label,
      isFullyHidden(vis) ? "HIDDEN EVERYWHERE — " + surfaces : surfaces);
    return send(res, 200, {
      ok: true,
      visibility: vis,
      hidden: isFullyHidden(vis),
      message: isFullyHidden(vis)
        ? "PIECE HIDDEN FROM EVERY SURFACE — THE RECORD AND ITS HISTORY STAY PUT."
        : "VISIBILITY SAVED — THE PUBLIC SITE PICKS IT UP ON THE NEXT LOAD.",
    });
  } catch (err) {
    return mongoError(res, err, "visibility save failed");
  }
}

async function handleAdminProductRestore(req, res) {
  const found = await userFromReq(req).catch(() => null);
  if (!found) return fail(res, 401, "unauthorized", "LOG IN TO CONTINUE.");
  if (found.user.role !== "admin") return fail(res, 403, "forbidden", "ADMIN ONLY.");
  const body = await readBody(req, res, 20000);
  if (body === null) return;
  if (body === undefined) return fail(res, 400, "bad_request", "MALFORMED REQUEST BODY.");
  const id = String(body.id ?? "").trim();
  if (!id) return fail(res, 422, "invalid", "MISSING PIECE ID.");
  try {
    const { connect } = require("./ipc-pay/mongo");
    const d = await connect();
    const custom = await d.collection("products").findOne({ id });
    /* archived core pieces restore here too — archive only hides, it
       never deletes, so the club can bring a piece back any time */
    if (!custom && PRODUCTS.some((x) => x.id === id)) {
      const meta = await productMetaMap(d);
      const m = meta[id] || {};
      if (m.archived !== true) return fail(res, 422, "not_archived", "THAT PIECE ISN'T ARCHIVED — IT'S ALREADY LIVE.");
      await d.collection("productMeta").updateOne(
        { id },
        { $set: { id, archived: false, updatedAt: new Date(), updatedBy: found.user.email }, $setOnInsert: { createdAt: new Date() } },
        { upsert: true }
      );
      bakedMetaCache = { at: 0, map: null };
      await logActivity(d, found.user.email, "product_restore", "product", id, id.toUpperCase(),
        "ARCHIVED PIECE RESTORED — BACK ON ITS SURFACES AND THE INVENTORY LIST");
      return send(res, 200, { ok: true, message: "PIECE RESTORED — IT'S BACK ON THE SHOP AND ITS COLLECTION." });
    }
    if (!custom) return fail(res, 404, "not_found", "RESTORE WORKS ON CLUB-ADDED PIECES — BAKED PIECES NEVER LEAVE THE CATALOG.");
    if (custom.active !== false) return fail(res, 422, "not_pulled", "THAT PIECE IS ALREADY LIVE.");
    await d.collection("products").updateOne(
      { id }, { $set: { active: true, updatedAt: new Date() } }
    );
    await logActivity(d, found.user.email, "product_restore", "product", id,
      (custom.name || id).toUpperCase(), "PULLED PIECE RESTORED — BACK ON THE SHOP");
    return send(res, 200, { ok: true, message: "PIECE RESTORED — IT'S BACK ON THE SHOP AND ITS COLLECTION." });
  } catch (err) {
    return mongoError(res, err, "product restore failed");
  }
}

/* --------------------------------------------------------------- */
/* SUPPORT TICKETS — customers raise issues against their account    */
/* (optionally against one of their own orders), the club answers    */
/* with a status. Conversations stay private: a member can only ever */
/* read their own tickets; admin routes check the role every time.   */
/* --------------------------------------------------------------- */

async function handleSupportCreate(req, res, ip) {
  const found = await userFromReq(req).catch(() => null);
  if (!found) return fail(res, 401, "unauthorized", "LOG IN TO OPEN A TICKET — THE CLUB ANSWERS INSIDE YOUR ACCOUNT.");
  if (rateLimited(ip, 12, 10 * 60 * 1000, "support")) {
    return fail(res, 429, "rate_limited", "A FEW TOO MANY TICKETS IN A ROW — GIVE IT TEN MINUTES.");
  }
  const body = await readBody(req, res, 20000);
  if (body === null) return;
  if (body === undefined) return fail(res, 400, "bad_request", "MALFORMED REQUEST BODY.");
  const subject = cleanSupportText(body.subject, 120);
  const category = SUPPORT_CATEGORIES.includes(body.category) ? body.category : "other";
  const message = cleanSupportText(body.message, 4000);
  const orderReference = cleanSupportText(body.orderReference, 40).toUpperCase();
  if (subject.length < 4) return fail(res, 422, "invalid", "GIVE THE TICKET A SUBJECT — AT LEAST 4 CHARACTERS.");
  if (message.length < 10) return fail(res, 422, "invalid", "TELL THE CLUB WHAT HAPPENED — AT LEAST 10 CHARACTERS.");
  try {
    const { connect } = require("./ipc-pay/mongo");
    const d = await connect();
    if (orderReference) {
      const order = await d.collection("orders").findOne({ reference: orderReference });
      if (!order) return fail(res, 422, "invalid", "NO ORDER WITH THAT REFERENCE — LEAVE IT BLANK OR CHECK THE NUMBER.");
      const mine = (order.userId && String(order.userId) === String(found.user._id)) ||
        String(order.email || "").toLowerCase() === found.user.email;
      if (!mine) return fail(res, 403, "forbidden", "THAT ORDER ISN'T YOURS — PICK ONE FROM YOUR OWN HISTORY.");
    }
    const now = new Date();
    const id = "tkt-" + Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
    let ref = await nextReference("ticket").catch(() => null);
    const doc = {
      id,
      ...(ref ? { ref } : {}),
      userId: found.user._id,
      email: found.user.email,
      orderReference: orderReference || null,
      subject,
      category,
      message,
      status: "open",
      replies: [],
      customerUnread: false,
      createdAt: now,
      updatedAt: now,
    };
    await d.collection("supportTickets").insertOne(doc);
    console.log("[ipc-pay] support ticket " + id + " opened by " + found.user.email);
    return send(res, 201, { ok: true, ticket: supportTicketView(doc), message: "TICKET OPENED — THE CLUB ANSWERS HERE IN YOUR ACCOUNT." });
  } catch (err) {
    return mongoError(res, err, "support ticket failed");
  }
}

async function handleSupportMine(req, res) {
  const found = await userFromReq(req).catch(() => null);
  if (!found) return fail(res, 401, "unauthorized", "LOG IN TO SEE YOUR TICKETS.");
  try {
    const { connect } = require("./ipc-pay/mongo");
    const d = await connect();
    /* closed conversations file out of the member's account view — the
       record stays in the database, the list stays clean */
    const rows = await d.collection("supportTickets")
      .find({ userId: found.user._id, status: { $ne: "closed" } }).sort({ updatedAt: -1 }).limit(100).toArray();
    const unread = rows.filter((r) => r.customerUnread).length;
    return send(res, 200, { ok: true, tickets: rows.map(supportTicketView), unread });
  } catch (err) {
    return mongoError(res, err, "support history failed");
  }
}

async function handleSupportReply(req, res) {
  const found = await userFromReq(req).catch(() => null);
  if (!found) return fail(res, 401, "unauthorized", "LOG IN TO CONTINUE.");
  const body = await readBody(req, res, 20000);
  if (body === null) return;
  if (body === undefined) return fail(res, 400, "bad_request", "MALFORMED REQUEST BODY.");
  const id = cleanSupportText(body.id, 60);
  const text = cleanSupportText(body.body, 2000);
  if (!id || text.length < 2) return fail(res, 422, "invalid", "WRITE SOMETHING FOR THE CLUB TO READ.");
  try {
    const { connect } = require("./ipc-pay/mongo");
    const d = await connect();
    const ticket = await d.collection("supportTickets").findOne({ id });
    if (!ticket || String(ticket.userId) !== String(found.user._id)) {
      return fail(res, 404, "not_found", "NO TICKET OF YOURS WITH THAT ID.");
    }
    const now = new Date();
    /* a member answering a resolved/closed ticket reopens it honestly */
    const reopen = ticket.status === "resolved" || ticket.status === "closed";
    await d.collection("supportTickets").updateOne(
      { id },
      { $set: {
        status: reopen ? "open" : ticket.status,
        updatedAt: now,
      }, $push: { replies: { by: "customer", author: found.user.email, body: text, at: now } } }
    );
    return send(res, 200, { ok: true, message: "REPLY SENT — THE CLUB SEES IT IN THE SUPPORT QUEUE." });
  } catch (err) {
    return mongoError(res, err, "support reply failed");
  }
}

async function handleSupportRead(req, res) {
  const found = await userFromReq(req).catch(() => null);
  if (!found) return fail(res, 401, "unauthorized", "LOG IN TO CONTINUE.");
  const body = await readBody(req, res, 20000);
  if (body === null) return;
  const id = cleanSupportText((body || {}).id, 60);
  if (!id) return send(res, 200, { ok: true });
  try {
    const { connect } = require("./ipc-pay/mongo");
    const d = await connect();
    await d.collection("supportTickets").updateOne(
      { id, userId: found.user._id },
      { $set: { customerUnread: false, customerReadAt: new Date() } }
    );
    return send(res, 200, { ok: true });
  } catch {
    return send(res, 200, { ok: true });
  }
}

async function handleAdminSupport(req, res) {
  const found = await userFromReq(req).catch(() => null);
  if (!found) return fail(res, 401, "unauthorized", "LOG IN TO CONTINUE.");
  if (found.user.role !== "admin") return fail(res, 403, "forbidden", "ADMIN ONLY.");
  try {
    const { connect } = require("./ipc-pay/mongo");
    const d = await connect();
    /* closed tickets leave the desk the moment they close — the record
       lives on in the database and the activity log, not on this screen */
    const rows = await d.collection("supportTickets")
      .find({ status: { $ne: "closed" } }).sort({ updatedAt: -1 }).limit(200).toArray();
    const counts = { open: 0, in_progress: 0, resolved: 0 };
    rows.forEach((r) => { if (counts[r.status] !== undefined) counts[r.status]++; });
    return send(res, 200, { ok: true, tickets: rows.map(supportTicketView), counts });
  } catch (err) {
    return mongoError(res, err, "admin support failed");
  }
}

async function handleAdminSupportReply(req, res) {
  const found = await userFromReq(req).catch(() => null);
  if (!found) return fail(res, 401, "unauthorized", "LOG IN TO CONTINUE.");
  if (found.user.role !== "admin") return fail(res, 403, "forbidden", "ADMIN ONLY.");
  const body = await readBody(req, res, 20000);
  if (body === null) return;
  if (body === undefined) return fail(res, 400, "bad_request", "MALFORMED REQUEST BODY.");
  const id = cleanSupportText(body.id, 60);
  const text = cleanSupportText(body.body, 4000);
  const status = SUPPORT_STATUSES.includes(body.status) ? body.status : null;
  if (!id || text.length < 2) return fail(res, 422, "invalid", "WRITE THE CLUB'S ANSWER FIRST.");
  try {
    const { connect } = require("./ipc-pay/mongo");
    const d = await connect();
    const ticket = await d.collection("supportTickets").findOne({ id });
    if (!ticket) return fail(res, 404, "not_found", "NO TICKET WITH THAT ID.");
    const now = new Date();
    const nextStatus = status || (ticket.status === "open" ? "in_progress" : ticket.status);
    await d.collection("supportTickets").updateOne(
      { id },
      { $set: {
        status: nextStatus,
        customerUnread: true,
        updatedAt: now,
      }, $push: { replies: { by: "admin", author: found.user.email, body: text, at: now } } }
    );
    await logActivity(d, found.user.email, "support_reply", "support", id,
      "TICKET " + (ticket.ref || id.toUpperCase()),
      "REPLIED · STATUS → " + nextStatus.toUpperCase().replace("_", " "));
    return send(res, 200, { ok: true, status: nextStatus, message: "ANSWER SENT — THE MEMBER SEES IT IN THEIR ACCOUNT." });
  } catch (err) {
    return mongoError(res, err, "admin support reply failed");
  }
}

async function handleAdminSupportStatus(req, res) {
  const found = await userFromReq(req).catch(() => null);
  if (!found) return fail(res, 401, "unauthorized", "LOG IN TO CONTINUE.");
  if (found.user.role !== "admin") return fail(res, 403, "forbidden", "ADMIN ONLY.");
  const body = await readBody(req, res, 20000);
  if (body === null) return;
  if (body === undefined) return fail(res, 400, "bad_request", "MALFORMED REQUEST BODY.");
  const id = cleanSupportText(body.id, 60);
  if (!SUPPORT_STATUSES.includes(body.status)) {
    return fail(res, 422, "invalid", "STATUS MUST BE open, in_progress, resolved OR closed.");
  }
  try {
    const { connect } = require("./ipc-pay/mongo");
    const d = await connect();
    const ticket = await d.collection("supportTickets").findOne({ id });
    if (!ticket) return fail(res, 404, "not_found", "NO TICKET WITH THAT ID.");
    await d.collection("supportTickets").updateOne(
      { id },
      { $set: { status: body.status, customerUnread: true, updatedAt: new Date() } }
    );
    await logActivity(d, found.user.email, "support_status", "support", id,
      "TICKET " + (ticket.ref || id.toUpperCase()),
      "STATUS " + ticket.status.toUpperCase().replace("_", " ") + " → " + body.status.toUpperCase().replace("_", " "));
    return send(res, 200, { ok: true, status: body.status, message: "STATUS SAVED — THE MEMBER IS NOTIFIED IN THEIR ACCOUNT." });
  } catch (err) {
    return mongoError(res, err, "admin support status failed");
  }
}

server.listen(PORT, () => {
  console.log("IPC contact API listening on port " + PORT);
  /* Seed the admin account + indexes in the background — the contact
     relay keeps working even if MONGODB_URI isn't set yet. */
  initDatabase()
    .then(() => console.log("[ipc-pay] MongoDB Atlas ready — accounts online."))
    .catch((err) => {
      if (err && err.code === "MONGO_NOT_CONFIGURED") {
        console.log("[ipc-pay] MONGODB_URI not set — contact relay only, accounts offline.");
      } else {
        console.error("[ipc-pay] Mongo init failed:", err && err.message);
        const hints = (err && err.hints && err.hints.length) ? err.hints : (typeof uriHints === "function" ? uriHints(process.env.MONGODB_URI) : []);
        hints.forEach((h) => console.error("[ipc-pay] FIX: " + h));
      }
    });
});