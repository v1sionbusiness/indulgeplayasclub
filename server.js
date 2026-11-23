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
 *   GET  /api/admin/users          → (Bearer admin)
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
const SHIPPING_CENTAVOS = 0; /* Free at checkout — courier coverage depends on the
   member's location (see T&C 04); where a courier can't reach, the club sorts
   a Metro Manila meetup first. */

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
const BUILD_STAMP = "ipc-v22-20261123-productmeta";
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
      const meta = BAKED_META[pid] || {};
      finish(injectProductMeta(html, pid, {
        name: baked.name,
        blurb: meta.blurb,
        img: meta.img,
        priceCentavos: baked.priceCentavos,
      }));
      return true;
    }

    (async function () {
      let info = null;
      try {
        const { connect } = require("./ipc-pay/mongo");
        const d = await connect();
        const doc = await d.collection("products")
          .findOne({ id: pid, active: { $ne: false } });
        if (doc) info = {
          name: doc.name,
          blurb: doc.desc || doc.alt || doc.name,
          img: doc.img,
          priceCentavos: doc.priceCentavos,
        };
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
  /* /p/<id>, /collection/<slug>, /pay/<ref>, /track/<ref> */
  return (seg.length === 2 && ["p", "collection", "pay", "track"].includes(seg[0]));
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
  return { id: String(u._id), email: u.email, name: u.name, phone: u.phone || "", role: u.role, createdAt: u.createdAt };
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
  if (includeProof) out.proofDataUrl = p.proofDataUrl || null;
  else out.proofPresent = Boolean(p.proofDataUrl);
  if (order) {
    out.order = {
      reference: order.reference,
      customerName: order.customerName,
      email: order.email,
      phone: order.phone || "",
      addressLine: order.addressLine || "",
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

/** IPC PAY AUTO READER — actually READS the screenshot a member submits.
    A proof is only auto-approved when the OCR finds ALL THREE of:
      (1) a Maya/PayMaya marker in the screenshot,
      (2) the exact order amount as a money figure,
      (3) the Maya transaction reference the member typed in.
    Anything else stays UNDER VERIFICATION for a human decision — a blurry
    screenshot can never fail a customer, and a wrong screenshot can never
    pass one. Reference-only claims never enter this path. The CAS guard
    means the reader can never override an admin decision that lands
    meanwhile. Runs in the background; on any error the payment simply
    stays under_verification for manual review. */
let __ocrWorker = null;
async function getOcrWorker() {
  if (__ocrWorker) return __ocrWorker;
  const { createWorker } = require("tesseract.js");
  __ocrWorker = await createWorker("eng", 1, { cachePath: "/tmp/ipc-ocr" });
  return __ocrWorker;
}

/** OCR + strict gates. Never throws: { pass:false, reason } on any problem. */
async function readMayaProof(payment) {
  const summary = { pass: false, mayaOk: false, refOk: false, amountOk: false,
                    nameOk: false, ocrChars: 0, reason: "" };
  try {
    const m = String(payment.proofDataUrl || "").match(/^data:image\/(?:jpeg|jpg|png);base64,([A-Za-z0-9+\/=\s]+)$/);
    if (!m) { summary.reason = "no readable image"; return summary; }
    const buf = Buffer.from(m[1], "base64");
    if (buf.length < 2048) { summary.reason = "image too small to read"; return summary; }

    /* OCR with a hard timeout — a slow reader falls back to manual review */
    const work = (async () => {
      try {
        const worker = await getOcrWorker();
        const { data } = await worker.recognize(buf);
        return String((data && data.text) || "");
      } catch (err) {
        try { if (__ocrWorker) await __ocrWorker.terminate(); } catch (e) {}
        __ocrWorker = null;
        throw err;
      }
    })();
    const text = await Promise.race([
      work,
      new Promise((resolve, reject) => setTimeout(() => reject(new Error("ocr timeout")), 45000)),
    ]).catch((err) => { summary.reason = "ocr unavailable: " + (err && err.message); return null; });
    if (text === null) return summary;

    const norm = text.toUpperCase().replace(/\s+/g, " ");
    summary.ocrChars = norm.length;

    /* gate 1 — it has to be a Maya screenshot at all */
    summary.mayaOk = /MAYA|PAYMAYA/.test(norm);

    /* gate 2 — the submitted reference must appear in the screenshot */
    const refNorm = String(payment.refNo || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
    const textNorm = norm.replace(/[^A-Z0-9]/g, "");
    summary.refOk = refNorm.length >= 4 && textNorm.indexOf(refNorm) >= 0;

    /* gate 3 — the exact order amount must appear as a money figure
       (handles 1250.00 / 1,250.00 / P1250 / PHP 1,250.00 forms) */
    const target = Math.round(Number(payment.amountCentavos) || 0);
    if (target > 0) {
      const tokens = norm.match(/(?:\u20b1|PHP|P)?\s?\d{1,3}(?:,\d{3})*(?:\.\d{1,2})?/g) || [];
      for (const t of tokens) {
        const cents = Math.round(parseFloat(t.replace(/[^0-9.]/g, "")) * 100) || 0;
        if (cents === target) { summary.amountOk = true; break; }
      }
    }

    /* extra signal for the admins — the account holder name on the QR */
    summary.nameOk = /CLAUDIO|ANCEL JAMES/.test(norm);

    summary.pass = summary.mayaOk && summary.refOk && summary.amountOk;
    if (!summary.pass && !summary.reason) {
      summary.reason = "mismatch: maya=" + summary.mayaOk + " ref=" + summary.refOk +
                       " amount=" + summary.amountOk;
    }
    return summary;
  } catch (err) {
    summary.reason = "reader error: " + (err && err.message);
    return summary;
  }
}

async function autoVerifyPayment(d, pay) {
  try {
    const settings = await getPaySettings(d);
    if (!settings.autoVerify) return false;

    /* fresh read — the payment may already have been decided by an admin */
    const fresh = await d.collection("payments").findOne({ _id: pay._id });
    if (!fresh || fresh.status !== "under_verification" || !fresh.proofDataUrl || !fresh.refNo) return false;

    /* READ the screenshot — every gate must hold before anything is marked */
    const read = await readMayaProof(fresh);
    console.log("[ipc-pay] AUTO READER read " + fresh.paymentReference +
      " — pass=" + read.pass + " maya=" + read.mayaOk + " ref=" + read.refOk +
      " amount=" + read.amountOk + " name=" + read.nameOk +
      (read.reason ? " (" + read.reason + ")" : ""));
    await d.collection("payments").updateOne(
      { _id: fresh._id },
      { $set: { autoRead: { ...read, at: new Date() } } }
    ).catch(() => {});
    if (!read.pass) return false;   /* stays UNDER VERIFICATION for a human */

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
      const user = publicUser(found.user);
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
        const fresh = await findUserById(user.id);
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
        const d = await connect();
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
        return send(res, 200, {
          ok: true,
          products: docs.map((doc) => productView(doc, soldMap[doc.id] || 0)),
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

    /* ---------------- admin GETs ---------------- */
    if (p === "/api/admin/overview" || p === "/api/admin/payments" ||
        p === "/api/admin/orders" || p === "/api/admin/users" ||
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
          return send(res, 200, {
            ok: true,
            products: docs.map((doc) => ({
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
              createdAt: doc.createdAt,
            })),
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
          const customRows = customDocs.map((doc) => ({
            id: doc.id,
            name: doc.name,
            priceCentavos: doc.priceCentavos,
            tag: doc.tag || "",
            sizes: doc.sizes && doc.sizes.length ? doc.sizes : ["OS"],
            colors: doc.colors || [],
            custom: true,
            active: doc.active !== false,
          }));
          const inventory = PRODUCTS.concat(customRows).map((p) => ({
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
          }));
          return send(res, 200, { ok: true, inventory });
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
        /* /api/admin/users — with per-member join + order stats */
        const [us, paidAgg, allAgg] = await Promise.all([
          d.collection("users")
            .find({}, { projection: { email: 1, name: 1, phone: 1, role: 1, createdAt: 1, status: 1, removedAt: 1 } })
            .sort({ createdAt: -1 }).limit(500).toArray(),
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
          users: us.map((u) => {
            const paid = paidByEmail.get(u.email) || {};
            const all = allByEmail.get(u.email) || {};
            return {
              email: u.email, name: u.name, phone: u.phone || "", role: u.role, createdAt: u.createdAt,
              status: u.status || "active", removedAt: u.removedAt || null,
              tier: tierForPaid(paid.spent || 0),
              orders: all.orders || 0,
              paidOrders: paid.paidOrders || 0,
              spentCentavos: paid.spent || 0,
              lastOrderAt: all.last || null,
            };
          }),
        });
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
  if (p === "/api/admin/products") return handleAdminProductSave(req, res);

  /* --- growth platform: reviews, streets, funnel, config, launch states --- */
  if (p === "/api/reviews") return handleReviewCreate(req, res);
  if (p === "/api/admin/reviews/moderate") return handleAdminReviewModerate(req, res);
  if (p === "/api/admin/streets") return handleAdminStreetAdd(req, res);
  if (p === "/api/admin/streets/remove") return handleAdminStreetRemove(req, res);
  if (p === "/api/analytics/event") return handleAnalyticsEvent(req, res, ip);
  if (p === "/api/admin/config") return handleConfigSet(req, res);
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
  if (subtotalCentavos + SHIPPING_CENTAVOS - discountCentavos < 100) {
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
    return send(res, 200, {
      ok: true,
      code: result.code,
      label: result.voucher.label || result.code,
      subtotalCentavos,
      discountCentavos: result.discountCentavos,
      totalCentavos: Math.max(0, subtotalCentavos + SHIPPING_CENTAVOS - result.discountCentavos),
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
  for (const raw of rawItems) {
    let product = PRODUCTS.find((x) => x.id === String(raw.productId ?? ""));
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
    });
  }

  const subtotalCentavos = lines.reduce((s, l) => s + l.priceCentavos * l.qty, 0);

  const c = body.customer ?? {};
  const name = String(c.name ?? "").trim().slice(0, 120);
  const rawPhone = String(c.phone ?? "").trim().slice(0, 40);
  const addressLine = String(c.addressLine ?? "").trim().slice(0, 240);
  const city = String(c.city ?? "").trim().slice(0, 80);
  const province = String(c.province ?? "").trim().slice(0, 80);
  const postalCode = String(c.postalCode ?? "").trim().slice(0, 12);
  const notes = String(c.notes ?? "").trim().slice(0, 400);
  if (!name || !rawPhone || !addressLine || !city || !province) {
    return fail(res, 422, "invalid", "COMPLETE THE DELIVERY DETAILS BEFORE PLACING THE ORDER.");
  }

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
    const totalCentavos = subtotalCentavos + SHIPPING_CENTAVOS - discountCentavos;
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
      city,
      province,
      postalCode,
      notes,
      items: lines,
      subtotalCentavos,
      discountCentavos,
      voucherCode: voucherResult ? voucherResult.code : null,
      shippingCentavos: SHIPPING_CENTAVOS,
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
      shippingCentavos: SHIPPING_CENTAVOS,
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
    const proofUpdate = await d.collection("payments").updateOne(
      { _id: pay._id, status: { $nin: ["paid", "failed"] } },
      {
        $set: {
          refNo,
          status: "under_verification",
          updatedAt: now,
          proofSubmittedAt: now,
          ...(decoded ? { proofDataUrl: `data:${proofMime};base64,${decoded.toString("base64")}` } : {}),
        },
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

    /* IPC PAY AUTO READER — runs in the background (OCR takes seconds):
       the response stays instant and the payment page's live poll picks up
       the result. Screenshot proofs that do not match the order amount +
       Maya reference simply stay UNDER VERIFICATION for a human decision.
       Reference-only claims are never auto-read at all. */
    if (decoded) {
      const proofDataUrl = "data:" + proofMime + ";base64," + decoded.toString("base64");
      setImmediate(() => {
        autoVerifyPayment(d, { ...pay, proofDataUrl })
          .catch((e) => console.error("[ipc-pay] auto reader crashed (kept for manual review):", e && e.message));
      });
    }

    const orderForEmail = await d.collection("orders").findOne({ reference: pay.orderReference });
    await sendPaymentEmail(pay, orderForEmail, "UNDER VERIFICATION",
      "We received your Maya transaction reference. IPC Pay reads screenshot proofs automatically — anything it can't match confidently goes to the club for a hand check.");
    return send(res, 200, {
      ok: true,
      status: "under_verification",
      message: "PROOF RECEIVED — IPC PAY IS READING YOUR PAYMENT. MOST PROOFS CONFIRM WITHIN MINUTES.",
    });
  } catch (err) {
    return mongoError(res, err, "proof upload failed");
  }
}

/* --------------------------------------------------------------- */
/* ADMIN DECISION — the ONLY path that can mark a payment paid.     */
/* --------------------------------------------------------------- */

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
    if (action === "approve") {
      await ensureTracking(d, pay.orderReference, "IPC TEAM");
      await creditReferralIfAny(d, pay.orderReference);
    }

    if (action === "reject") {
      await d.collection("users").updateOne(
        { _id: pay.userId },
        { $push: { paymentRejections: { $each: [now], $slice: -5 } } }
      );
      const account = await d.collection("users").findOne(
        { _id: pay.userId },
        { projection: { paymentRejections: 1 } }
      );
      const cutoff = now.getTime() - PAYMENT_REJECTION_WINDOW_MS;
      const recentRejections = (account && Array.isArray(account.paymentRejections)
        ? account.paymentRejections : []).filter((stamp) => new Date(stamp).getTime() >= cutoff);
      if (recentRejections.length >= 2) {
        await d.collection("users").updateOne(
          { _id: pay.userId },
          { $set: { paymentCooldownUntil: new Date(now.getTime() + PAYMENT_COOLDOWN_MS) } }
        );
      }
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
        ? "AUTO READER ON — SCREENSHOT PROOFS THAT MATCH THE ORDER ARE VERIFIED WITHOUT A TAP; MISMATCHES GO TO THE QUEUE."
        : "AUTO READER OFF — EVERY PAYMENT NEEDS A MANUAL ADMIN DECISION.",
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
    return send(res, 200, { ok: true, message: "PIECE PULLED FROM THE SHOP — PAST ORDERS STAY ON RECORD." });
  } catch (err) {
    return mongoError(res, err, "product remove failed");
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
    const d = await connect();
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
    const d = await connect();
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
  try {
    const { connect } = require("./ipc-pay/mongo");
    const d = await connect();
    const cfg = await d.collection("settings").findOne({ _id: "club" });
    if (cfg && Number(cfg.usdPhpRate) > 0) usdPhpRate = Number(cfg.usdPhpRate);
  } catch { /* defaults hold */ }
  return send(res, 200, { ok: true, usdPhpRate });
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