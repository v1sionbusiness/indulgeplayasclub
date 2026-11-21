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
 *    submitting proof moves their payment to "under_verification" and
 *    NOTHING on earth auto-approves it: only POST /api/admin/decision,
 *    which requires a logged-in admin account, can mark it paid/failed.
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
const SHIPPING_CENTAVOS = 0; /* FREE nationwide — no minimum spend (see FAQ) */

const PROOF_MAX_BYTES = 5 * 1024 * 1024; /* 5MB decoded */
const PROOF_TYPES = { "image/jpeg": ".jpg", "image/jpg": ".jpg", "image/png": ".png" };

/* --------------------------------------------------------------- */
/* Single-service mode (unchanged)                                  */
/* --------------------------------------------------------------- */

const INDEX_FILE = path.join(__dirname, "index.html");
const HEALTH = { ok: true, service: "indulge playas club — contact api" };

function serveIndex(res) {
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
    html = html.replace(/<\/body>/i, navigationFix + "</body>");

    res.writeHead(200, {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "public, max-age=300",
    });
    res.end(html);
    return true;
  } catch {
    return false; // no index.html here → caller falls back to the health JSON
  }
}

/* --------------------------------------------------------------- */
/* Small helpers                                                    */
/* --------------------------------------------------------------- */

function send(res, status, obj) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    ...CORS,
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
      "ACCOUNT SERVER NOT CONNECTED — SET MONGODB_URI ON THE HOST.");
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
  if (!user) return null;
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
    reviewedBy: p.reviewedBy || null,
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
      createdAt: order.createdAt,
    };
  }
  return out;
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
        .then(() => send(res, 200, { ok: true, database: "connected" }))
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
    if (p === "/" || p === "/index.html") {
      if (serveIndex(res)) return;
      return send(res, 200, HEALTH);
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

    /* --- one payment (owner or admin) --- */
    const payMatch = p.match(/^\/api\/payments\/([A-Za-z0-9-]+)$/);
    if (payMatch) {
      const found = await userFromReq(req).catch(() => null);
      if (!found) return fail(res, 401, "unauthorized", "LOG IN TO CONTINUE.");
      try {
        const { connect } = require("./ipc-pay/mongo");
        const d = await connect();
        const pay = await d.collection("payments")
          .findOne({ paymentReference: payMatch[1].toUpperCase() });
        if (!pay) return fail(res, 404, "not_found", "NO PAYMENT FOUND FOR THAT REFERENCE.");
        const order = await d.collection("orders").findOne({ reference: pay.orderReference });
        const isOwner = String(pay.userId) === String(found.user._id) ||
          (order && String(order.userId) === String(found.user._id));
        if (!isOwner && found.user.role !== "admin") {
          return fail(res, 403, "forbidden", "THIS PAYMENT BELONGS TO ANOTHER ACCOUNT.");
        }
        return send(res, 200, {
          ok: true,
          payment: paymentView(pay, order, found.user.role === "admin"),
        });
      } catch (err) {
        return mongoError(res, err, "payment lookup failed");
      }
    }

    /* ---------------- admin GETs ---------------- */
    if (p === "/api/admin/overview" || p === "/api/admin/payments" ||
        p === "/api/admin/orders" || p === "/api/admin/users" ||
        p === "/api/admin/vouchers") {
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
        if (p === "/api/admin/overview") {
          const [users, orders, payments, paidAgg, underAgg, activeVouchers, voucherRedemptions] = await Promise.all([
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
          ]);
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
            .find({}, { projection: { email: 1, name: 1, phone: 1, role: 1, createdAt: 1 } })
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

  /* --- admin role management: 20KB --- */
  if (p === "/api/admin/role") return handleAdminRole(req, res);

  /* --- voucher validation + admin voucher management: 20KB --- */
  if (p === "/api/vouchers/validate") return handleValidateVoucher(req, res);
  if (p === "/api/admin/vouchers") return handleAdminVoucherCreate(req, res);
  if (p === "/api/admin/vouchers/toggle") return handleAdminVoucherToggle(req, res);

  /* --- orders: 20KB --- */
  if (p === "/api/orders") return handleCreateOrder(req, res);

  /* --- proof upload: the ONE route allowed a big body (8MB covers a
         5MB image after base64 inflation) --- */
  if (p === "/api/payments/proof") return handleProof(req, res);

  /* --- admin decision: 20KB --- */
  if (p === "/api/admin/decision") return handleDecision(req, res);

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
      /* Send the IPC inbox notification first. This is the primary success
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
      if (!name) return fail(res, 422, "invalid", "DROP YOUR NAME TO JOIN THE CLUB.");
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return fail(res, 422, "invalid", "THAT EMAIL DOESN'T LOOK RIGHT.");
      }
      if (password.length < 8 || password.length > 72) {
        return fail(res, 422, "invalid", "PASSWORD NEEDS AT LEAST 8 CHARACTERS.");
      }
      const existing = await findUserByEmail(email);
      if (existing) {
        return fail(res, 409, "email_taken", "EMAIL ALREADY REGISTERED — LOG IN INSTEAD.");
      }
      const { connect } = require("./ipc-pay/mongo");
      const d = await connect();
      const phoneOwner = await d.collection("users").findOne({ phone });
      if (phoneOwner) {
        return fail(res, 409, "phone_taken", "THIS MOBILE NUMBER IS ALREADY LINKED TO AN IPC ACCOUNT. LOG IN INSTEAD.");
      }
      const user = await insertUser({ email, name, password, phone, role: "customer" });
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
   account (ADMIN_EMAIL) can never be demoted. */
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
    if (root && email === root && role !== "admin") {
      return fail(res, 403, "root_admin", "THE CLUB OWNER ACCOUNT STAYS ADMIN.");
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
  if (!found) return fail(res, 401, "unauthorized", "LOG IN TO CHECK OUT.");
  const body = await readBody(req, res, 20000);
  if (body === null) return;
  if (body === undefined) return fail(res, 400, "bad_request", "MALFORMED REQUEST BODY.");

  const rawItems = Array.isArray(body.items) ? body.items : [];
  if (rawItems.length === 0) {
    return fail(res, 422, "empty_bag", "YOUR BAG IS EMPTY — ADD A PIECE BEFORE CHECKING OUT.");
  }
  if (rawItems.length > 30) {
    return fail(res, 422, "invalid", "TOO MANY LINES IN ONE ORDER — SPLIT IT UP.");
  }
  const lines = [];
  for (const raw of rawItems) {    const product = PRODUCTS.find((x) => x.id === String(raw.productId ?? ""));
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
    const cooldownSeconds = await paymentCooldownSeconds(d, found.user._id);
    if (cooldownSeconds > 0) return rejectPaymentDuringCooldown(res, cooldownSeconds);
    const phone = await linkAccountPhone(d, found.user, rawPhone);
    const reference = await nextReference("order");
    const paymentReference = await nextReference("payment");
    const now = new Date();
    const voucherCodeInput = String(body.voucherCode || "").trim();
    let voucherResult = null;
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
      userId: found.user._id,
      email: found.user.email,
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
      userId: found.user._id,
      email: found.user.email,
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
  const found = await userFromReq(req).catch(() => null);
  if (!found) return fail(res, 401, "unauthorized", "LOG IN TO CONTINUE.");

  const body = await readBody(req, res, 8 * 1024 * 1024);
  if (body === null) return; // oversize → socket destroyed
  if (body === undefined) return fail(res, 400, "bad_request", "MALFORMED UPLOAD — SEND THE FORM AGAIN.");

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
    const cooldownSeconds = await paymentCooldownSeconds(d, found.user._id);
    if (cooldownSeconds > 0) return rejectPaymentDuringCooldown(res, cooldownSeconds);
    const pay = await d.collection("payments").findOne({ paymentReference: reference });
    if (!pay) return fail(res, 404, "not_found", "NO PAYMENT FOUND FOR THAT REFERENCE.");
    if (String(pay.userId) !== String(found.user._id)) {
      return fail(res, 403, "forbidden", "THIS PAYMENT BELONGS TO ANOTHER ACCOUNT.");
    }
    if (pay.status === "paid") {
      return fail(res, 422, "already_paid", "THIS PAYMENT IS ALREADY VERIFIED AND PAID.");
    }

    /* A Maya transaction reference must not be reused for another IPC order. */
    const duplicateRef = await d.collection("payments").findOne({
      refNo,
      _id: { $ne: pay._id },
    });
    if (duplicateRef) {
      return fail(res, 409, "duplicate_reference",
        "THAT MAYA TRANSACTION REFERENCE HAS ALREADY BEEN SUBMITTED FOR ANOTHER ORDER.");
    }

    const now = new Date();
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

    const orderForEmail = await d.collection("orders").findOne({ reference: pay.orderReference });
    await sendPaymentEmail(pay, orderForEmail, "UNDER VERIFICATION",
      "We received your Maya transaction reference. The club will verify it against its Maya account. This is not yet a paid confirmation.");
    return send(res, 200, {
      ok: true,
      status: "under_verification",
      message: "PROOF RECEIVED — IPC PAY IS VERIFYING YOUR PAYMENT.",
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