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
 *   POST /api/auth/login           → { email, password }
 *   POST /api/auth/logout          → (Bearer token)
 *   GET  /api/auth/me              → (Bearer token) profile + role
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
  initDatabase, checkConnection,
  createSession, findSession, deleteSession,
  findUserByEmail, findUserById, insertUser,
  nextReference,
} = require("./ipc-pay/mongo");

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

/* --------------------------------------------------------------- */
/* Product catalog — the server ALWAYS recomputes totals from this,  */
/* the client never names its own price. Money = integer centavos.   */
/* --------------------------------------------------------------- */

const PRODUCTS = [
  { id: "hoodie-001",   name: "CLUB HOODIE 001",    priceCentavos: 145000, sizes: ["S","M","L","XL"],   colors: ["WASHED BLACK"] },
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
    const html = fs.readFileSync(INDEX_FILE);
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
        req.destroy();
      }
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
  return { id: String(u._id), email: u.email, name: u.name, role: u.role };
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
    items: o.items,
    subtotalCentavos: o.subtotalCentavos,
    shippingCentavos: o.shippingCentavos,
    totalCentavos: o.totalCentavos,
    status: o.status,
    createdAt: o.createdAt,
    payment: payment ? {
      paymentReference: payment.paymentReference,
      status: payment.status,
      refNo: payment.refNo || null,
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
      city: order.city,
      province: order.province,
      items: order.items,
      subtotalCentavos: order.subtotalCentavos,
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
          return send(res, status, {
            ok: false,
            database: "unavailable",
            reason: err.code || "MONGO_REQUEST_FAILED",
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
      return send(res, 200, { ok: true, user: publicUser(found.user) });
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
          ok: true,
          orders: orders.map((o) => orderView(o, byOrder.get(o.reference))),
        });
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
        p === "/api/admin/orders" || p === "/api/admin/users") {
      const found = await userFromReq(req).catch(() => null);
      if (!found) return fail(res, 401, "unauthorized", "LOG IN TO CONTINUE.");
      if (found.user.role !== "admin") {
        return fail(res, 403, "forbidden", "ADMIN ONLY — THIS AREA IS FOR THE CLUB ADMINS.");
      }
      try {
        const { connect } = require("./ipc-pay/mongo");
        const d = await connect();
        if (p === "/api/admin/overview") {
          const [users, orders, payments, paidAgg] = await Promise.all([
            d.collection("users").countDocuments(),
            d.collection("orders").countDocuments(),
            d.collection("payments").aggregate([
              { $group: { _id: "$status", n: { $sum: 1 } } },
            ]).toArray(),
            d.collection("payments").aggregate([
              { $match: { status: "paid" } },
              { $group: { _id: null, total: { $sum: "$amountCentavos" } } },
            ]).toArray(),
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
            },
          });
        }
        if (p === "/api/admin/payments") {
          const pays = await d.collection("payments")
            .find({ status: { $in: ["under_verification", "pending"] } })
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
        /* /api/admin/users */
        const us = await d.collection("users")
          .find({}, { projection: { email: 1, name: 1, role: 1, createdAt: 1 } })
          .sort({ createdAt: -1 }).limit(500).toArray();
        return send(res, 200, {
          ok: true,
          users: us.map((u) => ({
            email: u.email, name: u.name, role: u.role, createdAt: u.createdAt,
          })),
        });
      } catch (err) {
        return mongoError(res, err, "admin query failed");
      }
    }

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
/* CONTACT RELAY — behavior preserved exactly                       */
/* --------------------------------------------------------------- */

function handleContact(req, res, ip) {
  if (rateLimited(ip, 5, 60 * 60 * 1000, "contact")) {
    return send(res, 429, { ok: false, reason: "rate_limited" });
  }
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

    /* honeypot — bots get a fake success so they move on */
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

    const publicKey = process.env.EMAILJS_PUBLIC_KEY || "";
    const serviceId = process.env.EMAILJS_SERVICE_ID || "";
    const templateId = process.env.EMAILJS_TEMPLATE_ID || "";
    if (!publicKey || !serviceId || !templateId) {
      return send(res, 503, { ok: false, reason: "not_configured" });
    }

    try {
      const r = await fetch(EMAILJS_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          service_id: serviceId,
          template_id: templateId,
          user_id: publicKey,
          template_params: {
            from_name: fromName,
            reply_to: replyTo,
            message: message,
            sent_at: sentAt || new Date().toLocaleString("en-PH"),
          },
        }),
        signal: AbortSignal.timeout(15000),
      });
      if (!r.ok) throw new Error("emailjs responded " + r.status);
      return send(res, 200, { ok: true });
    } catch (err) {
      console.error("relay failed:", err.message);
      return send(res, 502, { ok: false, reason: "send_failed" });
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
      const user = await insertUser({ email, name, password, role: "customer" });
      const token = await createSession(user);
      return send(res, 200, { ok: true, token, user: publicUser(user) });
    }

    /* ---- login ---- */
    if (p === "/api/auth/login") {
      const email = String(body.email ?? "").trim().toLowerCase().slice(0, 120);
      const password = String(body.password ?? "");
      const user = await findUserByEmail(email);
      const { verifyPassword } = require("./ipc-pay/mongo");
      if (!user || !verifyPassword(password, user.salt, user.hash)) {
        return fail(res, 401, "bad_credentials", "WRONG EMAIL OR PASSWORD.");
      }
      const token = await createSession(user);
      return send(res, 200, { ok: true, token, user: publicUser(user) });
    }

    /* ---- logout ---- */
    const token = bearerToken(req);
    if (token) await deleteSession(token);
    return send(res, 200, { ok: true });
  } catch (err) {
    return mongoError(res, err, "auth failed");
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
  for (const raw of rawItems) {
    const product = PRODUCTS.find((x) => x.id === String(raw.productId ?? ""));
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
  const totalCentavos = subtotalCentavos + SHIPPING_CENTAVOS;

  const c = body.customer ?? {};
  const name = String(c.name ?? "").trim().slice(0, 120);
  const phone = String(c.phone ?? "").trim().slice(0, 40);
  const addressLine = String(c.addressLine ?? "").trim().slice(0, 240);
  const city = String(c.city ?? "").trim().slice(0, 80);
  const province = String(c.province ?? "").trim().slice(0, 80);
  const postalCode = String(c.postalCode ?? "").trim().slice(0, 12);
  const notes = String(c.notes ?? "").trim().slice(0, 400);
  if (!name || !phone || !addressLine || !city || !province) {
    return fail(res, 422, "invalid", "COMPLETE THE DELIVERY DETAILS BEFORE PLACING THE ORDER.");
  }

  try {
    const { connect } = require("./ipc-pay/mongo");
    const d = await connect();
    const reference = await nextReference("order");
    const paymentReference = await nextReference("payment");
    const now = new Date();

    const orderDoc = {
      reference,
      userId: found.user._id,
      email: found.user.email,
      customerName: name,
      phone,
      addressLine,
      city,
      province,
      postalCode,
      notes,
      items: lines,
      subtotalCentavos,
      shippingCentavos: SHIPPING_CENTAVOS,
      totalCentavos,
      status: "awaiting_payment",
      createdAt: now,
      updatedAt: now,
    };
    await d.collection("orders").insertOne(orderDoc);

    const paymentDoc = {
      paymentReference,
      orderReference: reference,
      userId: found.user._id,
      email: found.user.email,
      amountCentavos: totalCentavos,
      currency: "PHP",
      status: "pending",
      method: "qr",
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
      shippingCentavos: SHIPPING_CENTAVOS,
    });
  } catch (err) {
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
    const pay = await d.collection("payments").findOne({ paymentReference: reference });
    if (!pay) return fail(res, 404, "not_found", "NO PAYMENT FOUND FOR THAT REFERENCE.");
    if (String(pay.userId) !== String(found.user._id)) {
      return fail(res, 403, "forbidden", "THIS PAYMENT BELONGS TO ANOTHER ACCOUNT.");
    }
    if (pay.status === "paid") {
      return fail(res, 422, "already_paid", "THIS PAYMENT IS ALREADY VERIFIED AND PAID.");
    }

    const now = new Date();
    await d.collection("payments").updateOne(
      { _id: pay._id },
      {
        $set: {
          refNo,
          status: "under_verification",
          updatedAt: now,
          ...(decoded ? { proofDataUrl: `data:${proofMime};base64,${decoded.toString("base64")}` } : {}),
        },
      }
    );
    await d.collection("orders").updateOne(
      { reference: pay.orderReference },
      { $set: { status: "under_verification", updatedAt: now } }
    );

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

    const now = new Date();
    const newStatus = action === "approve" ? "paid" : "failed";
    await d.collection("payments").updateOne(
      { _id: pay._id },
      { $set: { status: newStatus, updatedAt: now, verifiedAt: now, reviewedBy: found.user.email } }
    );
    await d.collection("orders").updateOne(
      { reference: pay.orderReference },
      { $set: { status: newStatus, updatedAt: now } }
    );

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
      }
    });
});
