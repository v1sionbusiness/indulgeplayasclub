"use strict";
/*
 * INDULGE PLAYAS CLUB — contact API
 * ---------------------------------
 * Tiny zero-dependency Node server that relays "SEND US A MESSAGE" form
 * posts to EmailJS. Deploy it on Render (free plan works) and keep the three
 * EmailJS values in Render's Environment settings — they are never written
 * into this file, so nothing secret is ever pushed to GitHub.
 *
 * Environment variables (Render dashboard → your service → Environment):
 *   EMAILJS_PUBLIC_KEY    — EmailJS Account → API keys → Public Key
 *   EMAILJS_SERVICE_ID    — service_…
 *   EMAILJS_TEMPLATE_ID   — template_…
 *
 * Endpoints:
 *   GET  /              → { ok: true } (health check)
 *   POST /api/contact   → relays { from_name, reply_to, message } to EmailJS
 *   POST /contact       → same as /api/contact
 *
 * The club email address is set ONCE in the EmailJS template ("To Email"),
 * never in code, never on the website.
 */

const http = require("node:http");

const PORT = process.env.PORT || 3000;
const EMAILJS_URL = "https://api.emailjs.com/api/v1.0/email/send";

/* The GitHub-Pages site lives on another origin, so allow its POSTs. */
const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

/* Tiny in-memory rate limit — 5 messages per IP per hour. */
const hits = new Map();
const RATE_LIMIT = 5;
const RATE_WINDOW = 60 * 60 * 1000;

function rateLimited(ip) {
  const now = Date.now();
  const list = (hits.get(ip) || []).filter((t) => now - t < RATE_WINDOW);
  if (list.length >= RATE_LIMIT) return true;
  list.push(now);
  hits.set(ip, list);
  if (hits.size > 500) hits.clear(); // crude cleanup — fine for a club site
  return false;
}

function send(res, status, obj) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    ...CORS,
  });
  res.end(JSON.stringify(obj));
}

const server = http.createServer((req, res) => {
  if (req.method === "OPTIONS") {
    res.writeHead(204, CORS);
    return res.end();
  }

  if (req.method === "GET") {
    return send(res, 200, { ok: true, service: "indulge playas club — contact api" });
  }

  if (req.method !== "POST") {
    return send(res, 405, { ok: false, reason: "method_not_allowed" });
  }

  const pathOk = /^\/(api\/)?contact\/?$/.test((req.url || "").split("?")[0]);
  if (!pathOk) {
    return send(res, 404, { ok: false, reason: "not_found" });
  }

  const ip =
    (req.headers["x-forwarded-for"] || "").split(",")[0].trim() ||
    req.socket.remoteAddress ||
    "unknown";

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

    if (rateLimited(ip)) {
      return send(res, 429, { ok: false, reason: "rate_limited" });
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
});

server.listen(PORT, () => {
  console.log("IPC contact API listening on port " + PORT);
});
