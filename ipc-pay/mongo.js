"use strict";
/*
 * INDULGE PLAYAS CLUB — MongoDB Atlas connection (IPC accounts + IPC Pay)
 * -----------------------------------------------------------------------
 * Everything the shop stores lives in MongoDB Atlas as collections and
 * documents — no SQL, no tables, no migration scripts. One connection
 * string (MONGODB_URI) is the whole setup.
 *
 * Collections (created automatically on first use):
 *   users     — { email, name, salt, hash, role: "customer"|"admin", createdAt }
 *   sessions  — { token, userId, email, expiresAt }   (auto-deleted when expired)
 *   counters  — { _id: "order"|"payment", seq }        (reference numbers)
 *   orders    — one document per order, money in integer centavos
 *   payments  — one document per IPC Pay payment, money in integer centavos
 *
 * Environment variables:
 *   MONGODB_URI       — Atlas → Connect → Drivers → the mongodb+srv://… string
 *   MONGODB_DB        — database name (default: "ipc")
 *   ADMIN_EMAIL       — admin account email  (seeded automatically on boot)
 *   ADMIN_PASSWORD    — admin account password (seeded automatically on boot)
 *   ADMIN_NAME        — admin display name (default: "Club Admin")
 *   ADMIN_RESET_PASSWORD — set to "true" to force-reset the admin password
 *                        to ADMIN_PASSWORD on boot (ignored otherwise)
 *
 * Security notes:
 *   - Passwords are hashed with scrypt (node:crypto) + a per-user random
 *     salt. No plaintext password is ever stored.
 *   - Sessions are 48-hex-char random tokens with a 30-day expiry; the TTL
 *     index makes MongoDB delete expired sessions automatically.
 *   - A customer uploading proof moves their payment to "under_verification",
 *     never further — this file holds no payment-decision code at all. Every
 *     path to "paid" (the guarded auto reader, admin decisions, the webhook)
 *     lives in server.js, logged and compare-and-set protected.
 */

const crypto = require("node:crypto");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");

const URI = (process.env.MONGODB_URI || "").trim();
const DB_NAME = (process.env.MONGODB_DB || "ipc").trim();

let client = null;
let database = null;
let initPromise = null;

/* ---------------------------------------------------------------- */
/* Errors                                                           */
/* ---------------------------------------------------------------- */

function notConfiguredError() {
  const err = new Error("MONGODB_URI is not set — IPC accounts are offline.");
  err.code = "MONGO_NOT_CONFIGURED";
  return err;
}

/* Plain-English sanity check for MONGODB_URI. Driver errors like
   "bad auth : authentication failed" are cryptic — these hints print
   the actual fix on the Render log and in /api/ipc-pay/health. */
function uriHints(u) {
  const hints = [];
  if (!u) {
    hints.push("MONGODB_URI is empty — paste the Atlas connection string in Render → Environment.");
    return hints;
  }
  if (!/^mongodb(\+srv)?:\/\//.test(u)) {
    hints.push('the URI must start with "mongodb+srv://" or "mongodb://" — copy it again from Atlas → Connect.');
  }
  if (u.indexOf("<db_password>") !== -1) {
    hints.push('the URI still contains "<db_password>" — replace it (including the < > brackets) with your real database password.');
  }
  if (/[<>"'`\\ ]/.test(u)) {
    hints.push('the URI contains <, >, quotes or spaces — remove them; angle brackets and quotes are template placeholders, never part of the password.');
  }
  if (u.indexOf("@") === -1) {
    hints.push("the URI is missing the user:password part — use the connection string from Atlas → Connect.");
  }
  const m = u.match(/^mongodb(?:\+srv)?:\/\/([^:@]*):([^@]*)@/);
  if (m && m[2]) {
    let pw = m[2];
    try {
      pw = decodeURIComponent(pw);
    } catch (e) {
      hints.push("the password part is not valid URL-encoding — easiest fix: set a LETTERS+NUMBERS ONLY password in Atlas.");
    }
    if (m[2] === "<db_password>") {
      /* already covered above */
    } else if (/[ @#/?%&+:;"'<>\\]/.test(pw)) {
      hints.push("the password contains special characters or brackets — Atlas → Database Access → Edit → Edit Password → use LETTERS+NUMBERS ONLY → Update User, then put that bare password (no < > brackets) into the URI.");
    }
  }
  return hints;
}

/* ---------------------------------------------------------------- */
/* Connection                                                       */
/* ---------------------------------------------------------------- */

function connect() {
  if (!URI) return Promise.reject(notConfiguredError());
  if (database) return Promise.resolve(database);
  if (!client) {
    client = new MongoClient(URI, {
      serverApi: { version: ServerApiVersion.v1, strict: false, deprecationErrors: false },
      maxPoolSize: 5,
    });
  }
  return client.connect().then(() => {
    database = client.db(DB_NAME);
    return database;
  }).catch((err) => {
    err.hints = uriHints(URI); /* carry the plain-English fix with the error */
    throw err;
  });
}

/** One-time boot: connect + indexes + admin seeding. Safe to call twice. */
function initDatabase() {
  if (!initPromise) {
    initPromise = connect()
      .then((d) => ensureIndexes(d))
      .then((d) => seedAdmin(d))
      .then((d) => seedVouchers(d))
      .then((d) => d);
  }
  return initPromise;
}

async function ensureIndexes(d) {
  /* one at a time — a hiccup on one index must never block the admin seed */
  const specs = [
    ["users", { email: 1 }, { unique: true }],
    ["users", { phone: 1 }, { unique: true, sparse: true }],
    ["sessions", { token: 1 }, { unique: true }],
    ["sessions", { expiresAt: 1 }, { expireAfterSeconds: 0 }], /* TTL — expired sessions delete themselves */
    ["orders", { reference: 1 }, { unique: true }],
    ["orders", { userId: 1, createdAt: -1 }, {}],
    ["payments", { paymentReference: 1 }, { unique: true }],
    ["payments", { orderReference: 1 }, {}],
    ["vouchers", { code: 1 }, { unique: true }],
    ["voucherRedemptions", { code: 1, userId: 1 }, { unique: true }],
    ["voucherRedemptions", { code: 1, phone: 1 }, { unique: true }],
    ["voucherRedemptions", { orderReference: 1 }, { unique: true }],
    /* v25 — activity log, support tickets, product visibility */
    ["activityLogs", { createdAt: -1 }, {}],
    ["activityLogs", { action: 1, createdAt: -1 }, {}],
    ["supportTickets", { id: 1 }, { unique: true }],
    ["supportTickets", { userId: 1, updatedAt: -1 }, {}],
    ["supportTickets", { status: 1, updatedAt: -1 }, {}],
    ["productVisibility", { id: 1 }, { unique: true }],
    ["analyticsEvents", { name: 1, createdAt: -1 }, {}],
  ];
  for (const [coll, key, opts] of specs) {
    try {
      await d.collection(coll).createIndex(key, opts);
    } catch (err) {
      /* index already exists with different options → fine to ignore,
         anything else gets logged but does not stop the boot sequence */
      console.log(`[ipc-pay] index ${coll}:${JSON.stringify(key)} skipped:`, err.message);
    }
  }
  return d;
}

/** Health check for /api/ipc-pay/health. */
function checkConnection() {
  if (!URI) return Promise.reject(notConfiguredError());
  return connect()
    .then((d) => d.command({ ping: 1 }))
    .then(() => undefined);
}

/* ---------------------------------------------------------------- */
/* Password hashing (scrypt — built into Node, no extra packages)   */
/* ---------------------------------------------------------------- */

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(String(password), salt, 64).toString("hex");
  return { salt, hash };
}

function verifyPassword(password, salt, hash) {
  try {
    const candidate = crypto.scryptSync(String(password), salt, 64);
    const stored = Buffer.from(hash, "hex");
    return candidate.length === stored.length && crypto.timingSafeEqual(candidate, stored);
  } catch {
    return false;
  }
}

/* ---------------------------------------------------------------- */
/* Sessions                                                         */
/* ---------------------------------------------------------------- */

const SESSION_DAYS = 30;

function createSession(user) {
  const token = crypto.randomBytes(24).toString("hex");
  const now = new Date();
  const expiresAt = new Date(now.getTime() + SESSION_DAYS * 24 * 60 * 60 * 1000);
  return connect().then((d) =>
    d.collection("sessions").insertOne({
      token,
      userId: user._id,
      email: user.email,
      createdAt: now,
      expiresAt,
    })
  ).then(() => token);
}

function findSession(token) {
  return connect().then((d) =>
    d.collection("sessions").findOne({
      token,
      expiresAt: { $gt: new Date() },
    })
  );
}

function deleteSession(token) {
  return connect().then((d) => d.collection("sessions").deleteOne({ token }));
}

/* ---------------------------------------------------------------- */
/* Users                                                            */
/* ---------------------------------------------------------------- */

function findUserByEmail(email) {
  return connect().then((d) =>
    d.collection("users").findOne({ email: String(email).toLowerCase() })
  );
}

function findUserByPhone(phone) {
  return connect().then((d) =>
    d.collection("users").findOne({ phone: String(phone) })
  );
}



function findUserById(id) {
  /* accept 24-hex strings as well as ObjectId — a raw string _id never
     matches in Mongo and silently returns null (this bit the /me lookup) */
  const key =
    typeof id === "string" && /^[0-9a-f]{24}$/i.test(id) ? new ObjectId(id) : id;
  return connect().then((d) => d.collection("users").findOne({ _id: key }));
}

function insertUser({ email, name, password, role, phone, birthMonth }) {
  const { salt, hash } = hashPassword(password);
  const doc = {
    email: String(email).toLowerCase(),
    name: String(name),
    ...(phone ? { phone: String(phone) } : {}),
    /* optional birth month (1-12) — powers the birthday voucher */
    ...(Number(birthMonth) >= 1 && Number(birthMonth) <= 12 ? { birthMonth: Math.round(Number(birthMonth)) } : {}),
    salt,
    hash,
    role: role === "admin" ? "admin" : "customer",
    createdAt: new Date(),
  };
  return connect().then((d) => d.collection("users").insertOne(doc)).then(() => doc);
}

/* ---------------------------------------------------------------- */
/* Starter voucher seeding — runs once on boot.                     */
/* If the vouchers collection is empty, the club's opening offers   */
/* are created so the checkout voucher box works from day one.      */
/* An existing voucher set is never touched.                        */
/* ---------------------------------------------------------------- */
function seedVouchers(d) {
  return d.collection("vouchers")
    .countDocuments()
    .then((n) => {
      if (n > 0) {
        console.log("[ipc-pay] vouchers present: " + n + " — seed skipped.");
        return d;
      }
      const now = new Date();
      const starters = [
        {
          code: "WELCOMEPCLUB",
          label: "Welcome to the club — 15% off your first order",
          type: "percent", value: 15,
          minSubtotalCentavos: 0, maxUses: 500, uses: 0,
          firstOrderOnly: true, active: true,
          startsAt: null, expiresAt: null,
          createdAt: now, createdBy: "seed",
        },
        {
          code: "PLAYASDAY",
          label: "Playas day — ₱200 off ₱1,000+",
          type: "fixed", value: 20000,
          minSubtotalCentavos: 100000, maxUses: 200, uses: 0,
          firstOrderOnly: false, active: true,
          startsAt: null, expiresAt: null,
          createdAt: now, createdBy: "seed",
        },
        {
          code: "IPCDROP01",
          label: "Drop 01 push — 10% off ₱2,000+ (30 days)",
          type: "percent", value: 10,
          minSubtotalCentavos: 200000, maxUses: 100, uses: 0,
          firstOrderOnly: false, active: true,
          startsAt: null,
          expiresAt: new Date(now.getTime() + 30 * 24 * 3600 * 1000),
          createdAt: now, createdBy: "seed",
        },
      ];
      return d.collection("vouchers")
        .insertMany(starters, { ordered: true })
        .then(() => console.log("[ipc-pay] starter vouchers seeded: WELCOMEPCLUB · PLAYASDAY · IPCDROP01"))
        .catch((err) => console.log("[ipc-pay] voucher seed skipped:", err.message))
        .then(() => d);
    })
    .catch((err) => {
      console.log("[ipc-pay] voucher seed check failed:", err.message);
      return d;
    });
}

/**
 * Admin account seeding — runs once on boot.
 * Set ADMIN_EMAIL + ADMIN_PASSWORD in Render → Environment and the club's
 * admin login exists automatically. An existing admin is left alone unless
 * ADMIN_RESET_PASSWORD=true (then the password gets reset to ADMIN_PASSWORD).
 */
function seedAdmin(d) {
  const email = (process.env.ADMIN_EMAIL || "").trim().toLowerCase();
  const password = process.env.ADMIN_PASSWORD || "";
  const name = (process.env.ADMIN_NAME || "Club Admin").trim();
  if (!email || !password) {
    console.log("[ipc-pay] ADMIN_EMAIL / ADMIN_PASSWORD not set — no admin account seeded.");
    return Promise.resolve(d);
  }
  const users = d.collection("users");
  return users
    .findOne({ email })
    .then((existing) => {
      if (!existing) {
        const { salt, hash } = hashPassword(password);
        return users.insertOne({
          email,
          name,
          salt,
          hash,
          role: "admin",
          createdAt: new Date(),
        }).then(() => console.log(`[ipc-pay] admin account created: ${email}`));
      }
      if (existing.role !== "admin") {
        return users.updateOne({ _id: existing._id }, { $set: { role: "admin" } })
          .then(() => console.log(`[ipc-pay] existing account promoted to admin: ${email}`));
      }
      if (String(process.env.ADMIN_RESET_PASSWORD).toLowerCase() === "true") {
        const { salt, hash } = hashPassword(password);
        return users.updateOne({ _id: existing._id }, { $set: { salt, hash } })
          .then(() => console.log(`[ipc-pay] admin password reset: ${email}`));
      }
      console.log(`[ipc-pay] admin account ready: ${email}`);
      return undefined;
    })
    .then(() => d);
}

/* ---------------------------------------------------------------- */
/* Reference numbers — IPC-00001, IPCP-00001                        */
/* ---------------------------------------------------------------- */

function nextReference(prefix) {
  return connect().then((d) =>
    d.collection("counters").findOneAndUpdate(
      { _id: prefix },
      { $inc: { seq: 1 } },
      { upsert: true, returnDocument: "after" }
    )
  ).then((r) => `${prefix === "order" ? "IPC" : prefix === "track" ? "IPCT" : prefix === "ticket" ? "IPCS" : "IPCP"}-${String(r.seq).padStart(5, "0")}`);
}

/* ---------------------------------------------------------------- */

module.exports = {
  connect,
  initDatabase,
  checkConnection,
  uriHints,
  hashPassword,
  verifyPassword,
  createSession,
  findSession,
  deleteSession,
  findUserByEmail,
  findUserByPhone,
  findUserById,
  insertUser,
  nextReference,
  MONGO_NOT_CONFIGURED: "MONGO_NOT_CONFIGURED",
};
