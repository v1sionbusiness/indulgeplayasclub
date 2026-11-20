"use strict";
/*
 * IPC PAY — Supabase connection helper for the contact API relay.
 * ---------------------------------------------------------------
 * The relay keeps ZERO secrets in code: the Supabase project URL and the
 * service-role key live in the host's Environment settings (Render →
 * Environment / Cloud Run → Variables & Secrets):
 *
 *   SUPABASE_URL               — https://YOUR-PROJECT.supabase.co
 *   SUPABASE_SERVICE_ROLE_KEY  — service_role key (NEVER the anon key)
 *
 * (NEXT_PUBLIC_SUPABASE_URL is accepted as a fallback name so the same
 * project can feed both the Next.js app and this relay.)
 *
 * checkConnection() pings the REST endpoint of the existing `ipc_payments`
 * table — it validates the URL, the key AND that the table is really there.
 * It never mutates anything and never logs or returns the key.
 *
 * Error codes (consumed by server.js):
 *   SUPABASE_NOT_CONFIGURED  — env vars missing            → HTTP 503
 *   SUPABASE_CONFIG_INVALID  — env vars malformed          → HTTP 503
 *   SUPABASE_REQUEST_FAILED  — network/HTTP error          → HTTP 502
 */

const SUPABASE_URL = (
  process.env.SUPABASE_URL ||
  process.env.NEXT_PUBLIC_SUPABASE_URL ||
  ""
).trim();

const SERVICE_KEY = (
  process.env.SUPABASE_SERVICE_ROLE_KEY ||
  ""
).trim();

function isConfigured() {
  return Boolean(SUPABASE_URL && SERVICE_KEY);
}

function failure(code, message) {
  const err = new Error(message);
  err.code = code;
  return err;
}

function validateConfig() {
  if (!isConfigured()) {
    throw failure(
      "SUPABASE_NOT_CONFIGURED",
      "Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY in the service Environment.",
    );
  }
  let parsed;
  try {
    parsed = new URL(SUPABASE_URL);
  } catch {
    throw failure(
      "SUPABASE_CONFIG_INVALID",
      "SUPABASE_URL must be a full URL like https://YOUR-PROJECT.supabase.co",
    );
  }
  if (parsed.protocol !== "https:" || !parsed.hostname.includes(".")) {
    throw failure(
      "SUPABASE_CONFIG_INVALID",
      "SUPABASE_URL must be an https Supabase project URL.",
    );
  }
}

/**
 * Ping the existing ipc_payments table through the REST API.
 * Resolves true when the database is reachable, the service key is valid
 * and the table exists; throws a coded error otherwise.
 */
async function checkConnection() {
  validateConfig();

  const endpoint =
    SUPABASE_URL.replace(/\/+$/, "") + "/rest/v1/ipc_payments?select=id&limit=1";

  let res;
  try {
    res = await fetch(endpoint, {
      method: "GET",
      headers: {
        apikey: SERVICE_KEY,
        Authorization: "Bearer " + SERVICE_KEY,
        "Accept": "application/json",
      },
      signal: AbortSignal.timeout(10000),
    });
  } catch (err) {
    throw failure(
      "SUPABASE_REQUEST_FAILED",
      "Could not reach Supabase: " + (err && err.message ? err.message : "network error"),
    );
  }

  if (!res.ok) {
    // 401/403 → bad key; 404/table missing → schema not migrated yet
    throw failure(
      "SUPABASE_REQUEST_FAILED",
      "Supabase REST responded " + res.status + " for ipc_payments" +
        (res.status === 404 ? " — run supabase/migration.sql first" : "") +
        (res.status === 401 || res.status === 403 ? " — check SUPABASE_SERVICE_ROLE_KEY" : ""),
    );
  }

  return true;
}
