"use strict";

/**
 * Server-only Supabase REST client for IPC Pay.
 * Uses the Supabase secret key only on the backend. Never import this file
 * from browser code or return credentials in API responses.
 */
function getConfig() {
  const rawUrl = process.env.SUPABASE_URL || "";
  const secretKey = process.env.SUPABASE_SECRET_KEY || "";
  if (!rawUrl || !secretKey) {
    const error = new Error("Supabase is not configured.");
    error.code = "SUPABASE_NOT_CONFIGURED";
    throw error;
  }

  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    const error = new Error("SUPABASE_URL is invalid.");
    error.code = "SUPABASE_CONFIG_INVALID";
    throw error;
  }
  if (url.protocol !== "https:") {
    const error = new Error("SUPABASE_URL must use HTTPS.");
    error.code = "SUPABASE_CONFIG_INVALID";
    throw error;
  }
  return { baseUrl: url.origin, secretKey };
}

async function checkConnection() {
  const { baseUrl, secretKey } = getConfig();
  const endpoint = new URL("/rest/v1/ipc_payments?select=id&limit=1", baseUrl);
  const response = await fetch(endpoint, {
    method: "GET",
    headers: {
      apikey: secretKey,
      Authorization: "Bearer " + secretKey,
      Accept: "application/json",
    },
    signal: AbortSignal.timeout(10000),
  });

  if (!response.ok) {
    const error = new Error("Supabase request failed with HTTP " + response.status);
    error.code = "SUPABASE_REQUEST_FAILED";
    error.status = response.status;
    throw error;
  }

  return { connected: true };
}

module.exports = { checkConnection };
