"use strict";

/**
 * IPC Pay Core — Phase 1 foundation.
 * This module validates payment intents and enforces safe status transitions.
 * It does not move money and does not claim that a payment has been received.
 */

const PAYMENT_STATUSES = Object.freeze([
  "pending",
  "processing",
  "paid",
  "failed",
  "expired",
  "refunded",
]);

const ALLOWED_TRANSITIONS = Object.freeze({
  pending: new Set(["processing", "paid", "failed", "expired"]),
  processing: new Set(["paid", "failed", "expired"]),
  paid: new Set(["refunded"]),
  failed: new Set(),
  expired: new Set(),
  refunded: new Set(),
});

function validatePaymentIntent(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new TypeError("Payment intent must be an object.");
  }

  const amountCentavos = input.amountCentavos;
  if (!Number.isSafeInteger(amountCentavos) || amountCentavos < 100) {
    throw new TypeError("amountCentavos must be a safe integer of at least 100.");
  }

  const currency = String(input.currency || "PHP").toUpperCase();
  if (currency !== "PHP") {
    throw new TypeError("Only PHP payments are currently supported.");
  }

  const merchantReference = String(input.merchantReference || "").trim();
  if (!merchantReference || merchantReference.length > 100) {
    throw new TypeError("merchantReference is required and must be 100 characters or fewer.");
  }

  const description = String(input.description || "").trim();
  if (description.length > 250) {
    throw new TypeError("description must be 250 characters or fewer.");
  }

  return Object.freeze({
    amountCentavos,
    currency,
    merchantReference,
    description,
  });
}

function assertStatusTransition(currentStatus, nextStatus) {
  if (!PAYMENT_STATUSES.includes(currentStatus)) {
    throw new TypeError("Unknown current payment status.");
  }
  if (!PAYMENT_STATUSES.includes(nextStatus)) {
    throw new TypeError("Unknown next payment status.");
  }
  if (!ALLOWED_TRANSITIONS[currentStatus].has(nextStatus)) {
    throw new Error("Invalid payment status transition: " + currentStatus + " -> " + nextStatus);
  }
  return true;
}

function formatPhp(amountCentavos) {
  if (!Number.isSafeInteger(amountCentavos) || amountCentavos < 0) {
    throw new TypeError("amountCentavos must be a non-negative safe integer.");
  }
  return new Intl.NumberFormat("en-PH", {
    style: "currency",
    currency: "PHP",
  }).format(amountCentavos / 100);
}

module.exports = {
  PAYMENT_STATUSES,
  validatePaymentIntent,
  assertStatusTransition,
  formatPhp,
};
