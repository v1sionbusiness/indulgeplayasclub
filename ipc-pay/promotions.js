"use strict";

/* IPC promotions: pure validation helpers shared by checkout and tests. */

function normalizePhilippineMobile(input) {
  const raw = String(input || "").trim();
  let digits = raw.replace(/[^0-9]/g, "");
  if (digits.startsWith("63")) digits = digits.slice(2);
  if (digits.startsWith("0")) digits = digits.slice(1);
  if (!/^9\\d{9}$/.test(digits)) {
    throw new TypeError("ENTER A VALID PHILIPPINE MOBILE NUMBER (09XXXXXXXXX).");
  }
  return "+63" + digits;
}

function normalizeVoucherCode(input) {
  const code = String(input || "").trim().toUpperCase();
  if (!/^[A-Z0-9][A-Z0-9_-]{2,31}$/.test(code)) {
    throw new TypeError("VOUCHER CODE MUST BE 3–32 LETTERS, NUMBERS, DASHES OR UNDERSCORES.");
  }
  return code;
}

function calculateVoucherDiscount(subtotalCentavos, voucher) {
  if (!Number.isSafeInteger(subtotalCentavos) || subtotalCentavos < 0) {
    throw new TypeError("Subtotal must be a non-negative integer amount in centavos.");
  }
  if (!voucher || (voucher.type !== "percent" && voucher.type !== "fixed")) {
    throw new TypeError("Unsupported voucher type.");
  }
  let discount = voucher.type === "percent"
    ? Math.floor(subtotalCentavos * Number(voucher.value) / 100)
    : Math.floor(Number(voucher.value));
  if (!Number.isSafeInteger(discount) || discount < 0) {
    throw new TypeError("Voucher value is invalid.");
  }
  return Math.min(subtotalCentavos, discount);
}

module.exports = {
  normalizePhilippineMobile,
  normalizeVoucherCode,
  calculateVoucherDiscount,
};
