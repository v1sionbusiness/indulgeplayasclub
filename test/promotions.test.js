"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  normalizePhilippineMobile,
  normalizeVoucherCode,
  calculateVoucherDiscount,
} = require("../ipc-pay/promotions");

test("normalizes common Philippine mobile number formats", () => {
  assert.equal(normalizePhilippineMobile("0917 123 4567"), "+639171234567");
  assert.equal(normalizePhilippineMobile("+63 917-123-4567"), "+639171234567");
  assert.equal(normalizePhilippineMobile("639171234567"), "+639171234567");
});

test("rejects invalid mobile numbers", () => {
  assert.throws(() => normalizePhilippineMobile("12345"), /VALID PHILIPPINE MOBILE/);
});

test("normalizes voucher codes", () => {
  assert.equal(normalizeVoucherCode(" welcome_10 "), "WELCOME_10");
  assert.throws(() => normalizeVoucherCode("x"), /VOUCHER CODE/);
});

test("calculates percent and fixed discounts in centavos", () => {
  assert.equal(calculateVoucherDiscount(100000, { type: "percent", value: 10 }), 10000);
  assert.equal(calculateVoucherDiscount(100000, { type: "fixed", value: 2500 }), 2500);
  assert.equal(calculateVoucherDiscount(1000, { type: "fixed", value: 2500 }), 1000);
});
