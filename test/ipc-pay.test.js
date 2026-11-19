"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  validatePaymentIntent,
  assertStatusTransition,
  formatPhp,
} = require("../ipc-pay/core");

test("validates and normalizes a PHP payment intent", () => {
  const intent = validatePaymentIntent({
    amountCentavos: 12500,
    merchantReference: "ORDER-1001",
    description: "Club merchandise",
  });
  assert.equal(intent.amountCentavos, 12500);
  assert.equal(intent.currency, "PHP");
  assert.equal(intent.merchantReference, "ORDER-1001");
});

test("rejects floating point amounts and unsupported currencies", () => {
  assert.throws(() => validatePaymentIntent({
    amountCentavos: 125.5,
    merchantReference: "ORDER-1002",
  }), /safe integer/);

  assert.throws(() => validatePaymentIntent({
    amountCentavos: 12500,
    currency: "USD",
    merchantReference: "ORDER-1003",
  }), /Only PHP/);
});

test("allows a pending payment to become paid", () => {
  assert.equal(assertStatusTransition("pending", "paid"), true);
});

test("does not allow a paid payment to become pending again", () => {
  assert.throws(
    () => assertStatusTransition("paid", "pending"),
    /Invalid payment status transition/
  );
});

test("formats integer centavos as PHP", () => {
  assert.match(formatPhp(12345), /123/);
});
