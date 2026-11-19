"use strict";

/**
 * Provider adapter contract.
 *
 * A real adapter must be implemented only after IPC has an approved merchant
 * account and credentials from an authorized payment service provider.
 * Never treat a browser redirect or screenshot as proof of payment.
 */

class ProviderNotConfiguredError extends Error {
  constructor() {
    super("No approved payment provider is configured.");
    this.name = "ProviderNotConfiguredError";
    this.code = "PROVIDER_NOT_CONFIGURED";
  }
}

class PaymentProviderAdapter {
  async createCheckoutSession() {
    throw new ProviderNotConfiguredError();
  }

  verifyWebhookSignature() {
    throw new ProviderNotConfiguredError();
  }

  parseVerifiedWebhook() {
    throw new ProviderNotConfiguredError();
  }
}

module.exports = {
  PaymentProviderAdapter,
  ProviderNotConfiguredError,
};
