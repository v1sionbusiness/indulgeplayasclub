# IPC Pay

IPC Pay is Indulge Playas Club's first-party payment orchestration layer.
It will own payment references, order/payment records, checkout UX, webhook
verification, reconciliation and admin reporting. Actual money movement must
remain with an authorized, approved payment provider until IPC has any
separate regulatory approvals required to operate payment services itself.

## Phase 1 status

- Core PHP amount validation (integer centavos; no floating-point arithmetic).
- Payment status vocabulary and transition guard.
- Provider adapter contract that fails closed until a real provider is approved.
- Supabase schema with unique payment/idempotency references and RLS enabled.

## Important safety rules

- A return URL, browser event, uploaded receipt or screenshot never marks a payment paid.
- Only a verified provider webhook or authenticated provider-side status lookup may confirm payment.
- Verify the provider signature, merchant account, amount, currency and transaction reference.
- Process webhook events idempotently; reject duplicate or out-of-order state changes.
- Keep provider secrets and Supabase service-role keys in Render environment variables.
- Do not store card numbers, CVV, wallet PINs or OTPs.
- Never use the mock/development path for real payments.

## Next implementation steps

1. Create a Supabase project and apply `database/ipc-pay-schema.sql`.
2. Add a server-side persistence repository using the Supabase service role.
3. Add authenticated payment-intent endpoints with idempotency.
4. Implement a provider adapter after merchant onboarding and API documentation are available.
5. Add signed webhook verification, reconciliation and automated tests.
6. Connect the checkout UI to the existing storefront without changing the current contact form.

No real payment provider is configured by this phase.
