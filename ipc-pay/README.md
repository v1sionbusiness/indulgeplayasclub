# IPC Pay

IPC Pay is Indulge Playas Club's order and payment record system. The live
storefront backend currently uses MongoDB Atlas (not the Supabase schema in
`database/ipc-pay-schema.sql`).

## Current checkout mode: static Maya QR

The merchant currently has a static Maya QR only. The website must treat this
as a **manual-verification payment method**, not as an automated gateway.

1. The server creates an order and a unique IPC payment reference.
2. The customer pays the exact server-calculated PHP amount using the merchant's
   static Maya QR.
3. The customer submits the Maya transaction reference and (optionally) a JPG,
   JPEG or PNG receipt image.
4. IPC stores the submission as `under_verification`; the order is not paid.
5. An authenticated admin checks the transaction in the merchant's Maya account
   and approves or rejects it from the admin payment queue.
6. The server updates the order/payment and attempts a customer status email.

A screenshot or customer-submitted reference is not proof of settlement. An
admin must check the merchant-side Maya transaction record before approving.
A payment cannot be approved without a submitted transaction reference.
Duplicate transaction references are rejected, and payment decisions use an
atomic status check so concurrent admin actions cannot issue conflicting
decisions.

## Email configuration

Set these Render environment variables to enable payment status emails:

- `EMAILJS_PUBLIC_KEY`
- `EMAILJS_SERVICE_ID`
- `EMAILJS_PAYMENT_TEMPLATE_ID`

The payment EmailJS template must use `{{to_email}}` as its recipient and may
use `{{customer_name}}`, `{{order_reference}}`, `{{payment_reference}}`,
`{{amount}}`, `{{payment_status}}`, `{{status_detail}}` and `{{reply_to}}`.
The existing contact-form template remains separate.

## Later: automated Maya verification

A static QR does not provide IPC with a unique order-linked payment event or a
documented webhook callback. Do not mark an order paid based on a browser
redirect, screenshot, or customer reference alone.

Automated verification requires the merchant to be approved for the relevant
Maya online payment product (for example, Dynamic QRPh / Pay with Maya), API
credentials, and registered webhook endpoints. Keep those credentials in
Render environment variables. The future integration must validate webhook
authenticity, merchant account, amount, currency, payment reference and event
idempotency before marking an order paid.

## Safety rules

- Never store card numbers, CVV, wallet PINs or OTPs.
- Never auto-refund when a page fails to load or a customer closes checkout.
- Do not expose provider secrets to the browser.
- Keep order and payment states separate from customer-submitted claims.
