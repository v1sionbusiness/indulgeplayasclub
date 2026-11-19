-- IPC Pay — Supabase/PostgreSQL schema (Phase 1)
-- Apply in the Supabase SQL Editor after creating the project.
-- Keep service-role credentials on the server only. Never expose them in the browser.

create extension if not exists pgcrypto;

create table if not exists public.ipc_payments (
  id uuid primary key default gen_random_uuid(),
  payment_reference text not null unique,
  merchant_reference text not null,
  amount_centavos bigint not null check (amount_centavos >= 100),
  currency text not null default 'PHP' check (currency = 'PHP'),
  status text not null default 'pending'
    check (status in ('pending', 'processing', 'paid', 'failed', 'expired', 'refunded')),
  provider text,
  provider_reference text unique,
  idempotency_key text not null unique,
  description text not null default '',
  metadata jsonb not null default '{}'::jsonb,
  paid_at timestamptz,
  expires_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists ipc_payments_merchant_reference_idx
  on public.ipc_payments (merchant_reference);
create index if not exists ipc_payments_status_created_idx
  on public.ipc_payments (status, created_at desc);

create or replace function public.ipc_payments_set_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists ipc_payments_updated_at on public.ipc_payments;
create trigger ipc_payments_updated_at
before update on public.ipc_payments
for each row execute function public.ipc_payments_set_updated_at();

-- Deny direct client access by default. Server-side access will use the
-- Supabase service role after backend authentication and authorization exist.
alter table public.ipc_payments enable row level security;
