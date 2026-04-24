-- IllegalBet Scanner — Postgres / Supabase schema
-- Run this once in Supabase SQL Editor (or any Postgres 14+)

create extension if not exists "pgcrypto";
create extension if not exists "vector";

-- ----------------------------------------------------------------
-- Domains table (one row per tracked domain)
-- ----------------------------------------------------------------
create table if not exists domains (
    id               uuid primary key default gen_random_uuid(),
    domain           text unique not null,
    first_seen       timestamptz not null default now(),
    last_checked     timestamptz not null default now(),
    source           text,
    ip               text,
    licensed         boolean not null default false,
    risk_score       int not null default 0,
    risk_label       text not null default 'unknown',
    reasons          jsonb default '[]'::jsonb,
    infra            jsonb,
    site             jsonb,
    cnpj             jsonb,
    embedding        vector(384)     -- optional: for self-learning similarity
);

create index if not exists domains_risk_idx        on domains (risk_label);
create index if not exists domains_score_idx       on domains (risk_score desc);
create index if not exists domains_last_checked_ix on domains (last_checked desc);
create index if not exists domains_licensed_idx    on domains (licensed);

-- ----------------------------------------------------------------
-- Scan events (log history — one row per scan attempt)
-- ----------------------------------------------------------------
create table if not exists scan_events (
    id           bigserial primary key,
    domain       text not null,
    t            timestamptz not null default now(),
    source       text,
    risk_score   int,
    risk_label   text,
    snapshot     jsonb
);
create index if not exists scan_events_domain_ix on scan_events (domain, t desc);

-- ----------------------------------------------------------------
-- SPA whitelist cache (licensed operators)
-- ----------------------------------------------------------------
create table if not exists spa_whitelist (
    domain       text primary key,
    fetched_at   timestamptz not null default now()
);

-- ----------------------------------------------------------------
-- Optional: infrastructure clusters (shared hosting)
-- ----------------------------------------------------------------
create table if not exists infra_clusters (
    ip           text primary key,
    asn          text,
    isp          text,
    country_code text,
    domain_count int default 0,
    last_seen    timestamptz default now()
);

-- ----------------------------------------------------------------
-- Row Level Security (public read, service_role write)
-- ----------------------------------------------------------------
alter table domains       enable row level security;
alter table scan_events   enable row level security;
alter table spa_whitelist enable row level security;

drop policy if exists "public read domains"       on domains;
drop policy if exists "public read scan_events"   on scan_events;
drop policy if exists "public read whitelist"     on spa_whitelist;

create policy "public read domains"     on domains       for select using (true);
create policy "public read scan_events" on scan_events   for select using (true);
create policy "public read whitelist"   on spa_whitelist for select using (true);
-- Writes are done by your backend using the service_role key, which bypasses RLS.

-- ----------------------------------------------------------------
-- View: current risk snapshot
-- ----------------------------------------------------------------
create or replace view risk_dashboard as
select
  risk_label,
  count(*)                   as n,
  count(*) filter (where licensed) as n_licensed,
  avg(risk_score)::int       as avg_score,
  max(last_checked)          as most_recent
from domains
group by risk_label
order by n desc;
