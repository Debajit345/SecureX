create extension if not exists pgcrypto;

create table if not exists public.scan_cache (
  id text primary key check (id ~ '^[a-f0-9]{64}$'),
  url_hash text not null unique,
  report_gzip text not null,
  scanned_at timestamptz not null,
  updated_at timestamptz not null default now()
);

create table if not exists public.saved_reports (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  cache_id text not null references public.scan_cache(id) on delete cascade,
  created_at timestamptz not null default now()
);
create index if not exists saved_reports_user_created_idx on public.saved_reports(user_id, created_at desc);

alter table public.scan_cache enable row level security;
alter table public.saved_reports enable row level security;
revoke all on public.scan_cache, public.saved_reports from anon, authenticated;
grant all on public.scan_cache, public.saved_reports to service_role;
grant select, insert, delete on public.saved_reports to authenticated;

create policy "Users read own saved reports" on public.saved_reports
  for select to authenticated using ((select auth.uid()) = user_id);
create policy "Users create own saved reports" on public.saved_reports
  for insert to authenticated with check ((select auth.uid()) = user_id);
create policy "Users delete own saved reports" on public.saved_reports
  for delete to authenticated using ((select auth.uid()) = user_id);

-- The API accesses these tables with a server-only service key after verifying the user's JWT.
comment on table public.scan_cache is 'Compressed shared scan snapshots; never expose directly through the Data API.';
comment on table public.saved_reports is 'Private user-to-scan references; backend filters by verified Supabase Auth user ID.';
