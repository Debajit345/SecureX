create table if not exists public.securex_rate_limits (
  subject_hash text not null,
  bucket text not null,
  window_started timestamptz not null,
  request_count integer not null default 0,
  primary key (subject_hash, bucket)
);
alter table public.securex_rate_limits enable row level security;
revoke all on public.securex_rate_limits from anon, authenticated;
grant all on public.securex_rate_limits to service_role;

create or replace function public.securex_take_rate_limit(
  p_subject text, p_bucket text, p_limit integer, p_window_seconds integer
) returns boolean
language plpgsql security invoker set search_path = '' as $$
declare allowed boolean;
begin
  insert into public.securex_rate_limits(subject_hash,bucket,window_started,request_count)
  values (p_subject,p_bucket,now(),1)
  on conflict(subject_hash,bucket) do update set
    window_started = case when public.securex_rate_limits.window_started + make_interval(secs => p_window_seconds) <= now() then now() else public.securex_rate_limits.window_started end,
    request_count = case when public.securex_rate_limits.window_started + make_interval(secs => p_window_seconds) <= now() then 1 else public.securex_rate_limits.request_count + 1 end;
  select request_count <= p_limit into allowed from public.securex_rate_limits where subject_hash=p_subject and bucket=p_bucket;
  return allowed;
end $$;
revoke all on function public.securex_take_rate_limit(text,text,integer,integer) from public, anon, authenticated;
grant execute on function public.securex_take_rate_limit(text,text,integer,integer) to service_role;

alter table public.reports add column if not exists moderation_status text not null default 'approved'
  check (moderation_status in ('pending','approved','rejected'));
alter table public.reports alter column moderation_status set default 'pending';
create index if not exists reports_moderation_url_idx on public.reports(url, moderation_status, created_at desc);
drop policy if exists "Community can read report signals" on public.reports;
create policy "Community can read approved report signals" on public.reports for select to anon using (moderation_status='approved');
-- Cleanup is bounded so scheduled maintenance does not scan an unbounded history.
create index if not exists securex_rate_limits_window_idx on public.securex_rate_limits(window_started);
