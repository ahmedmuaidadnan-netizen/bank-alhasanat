-- Run this script in Supabase SQL Editor
-- It creates a direct phone/password login table (without Supabase Auth).

create extension if not exists pgcrypto;

create table if not exists public.members (
  id uuid primary key default gen_random_uuid(),
  full_name text not null,
  phone text not null,
  password text not null,
  istighfar integer not null default 0,
  salawat integer not null default 0,
  quran_parts integer not null default 0,
  created_at timestamptz not null default now()
);

alter table public.members add column if not exists full_name text;
alter table public.members add column if not exists phone text;
alter table public.members add column if not exists password text;
alter table public.members add column if not exists istighfar integer not null default 0;
alter table public.members add column if not exists salawat integer not null default 0;
alter table public.members add column if not exists quran_parts integer not null default 0;
alter table public.members add column if not exists created_at timestamptz not null default now();

create unique index if not exists members_phone_unique_idx on public.members (phone);

create table if not exists public.member_activity (
  id uuid primary key default gen_random_uuid(),
  member_id uuid not null references public.members (id) on delete cascade,
  delta_istighfar integer not null default 0,
  delta_salawat integer not null default 0,
  delta_quran_parts integer not null default 0,
  source text not null default 'member',
  created_at timestamptz not null default now()
);

create index if not exists member_activity_created_at_idx on public.member_activity (created_at desc);
create index if not exists member_activity_member_id_idx on public.member_activity (member_id);

alter table public.members enable row level security;
alter table public.member_activity enable row level security;

grant usage on schema public to anon, authenticated;
grant select, insert, update, delete on table public.members to anon, authenticated;
grant select, insert, delete on table public.member_activity to anon, authenticated;

create table if not exists public.member_security (
  member_id uuid primary key references public.members (id) on delete cascade,
  violation_level integer not null default 0,
  ban_until timestamptz,
  updated_at timestamptz not null default now()
);

alter table public.member_security enable row level security;
grant select, insert, update on table public.member_security to anon, authenticated;

drop policy if exists "Public read members" on public.members;
create policy "Public read members"
on public.members
for select
to anon, authenticated
using (true);

drop policy if exists "Public insert members" on public.members;
create policy "Public insert members"
on public.members
for insert
to anon, authenticated
with check (true);

drop policy if exists "Public update members" on public.members;
create policy "Public update members"
on public.members
for update
to anon, authenticated
using (true)
with check (true);

drop policy if exists "Public delete members" on public.members;
create policy "Public delete members"
on public.members
for delete
to anon, authenticated
using (true);

drop policy if exists "Public read activity" on public.member_activity;
create policy "Public read activity"
on public.member_activity
for select
to anon, authenticated
using (true);

drop policy if exists "Public insert activity" on public.member_activity;
create policy "Public insert activity"
on public.member_activity
for insert
to anon, authenticated
with check (true);

drop policy if exists "Public delete activity" on public.member_activity;
create policy "Public delete activity"
on public.member_activity
for delete
to anon, authenticated
using (true);

drop policy if exists "Public read member security" on public.member_security;
create policy "Public read member security"
on public.member_security
for select
to anon, authenticated
using (true);

drop policy if exists "Public insert member security" on public.member_security;
create policy "Public insert member security"
on public.member_security
for insert
to anon, authenticated
with check (true);

drop policy if exists "Public update member security" on public.member_security;
create policy "Public update member security"
on public.member_security
for update
to anon, authenticated
using (true)
with check (true);

create or replace function public.submit_competition_count(
  p_phone text,
  p_password text,
  p_metric text,
  p_increment integer
)
returns table(member_total integer, global_total bigint)
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_member public.members%rowtype;
  v_password_hash text;
  v_recent_sum integer;
  v_now timestamptz := now();
  v_ban_until timestamptz;
  v_member_total integer;
  v_global_total bigint;
begin
  if p_increment is null or p_increment < 1 or p_increment > 300 then
    raise exception 'invalid increment';
  end if;

  if p_metric not in ('istighfar', 'salawat') then
    raise exception 'invalid metric';
  end if;

  select * into v_member
  from public.members
  where phone = p_phone
  limit 1;

  if not found then
    raise exception 'member not found';
  end if;

  if left(v_member.password, 7) = 'sha256$' then
    v_password_hash := 'sha256$' || encode(digest(p_password, 'sha256'), 'hex');
    if v_member.password <> v_password_hash then
      raise exception 'invalid password';
    end if;
  else
    if v_member.password <> p_password then
      raise exception 'invalid password';
    end if;
  end if;

  select ban_until
    into v_ban_until
  from public.member_security
  where member_id = v_member.id
  limit 1;

  if v_ban_until is not null and v_ban_until > v_now then
    raise exception 'banned until %', to_char(v_ban_until, 'YYYY-MM-DD HH24:MI');
  end if;

  if p_metric = 'istighfar' then
    select coalesce(sum(delta_istighfar), 0)
      into v_recent_sum
    from public.member_activity
    where member_id = v_member.id
      and source = 'member_competition'
      and created_at >= (v_now - interval '1 minute');
  else
    select coalesce(sum(delta_salawat), 0)
      into v_recent_sum
    from public.member_activity
    where member_id = v_member.id
      and source = 'member_competition'
      and created_at >= (v_now - interval '1 minute');
  end if;

  if (v_recent_sum + p_increment) > 600 then
    raise exception 'rate limit exceeded';
  end if;

  if p_metric = 'istighfar' then
    update public.members
      set istighfar = istighfar + p_increment
    where id = v_member.id
    returning istighfar into v_member_total;

    insert into public.member_activity (
      member_id,
      delta_istighfar,
      delta_salawat,
      delta_quran_parts,
      source
    ) values (
      v_member.id,
      p_increment,
      0,
      0,
      'member_competition'
    );

    select coalesce(sum(istighfar), 0)::bigint into v_global_total from public.members;
  else
    update public.members
      set salawat = salawat + p_increment
    where id = v_member.id
    returning salawat into v_member_total;

    insert into public.member_activity (
      member_id,
      delta_istighfar,
      delta_salawat,
      delta_quran_parts,
      source
    ) values (
      v_member.id,
      0,
      p_increment,
      0,
      'member_competition'
    );

    select coalesce(sum(salawat), 0)::bigint into v_global_total from public.members;
  end if;

  return query select v_member_total, v_global_total;
end;
$$;

grant execute on function public.submit_competition_count(text, text, text, integer)
to anon, authenticated;

create or replace function public.apply_fast_tap_penalty(
  p_phone text,
  p_password text
)
returns table(violation_level integer, ban_until timestamptz)
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_member public.members%rowtype;
  v_password_hash text;
  v_security public.member_security%rowtype;
  v_next_level integer;
  v_new_ban_until timestamptz;
begin
  select * into v_member
  from public.members
  where phone = p_phone
  limit 1;

  if not found then
    raise exception 'member not found';
  end if;

  if left(v_member.password, 7) = 'sha256$' then
    v_password_hash := 'sha256$' || encode(digest(p_password, 'sha256'), 'hex');
    if v_member.password <> v_password_hash then
      raise exception 'invalid password';
    end if;
  else
    if v_member.password <> p_password then
      raise exception 'invalid password';
    end if;
  end if;

  insert into public.member_security (member_id, violation_level, ban_until, updated_at)
  values (v_member.id, 0, null, now())
  on conflict (member_id) do nothing;

  select * into v_security
  from public.member_security
  where member_id = v_member.id
  for update;

  v_next_level := least(coalesce(v_security.violation_level, 0) + 1, 3);
  if v_next_level = 1 then
    v_new_ban_until := now() + interval '1 hour';
  elsif v_next_level = 2 then
    v_new_ban_until := now() + interval '1 day';
  else
    v_new_ban_until := now() + interval '1 month';
  end if;

  update public.member_security
    set violation_level = v_next_level,
        ban_until = v_new_ban_until,
        updated_at = now()
  where member_id = v_member.id;

  return query select v_next_level, v_new_ban_until;
end;
$$;

grant execute on function public.apply_fast_tap_penalty(text, text)
to anon, authenticated;

create table if not exists public.group_khatma_parts (
  part_number integer primary key,
  reserved_by_member_id uuid references public.members (id) on delete set null,
  reserved_by_name text,
  reserved_at timestamptz
);

insert into public.group_khatma_parts (part_number)
select gs
from generate_series(1, 30) as gs
on conflict (part_number) do nothing;

create table if not exists public.group_khatma_stats (
  id integer primary key,
  khatma_count integer not null default 0,
  total_parts_read integer not null default 0,
  total_surahs_read integer not null default 0,
  total_ayat_read integer not null default 0,
  updated_at timestamptz not null default now()
);

insert into public.group_khatma_stats (id, khatma_count, total_parts_read, total_surahs_read, total_ayat_read)
values (1, 0, 0, 0, 0)
on conflict (id) do nothing;

alter table public.group_khatma_parts enable row level security;
alter table public.group_khatma_stats enable row level security;

grant select, update on table public.group_khatma_parts to anon, authenticated;
grant select, insert, update on table public.group_khatma_stats to anon, authenticated;

drop policy if exists "Public read khatma parts" on public.group_khatma_parts;
create policy "Public read khatma parts"
on public.group_khatma_parts
for select
to anon, authenticated
using (true);

drop policy if exists "Public update khatma parts" on public.group_khatma_parts;
create policy "Public update khatma parts"
on public.group_khatma_parts
for update
to anon, authenticated
using (true)
with check (true);

drop policy if exists "Public read khatma stats" on public.group_khatma_stats;
create policy "Public read khatma stats"
on public.group_khatma_stats
for select
to anon, authenticated
using (true);

drop policy if exists "Public update khatma stats" on public.group_khatma_stats;
create policy "Public update khatma stats"
on public.group_khatma_stats
for update
to anon, authenticated
using (true)
with check (true);

drop policy if exists "Public insert khatma stats" on public.group_khatma_stats;
create policy "Public insert khatma stats"
on public.group_khatma_stats
for insert
to anon, authenticated
with check (true);

create or replace function public.complete_group_khatma()
returns void
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_reserved_count integer;
begin
  select count(*) into v_reserved_count
  from public.group_khatma_parts
  where reserved_by_member_id is not null;

  if v_reserved_count <> 30 then
    raise exception 'all 30 parts must be reserved first';
  end if;

  insert into public.group_khatma_stats (
    id, khatma_count, total_parts_read, total_surahs_read, total_ayat_read, updated_at
  )
  values (1, 1, 30, 114, 6236, now())
  on conflict (id) do update
  set khatma_count = public.group_khatma_stats.khatma_count + 1,
      total_parts_read = public.group_khatma_stats.total_parts_read + 30,
      total_surahs_read = public.group_khatma_stats.total_surahs_read + 114,
      total_ayat_read = public.group_khatma_stats.total_ayat_read + 6236,
      updated_at = now();

  update public.group_khatma_parts
  set reserved_by_member_id = null,
      reserved_by_name = null,
      reserved_at = null
  where part_number between 1 and 30;
end;
$$;

grant execute on function public.complete_group_khatma()
to anon, authenticated;

create or replace function public.reserve_khatma_part(
  p_member_id uuid,
  p_member_name text,
  p_part_number integer
)
returns table(success boolean, message text)
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_reserved_count integer;
  v_part_taken uuid;
begin
  if p_part_number < 1 or p_part_number > 30 then
    return query select false, 'رقم الجزء غير صحيح.';
    return;
  end if;

  select count(*) into v_reserved_count
  from public.group_khatma_parts
  where reserved_by_member_id = p_member_id;

  if v_reserved_count >= 2 then
    return query select false, 'الحد الأقصى لحجزك في الختمة الواحدة هو جزآن فقط.';
    return;
  end if;

  select reserved_by_member_id into v_part_taken
  from public.group_khatma_parts
  where part_number = p_part_number
  limit 1;

  if v_part_taken is not null then
    return query select false, 'هذا الجزء محجوز بالفعل.';
    return;
  end if;

  update public.group_khatma_parts
    set reserved_by_member_id = p_member_id,
        reserved_by_name = p_member_name,
        reserved_at = now()
  where part_number = p_part_number
    and reserved_by_member_id is null;

  if not found then
    return query select false, 'الجزء تم حجزه قبل لحظات من عضو آخر.';
    return;
  end if;

  return query select true, 'تم حجز هذا الجزء لك بنجاح. نرجو الالتزام بقراءته وإتمامه؛ فهو أمانة في ذمتك.';
end;
$$;

grant execute on function public.reserve_khatma_part(uuid, text, integer)
to anon, authenticated;

-- Cleanup helper: remove old activity logs without touching totals in members table.
create or replace function public.cleanup_old_member_activity(p_keep_days integer default 90)
returns integer
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_deleted_count integer := 0;
begin
  if p_keep_days is null or p_keep_days < 1 then
    raise exception 'p_keep_days must be >= 1';
  end if;

  delete from public.member_activity
  where created_at < (now() - make_interval(days => p_keep_days));

  get diagnostics v_deleted_count = row_count;
  return v_deleted_count;
end;
$$;

grant execute on function public.cleanup_old_member_activity(integer)
to anon, authenticated;
