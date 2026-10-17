-- Double Feature starter schema for a shared, authenticated deployment.
-- Review and test these policies in a non-production Supabase project first.
-- Create rooms and memberships through a trusted server-side/admin flow.
create extension if not exists pgcrypto;

create table if not exists public.rooms (
  id uuid primary key default gen_random_uuid(),
  name text not null default 'Double Feature',
  created_at timestamptz not null default now()
);

create table if not exists public.room_members (
  room_id uuid not null references public.rooms(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  display_name text not null,
  created_at timestamptz not null default now(),
  primary key (room_id, user_id)
);

create table if not exists public.titles (
  id uuid primary key default gen_random_uuid(),
  room_id uuid not null references public.rooms(id) on delete cascade,
  tmdb_id bigint,
  media_type text not null check (media_type in ('movie','tv')),
  title text not null,
  overview text not null default '',
  poster_path text,
  custom_image_path text,
  release_year integer,
  genres jsonb not null default '[]'::jsonb,
  added_by uuid not null references auth.users(id),
  status text not null default 'candidate' check (status in ('candidate','chosen','watched','dismissed')),
  created_at timestamptz not null default now(),
  unique (room_id, media_type, tmdb_id)
);

create table if not exists public.ratings (
  id uuid primary key default gen_random_uuid(),
  room_id uuid not null references public.rooms(id) on delete cascade,
  title_id uuid not null references public.titles(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  own_interest smallint not null check (own_interest between 0 and 10),
  partner_estimate smallint not null check (partner_estimate between 0 and 10),
  updated_at timestamptz not null default now(),
  unique (title_id, user_id)
);

create index if not exists titles_room_created_idx on public.titles(room_id, created_at desc);
create index if not exists ratings_room_title_idx on public.ratings(room_id, title_id);

alter table public.rooms enable row level security;
alter table public.room_members enable row level security;
alter table public.titles enable row level security;
alter table public.ratings enable row level security;

-- SECURITY DEFINER avoids recursive RLS when checking membership in room_members.
-- Keep this function narrowly scoped and do not let clients choose the user id.
create or replace function public.is_room_member(target_room_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.room_members m
    where m.room_id = target_room_id and m.user_id = (select auth.uid())
  );
$$;

revoke all on function public.is_room_member(uuid) from public;
grant execute on function public.is_room_member(uuid) to authenticated;

create policy "members can read rooms" on public.rooms for select
using (public.is_room_member(id));

create policy "members can read room members" on public.room_members for select
using (public.is_room_member(room_id));

-- Membership creation/deletion should be performed by a trusted admin flow.
-- No client insert/update/delete policy is intentionally provided for room_members.

create policy "members can read titles" on public.titles for select
using (public.is_room_member(room_id));

create policy "members can add titles" on public.titles for insert
with check (added_by = (select auth.uid()) and public.is_room_member(room_id));

create policy "members can update titles" on public.titles for update
using (public.is_room_member(room_id))
with check (public.is_room_member(room_id));

create policy "members can delete titles" on public.titles for delete
using (public.is_room_member(room_id));

create policy "members can read ratings" on public.ratings for select
using (public.is_room_member(room_id));

create policy "members can add own rating" on public.ratings for insert
with check (
  user_id = (select auth.uid())
  and public.is_room_member(room_id)
  and exists (select 1 from public.titles t where t.id = title_id and t.room_id = room_id)
);

create policy "members can update own rating" on public.ratings for update
using (user_id = (select auth.uid()) and public.is_room_member(room_id))
with check (
  user_id = (select auth.uid())
  and public.is_room_member(room_id)
  and exists (select 1 from public.titles t where t.id = title_id and t.room_id = room_id)
);

create policy "members can delete own rating" on public.ratings for delete
using (user_id = (select auth.uid()) and public.is_room_member(room_id));

-- Shared score is calculated only when both rating rows exist:
-- (A.own_interest * B.own_interest) + (A.partner_estimate * B.partner_estimate)
-- Display a shared score only once both rows exist.
