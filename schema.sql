-- رحلة مع سفر طوبيا: Supabase schema
-- نفّذ هذا الملف في Supabase > SQL Editor بعد إنشاء مشروع جديد.
create extension if not exists pgcrypto;

create table if not exists public.participants (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  active boolean not null default true,
  created_at timestamptz not null default now()
);
create unique index if not exists participants_name_unique on public.participants (lower(trim(name)));

create table if not exists public.reading_days (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  passage text,
  notes text,
  reading_date date not null,
  published boolean not null default false,
  created_at timestamptz not null default now()
);
create table if not exists public.questions (
  id uuid primary key default gen_random_uuid(),
  reading_day_id uuid not null references public.reading_days(id) on delete cascade,
  question_text text not null,
  option_1 text not null,
  option_2 text not null,
  option_3 text not null,
  created_at timestamptz not null default now()
);
create table if not exists public.progress (
  id uuid primary key default gen_random_uuid(),
  participant_id uuid not null references public.participants(id) on delete cascade,
  reading_day_id uuid not null references public.reading_days(id) on delete cascade,
  completed boolean not null default false,
  completed_at timestamptz,
  unique(participant_id, reading_day_id)
);
create table if not exists public.question_answer_keys (
  question_id uuid primary key references public.questions(id) on delete cascade,
  correct_option int not null check (correct_option between 0 and 2)
);
create table if not exists public.answers (
  id uuid primary key default gen_random_uuid(),
  participant_id uuid not null references public.participants(id) on delete cascade,
  question_id uuid not null references public.questions(id) on delete cascade,
  selected_option int not null check (selected_option between 0 and 2),
  is_correct boolean not null default false,
  created_at timestamptz not null default now(),
  unique(participant_id, question_id)
);

alter table public.participants enable row level security;
alter table public.reading_days enable row level security;
alter table public.questions enable row level security;
alter table public.progress enable row level security;
alter table public.answers enable row level security;
alter table public.question_answer_keys enable row level security;

-- Admin role: create an Auth user, then set app_metadata.role = "admin"
-- from a trusted server/admin environment. Never expose the service_role key in the website.
create or replace function public.is_admin()
returns boolean language sql stable as $$
  select coalesce(auth.jwt() -> 'app_metadata' ->> 'role', '') = 'admin';
$$;

-- Public participants can read active names to choose their name.
drop policy if exists "public read active participants" on public.participants;
create policy "public read active participants" on public.participants
for select to anon, authenticated using (active = true or public.is_admin());
drop policy if exists "admin manage participants" on public.participants;
create policy "admin manage participants" on public.participants
for all to authenticated using (public.is_admin()) with check (public.is_admin());

-- Public can read only published readings and their questions.
drop policy if exists "public read published days" on public.reading_days;
create policy "public read published days" on public.reading_days
for select to anon, authenticated using (published = true or public.is_admin());
drop policy if exists "admin manage days" on public.reading_days;
create policy "admin manage days" on public.reading_days
for all to authenticated using (public.is_admin()) with check (public.is_admin());

drop policy if exists "public read questions for published days" on public.questions;
create policy "public read questions for published days" on public.questions
for select to anon, authenticated using (
  exists (select 1 from public.reading_days d where d.id = reading_day_id and d.published = true)
  or public.is_admin()
);
drop policy if exists "admin manage questions" on public.questions;
create policy "admin manage questions" on public.questions
for all to authenticated using (public.is_admin()) with check (public.is_admin());
drop policy if exists "admin manage answer keys" on public.question_answer_keys;
create policy "admin manage answer keys" on public.question_answer_keys
for all to authenticated using (public.is_admin()) with check (public.is_admin());

-- Prototype: participants can submit/update their own selected participant row.
-- Important limitation: name-only entry is not identity verification; users may select another name.
drop policy if exists "public submit progress" on public.progress;
create policy "public submit progress" on public.progress
for insert to anon, authenticated with check (
  completed = true and exists (select 1 from public.participants p where p.id = participant_id and p.active = true)
  and exists (select 1 from public.reading_days d where d.id = reading_day_id and d.published = true)
);
drop policy if exists "public update progress" on public.progress;
create policy "public update progress" on public.progress
for update to anon, authenticated using (true) with check (
  completed = true and exists (select 1 from public.participants p where p.id = participant_id and p.active = true)
  and exists (select 1 from public.reading_days d where d.id = reading_day_id and d.published = true)
);
drop policy if exists "admin read progress" on public.progress;
create policy "admin read progress" on public.progress
for select to authenticated using (public.is_admin());

-- Answers are submitted through a database function so the correct answer stays private.
create or replace function public.submit_answer(
  p_participant_id uuid,
  p_question_id uuid,
  p_selected_option int
) returns boolean
language plpgsql
security definer
set search_path = public
as $$
declare v_correct int; v_day uuid;
begin
  if p_selected_option < 0 or p_selected_option > 2 then
    raise exception 'Invalid option';
  end if;
  if not exists (select 1 from participants where id=p_participant_id and active=true) then
    raise exception 'Participant not found';
  end if;
  select q.reading_day_id into v_day from questions q where q.id=p_question_id;
  if v_day is null or not exists (select 1 from reading_days where id=v_day and published=true) then
    raise exception 'Question is not available';
  end if;
  select correct_option into v_correct from question_answer_keys where question_id=p_question_id;
  if v_correct is null then raise exception 'Answer key missing'; end if;
  insert into answers(participant_id,question_id,selected_option,is_correct)
  values(p_participant_id,p_question_id,p_selected_option,p_selected_option=v_correct)
  on conflict(participant_id,question_id) do update
    set selected_option=excluded.selected_option,is_correct=excluded.is_correct,created_at=now();
  return p_selected_option=v_correct;
end;
$$;
grant execute on function public.submit_answer(uuid,uuid,int) to anon, authenticated;
drop policy if exists "admin read answers" on public.answers;
create policy "admin read answers" on public.answers
for select to authenticated using (public.is_admin());

grant usage on schema public to anon, authenticated;
grant select on public.participants, public.reading_days, public.questions to anon, authenticated;
grant insert, update on public.progress to anon, authenticated;
grant select, insert, update, delete on public.participants, public.reading_days, public.questions, public.question_answer_keys to authenticated;
grant select on public.progress, public.answers to authenticated;
