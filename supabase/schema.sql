-- Выполнить один раз: Supabase → SQL Editor → New query → вставить всё → Run

create table if not exists public.devices (
  id          text primary key,
  sub         jsonb not null,
  updated_at  timestamptz not null default now()
);

-- Доступ к таблице только у функции (сервисный ключ). Публичный ключ ничего не прочитает.
alter table public.devices enable row level security;
revoke all on public.devices from anon, authenticated;
grant all on public.devices to service_role;
