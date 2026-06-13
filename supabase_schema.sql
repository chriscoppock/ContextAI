-- ContextAI Supabase schema
-- Run this once in your Supabase project's SQL Editor.

create extension if not exists pgcrypto;

-- ==========================================
-- PROFILES: display name + per-user encryption salt
-- (auto-created by trigger when an auth user registers)
-- ==========================================
create table public.profiles (
    id uuid primary key references auth.users (id) on delete cascade,
    display_name text not null,
    encryption_salt text not null,
    created_at timestamptz not null default now()
);

alter table public.profiles enable row level security;

create policy "Users can read own profile"
    on public.profiles for select
    using (auth.uid() = id);

-- Auto-create a profile (with a random encryption salt) for every new auth user
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer set search_path = public
as $$
begin
    insert into public.profiles (id, display_name, encryption_salt)
    values (
        new.id,
        coalesce(new.raw_user_meta_data ->> 'display_name', 'Friend'),
        encode(gen_random_bytes(16), 'hex')
    );
    return new;
end;
$$;

create trigger on_auth_user_created
    after insert on auth.users
    for each row execute function public.handle_new_user();

-- ==========================================
-- REFLECTION SESSIONS: encrypted journal payloads
-- (profile_details / questions / journal_entries are Fernet ciphertext)
-- ==========================================
create table public.reflection_sessions (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references auth.users (id) on delete cascade,
    summary text not null,
    profile_details text not null,
    questions text not null,
    journal_entries text not null,
    created_at timestamptz not null default now()
);

create index reflection_sessions_user_created_idx
    on public.reflection_sessions (user_id, created_at desc);

alter table public.reflection_sessions enable row level security;

create policy "Users can read own sessions"
    on public.reflection_sessions for select
    using (auth.uid() = user_id);

create policy "Users can insert own sessions"
    on public.reflection_sessions for insert
    with check (auth.uid() = user_id);

create policy "Users can update own sessions"
    on public.reflection_sessions for update
    using (auth.uid() = user_id);

-- ==========================================
-- GENERATION LOG: enforces the daily Gemini generation limit
-- ==========================================
create table public.generation_log (
    id bigint generated always as identity primary key,
    user_id uuid not null references auth.users (id) on delete cascade,
    created_at timestamptz not null default now()
);

create index generation_log_user_created_idx
    on public.generation_log (user_id, created_at desc);

alter table public.generation_log enable row level security;

create policy "Users can read own generation log"
    on public.generation_log for select
    using (auth.uid() = user_id);

create policy "Users can insert own generation log"
    on public.generation_log for insert
    with check (auth.uid() = user_id);
