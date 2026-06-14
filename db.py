import os
from datetime import datetime, timezone

import streamlit as st
from supabase import create_client, Client

# Per-user cap on Gemini generations per UTC day
DAILY_GENERATION_LIMIT = 3


def _get_secret(name: str):
    """Reads a config value from environment variables or Streamlit secrets."""
    value = os.environ.get(name)
    if value:
        return value
    try:
        return st.secrets[name]
    except (KeyError, FileNotFoundError):
        return None


def get_supabase() -> Client:
    """Returns the per-browser-session Supabase client (created once, reused across reruns).

    The client is kept in session_state because it carries the user's auth
    session after sign-in; recreating it every rerun would drop the login.
    """
    if st.session_state.get("sb") is None:
        url = _get_secret("SUPABASE_URL")
        key = _get_secret("SUPABASE_ANON_KEY")
        if not url or not key:
            st.error(
                "**Supabase is not configured.**\n\n"
                "1. Create a project at https://supabase.com\n"
                "2. Run `supabase_schema.sql` in the project's SQL Editor\n"
                "3. Copy `.streamlit/secrets.toml.example` to `.streamlit/secrets.toml` "
                "and fill in your project URL and anon key (Settings → API)."
            )
            st.stop()
        st.session_state.sb = create_client(url, key)
    return st.session_state.sb


# ==========================================
# AUTH
# ==========================================
def sign_up_user(client: Client, email: str, password: str, display_name: str):
    """Creates a Supabase Auth account. Returns (auth_response, error_message)."""
    try:
        res = client.auth.sign_up({
            "email": email,
            "password": password,
            "options": {"data": {"display_name": display_name}},
        })
        return res, None
    except Exception as e:
        return None, getattr(e, "message", str(e))


def sign_in_user(client: Client, email: str, password: str):
    """Authenticates against Supabase Auth. Returns (auth_response, error_message)."""
    try:
        res = client.auth.sign_in_with_password({"email": email, "password": password})
        return res, None
    except Exception as e:
        return None, getattr(e, "message", str(e))


def sign_out_user(client: Client):
    try:
        client.auth.sign_out()
    except Exception:
        pass


def request_password_reset(client: Client, email: str):
    """Asks Supabase to email a recovery code. Returns an error message or None.

    Note: Supabase intentionally reports success even for unregistered emails,
    to prevent account enumeration.
    """
    try:
        client.auth.reset_password_for_email(email)
        return None
    except Exception as e:
        return getattr(e, "message", str(e))


def verify_recovery_code(client: Client, email: str, code_or_link: str):
    """Exchanges an emailed recovery code OR a pasted recovery link for an authenticated session.

    The default Supabase reset email only contains a link (templates can't be
    customized without custom SMTP), so we also accept the full link and pull
    the token hash out of its query string.

    Returns (auth_response, error_message).
    """
    code_or_link = code_or_link.strip()
    if "token=" in code_or_link:
        from urllib.parse import urlparse, parse_qs
        query = parse_qs(urlparse(code_or_link).query)
        token_hash = (query.get("token") or [None])[0]
        if not token_hash:
            return None, "Couldn't find a token in that link. Paste the full reset link from the email."
        params = {"token_hash": token_hash, "type": "recovery"}
    else:
        params = {"email": email, "token": code_or_link, "type": "recovery"}

    try:
        res = client.auth.verify_otp(params)
        return res, None
    except Exception as e:
        return None, getattr(e, "message", str(e))


def update_password(client: Client, new_password: str):
    """Sets a new password for the currently authenticated user. Returns an error message or None."""
    try:
        client.auth.update_user({"password": new_password})
        return None
    except Exception as e:
        return getattr(e, "message", str(e))


def fetch_profile(client: Client, user_id: str):
    """Fetches the user's profile row (display name + encryption salt)."""
    res = client.table("profiles").select("*").eq("id", user_id).execute()
    return res.data[0] if res.data else None


# ==========================================
# REFLECTION SESSIONS (encrypted payloads)
# ==========================================
def fetch_sessions(client: Client, user_id: str):
    """Returns the user's reflection sessions, newest first."""
    res = (
        client.table("reflection_sessions")
        .select("*")
        .eq("user_id", user_id)
        .order("created_at", desc=True)
        .execute()
    )
    return res.data or []


def insert_session_row(client: Client, user_id: str, summary: str,
                       enc_profile: str, enc_questions: str, enc_journals: str):
    res = client.table("reflection_sessions").insert({
        "user_id": user_id,
        "summary": summary,
        "profile_details": enc_profile,
        "questions": enc_questions,
        "journal_entries": enc_journals,
    }).execute()
    return res.data[0] if res.data else None


def update_session_journals(client: Client, session_id: str, enc_journals: str):
    client.table("reflection_sessions").update(
        {"journal_entries": enc_journals}
    ).eq("id", session_id).execute()


def update_session_payloads(client: Client, session_id: str,
                            enc_profile: str, enc_questions: str, enc_journals: str):
    """Rewrites all encrypted columns of a session (used for password-change re-encryption)."""
    client.table("reflection_sessions").update({
        "profile_details": enc_profile,
        "questions": enc_questions,
        "journal_entries": enc_journals,
    }).eq("id", session_id).execute()


# ==========================================
# DAILY GENERATION LIMIT
# ==========================================
def count_generations_today(client: Client, user_id: str) -> int:
    """Counts Gemini generations the user has performed since UTC midnight."""
    day_start = datetime.now(timezone.utc).replace(
        hour=0, minute=0, second=0, microsecond=0
    ).isoformat()
    res = (
        client.table("generation_log")
        .select("id", count="exact")
        .eq("user_id", user_id)
        .gte("created_at", day_start)
        .execute()
    )
    return res.count or 0


def log_generation(client: Client, user_id: str):
    client.table("generation_log").insert({"user_id": user_id}).execute()
