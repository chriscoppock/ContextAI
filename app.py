import streamlit as st
import json
import base64
import urllib.parse
from datetime import datetime

# Secure Cryptographic Imports
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import db
from db import DAILY_GENERATION_LIMIT
from models import (
    LifeStage,
    LivingSituation,
    RelationshipStatus,
    LifeTheme,
    UserContextProfile,
    BaselineProfile,
    RelationshipProfile,
    OutletsProfile
)
from prompt_engine import PromptEngine

# ==========================================
# ZERO-KNOWLEDGE CRYPTOGRAPHY HELPERS
# ==========================================
def derive_encryption_key(password: str, salt_hex: str) -> str:
    """Derives a secure, symmetric AES-256 Fernet key from the user's password."""
    salt = bytes.fromhex(salt_hex)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
    return key.decode('utf-8')

def encrypt_data(data, key_str: str) -> str:
    """Serializes and encrypts Python data (dicts, lists) using AES-256 Fernet."""
    if not key_str:
        raise ValueError("Encryption key is missing. Please log in.")
    serialized = json.dumps(data).encode('utf-8')
    fernet = Fernet(key_str.encode('utf-8'))
    encrypted = fernet.encrypt(serialized)
    return encrypted.decode('utf-8')

def decrypt_data(encrypted_str: str, key_str: str):
    """Decrypts AES-256 Fernet ciphertext strings back into Python data."""
    if not key_str:
        raise ValueError("Decryption key is missing. Please log in.")
    fernet = Fernet(key_str.encode('utf-8'))
    decrypted_bytes = fernet.decrypt(encrypted_str.encode('utf-8'))
    return json.loads(decrypted_bytes.decode('utf-8'))

# ==========================================
# SUPABASE-BACKED HISTORY HELPERS
# ==========================================
def format_timestamp(iso_str: str) -> str:
    """Renders a Supabase UTC timestamp in the viewer's local time."""
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        return dt.astimezone().strftime("%Y-%m-%d %I:%M %p")
    except Exception:
        return iso_str

def load_and_decrypt_history(client, user_id, key_str):
    """Loads and decrypts the user's reflection sessions from Supabase."""
    user_history = []
    for row in db.fetch_sessions(client, user_id):
        entry = {
            "id": row["id"],
            "timestamp": format_timestamp(row["created_at"]),
            "summary": row["summary"],
        }
        try:
            entry["profile_details"] = decrypt_data(row["profile_details"], key_str)
            entry["questions"] = decrypt_data(row["questions"], key_str)
            entry["journal_entries"] = decrypt_data(row["journal_entries"], key_str)
        except Exception:
            entry["profile_details"] = {}
            entry["questions"] = []
            entry["journal_entries"] = {}
            entry["decryption_failed"] = True
        user_history.append(entry)
    return user_history

def save_session_to_history(client, user_id, summary_label, raw_profile_dict, curated_questions, key_str):
    """Encrypts and inserts a newly generated reflection session into Supabase."""
    serialized_questions = []
    for q in curated_questions:
        serialized_questions.append({
            "category": q.category,
            "question_text": q.question_text,
            "insight_trigger": q.insight_trigger
        })

    enc_profile = encrypt_data(raw_profile_dict, key_str)
    enc_questions = encrypt_data(serialized_questions, key_str)
    enc_journals = encrypt_data({}, key_str)

    return db.insert_session_row(
        client, user_id, summary_label, enc_profile, enc_questions, enc_journals
    )

def save_journal_answer(client, session, question_idx, answer_text, key_str):
    """Updates one reflection answer and re-encrypts the session's journal payload."""
    session["journal_entries"][str(question_idx)] = answer_text
    enc_journals = encrypt_data(session["journal_entries"], key_str)
    db.update_session_journals(client, session["id"], enc_journals)

# ==========================================
# EXPORT GENERATION UTILITY
# ==========================================
def format_export_markdown(session, user_name) -> str:
    """Formats a session's data (questions + answers) into markdown."""
    md = f"# ContextAI Journal Reflection\n"
    md += f"**User:** {user_name}\n"
    md += f"**Date:** {session['timestamp']}\n"
    md += f"**Context Theme Focus:** {session['summary']}\n\n"
    md += "---\n\n"

    for idx, q in enumerate(session['questions']):
        md += f"### Q{idx + 1}: {q['category']}\n"
        md += f"*{q['question_text']}*\n\n"

        answer = session['journal_entries'].get(str(idx), "")
        if answer.strip():
            md += f"**My Reflection:**\n> {answer}\n\n"
        else:
            md += f"**My Reflection:**\n*Unanswered*\n\n"
        md += "---\n\n"

    return md

# ==========================================
# STREAMLIT UI DESIGN & WORKFLOW
# ==========================================
st.set_page_config(page_title="ContextAI", page_icon="🧩", layout="centered")

# Track authentication status
if "sb" not in st.session_state:
    st.session_state.sb = None
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "user_id" not in st.session_state:
    st.session_state.user_id = None
if "email" not in st.session_state:
    st.session_state.email = None
if "display_name" not in st.session_state:
    st.session_state.display_name = None
if "encryption_key" not in st.session_state:
    st.session_state.encryption_key = None
if "encryption_salt" not in st.session_state:
    st.session_state.encryption_salt = None

# Forgot-password flow state
if "reset_stage" not in st.session_state:
    st.session_state.reset_stage = None
if "reset_email" not in st.session_state:
    st.session_state.reset_email = None

# Track generation workflow states
if "survey_submitted" not in st.session_state:
    st.session_state.survey_submitted = False
if "user_profile" not in st.session_state:
    st.session_state.user_profile = None
if "current_response" not in st.session_state:
    st.session_state.current_response = None
if "active_summary_label" not in st.session_state:
    st.session_state.active_summary_label = ""
if "active_raw_profile" not in st.session_state:
    st.session_state.active_raw_profile = {}

# Memory Retention Profile Dictionary Setup
if "form_defaults" not in st.session_state:
    st.session_state.form_defaults = {
        "life_stage": list(LifeStage)[0].value if list(LifeStage) else "",
        "living_situation": list(LivingSituation)[0].value if list(LivingSituation) else "",
        "professional_focus": "",
        "relationship_status": list(RelationshipStatus)[0].value if list(RelationshipStatus) else "",
        "has_dependents": False,
        "custody_details": "",
        "key_pillars": "",
        "creative": "",
        "recreation": "",
        "rituals": "",
        "themes": [],
        "additional_notes": ""
    }

def complete_login(user_id, email, display_name, encryption_key, encryption_salt):
    """Populates session state after a successful Supabase sign-in."""
    st.session_state.logged_in = True
    st.session_state.user_id = user_id
    st.session_state.email = email
    st.session_state.display_name = display_name
    st.session_state.encryption_key = encryption_key
    st.session_state.encryption_salt = encryption_salt
    st.session_state.reset_stage = None
    st.session_state.reset_email = None

# ==========================================
# GUEST / SECURE PORTAL INTERFACE
# ==========================================
if not st.session_state.logged_in:
    st.title("🧩 ContextAI Secure Portal")
    st.write("Welcome to your private prompt refinery. Sign in to load and encrypt your customized journals.")

    supabase = db.get_supabase()
    auth_mode = st.radio("Choose Action", ["Sign In", "Register Private Profile", "Reset Forgotten Password"], horizontal=True)

    if auth_mode == "Sign In":
        with st.form("login_form"):
            email_input = st.text_input("Email").strip()
            pass_input = st.text_input("Password", type="password")
            btn_submit = st.form_submit_button("Access Secure Sandbox")

            if btn_submit:
                if not email_input or not pass_input:
                    st.error("Fields cannot be empty.")
                else:
                    auth_res, error_msg = db.sign_in_user(supabase, email_input, pass_input)
                    if error_msg:
                        st.error(error_msg)
                    else:
                        profile = db.fetch_profile(supabase, auth_res.user.id)
                        if profile is None:
                            st.error("Account profile not found. Make sure supabase_schema.sql has been run in your Supabase project.")
                        else:
                            encryption_key = derive_encryption_key(pass_input, profile["encryption_salt"])
                            complete_login(
                                auth_res.user.id,
                                email_input,
                                profile["display_name"],
                                encryption_key,
                                profile["encryption_salt"]
                            )
                            st.rerun()

    elif auth_mode == "Register Private Profile":
        with st.form("register_form"):
            st.info(
                "Your password is cryptographically combined with a randomized salt to encrypt your journal data. "
                "**If you lose your password, your encrypted journals cannot be recovered.**"
            )
            reg_email = st.text_input("Email Address").strip()
            reg_display = st.text_input("Preferred Nickname (addressed by AI)").strip()
            reg_pass = st.text_input("Secure Password (8+ characters)", type="password")
            reg_pass_conf = st.text_input("Confirm Password", type="password")

            btn_register = st.form_submit_button("Instantiate My Account")

            if btn_register:
                if not reg_email or not reg_display or not reg_pass:
                    st.error("All credentials are required.")
                elif "@" not in reg_email or "." not in reg_email:
                    st.error("Please enter a valid email address.")
                elif len(reg_pass) < 8:
                    st.error("Password must be at least 8 characters long.")
                elif reg_pass != reg_pass_conf:
                    st.error("Passwords do not match.")
                else:
                    auth_res, error_msg = db.sign_up_user(supabase, reg_email, reg_pass, reg_display)
                    if error_msg:
                        st.error(error_msg)
                    elif auth_res.session is None:
                        # Email confirmation is enabled on the Supabase project
                        st.success("Account created! Check your email for a confirmation link, then return here to sign in.")
                    else:
                        profile = db.fetch_profile(supabase, auth_res.user.id)
                        if profile is None:
                            st.error("Account created, but no profile was found. Make sure supabase_schema.sql has been run in your Supabase project.")
                        else:
                            encryption_key = derive_encryption_key(reg_pass, profile["encryption_salt"])
                            complete_login(
                                auth_res.user.id,
                                reg_email,
                                profile["display_name"],
                                encryption_key,
                                profile["encryption_salt"]
                            )
                            st.rerun()

    else:  # Reset Forgotten Password
        st.warning(
            "⚠️ **Read this first:** your journals are encrypted with a key derived from your password. "
            "Resetting a *forgotten* password restores access to your account, but **existing journal "
            "entries will become unreadable** — we never have the key to decrypt them. "
            "(If you simply want a new password and still know your current one, sign in and use "
            "**Change Password** in the sidebar instead — that path re-encrypts everything with no data loss.)"
        )

        if st.session_state.reset_stage != "verify":
            with st.form("reset_request_form"):
                reset_email_input = st.text_input("Account Email").strip()
                btn_send_code = st.form_submit_button("Email Me a Reset Code")

                if btn_send_code:
                    if not reset_email_input:
                        st.error("Please enter your account email.")
                    else:
                        error_msg = db.request_password_reset(supabase, reset_email_input)
                        if error_msg:
                            st.error(error_msg)
                        else:
                            st.session_state.reset_stage = "verify"
                            st.session_state.reset_email = reset_email_input
                            st.rerun()
        else:
            st.info(
                f"📨 A reset email was sent to **{st.session_state.reset_email}** (if an account exists for it).\n\n"
                "**Important — do not click the link in the email.** Instead, right-click the "
                "\"Reset Password\" link/button, choose **Copy Link Address**, and paste the whole "
                "link below. (Clicking it consumes the token on a page that can't complete the reset.)"
            )

            with st.form("reset_verify_form"):
                otp_code = st.text_input("Pasted Reset Link (or reset code, if your email contains one)").strip()
                new_pass = st.text_input("New Password (8+ characters)", type="password")
                new_pass_conf = st.text_input("Confirm New Password", type="password")
                btn_reset = st.form_submit_button("Reset Password & Sign In")

                if btn_reset:
                    if not otp_code or not new_pass:
                        st.error("All fields are required.")
                    elif len(new_pass) < 8:
                        st.error("Password must be at least 8 characters long.")
                    elif new_pass != new_pass_conf:
                        st.error("Passwords do not match.")
                    else:
                        auth_res, error_msg = db.verify_recovery_code(
                            supabase, st.session_state.reset_email, otp_code
                        )
                        if error_msg:
                            st.error(f"Code verification failed: {error_msg}")
                        else:
                            error_msg = db.update_password(supabase, new_pass)
                            if error_msg:
                                st.error(f"Password update failed: {error_msg}")
                            else:
                                profile = db.fetch_profile(supabase, auth_res.user.id)
                                if profile is None:
                                    st.error("Password was reset, but no profile was found. Try signing in normally.")
                                else:
                                    encryption_key = derive_encryption_key(new_pass, profile["encryption_salt"])
                                    complete_login(
                                        auth_res.user.id,
                                        st.session_state.reset_email,
                                        profile["display_name"],
                                        encryption_key,
                                        profile["encryption_salt"]
                                    )
                                    st.rerun()

            if st.button("↩️ Start over with a different email"):
                st.session_state.reset_stage = None
                st.session_state.reset_email = None
                st.rerun()

# ==========================================
# SECURE LOGGED-IN PLATFORM WORKSPACE
# ==========================================
else:
    supabase = db.get_supabase()

    # Sidebar controls
    st.sidebar.title("🔒 Sandbox Locked")
    st.sidebar.markdown(f"**Operator:** {st.session_state.display_name}")
    st.sidebar.caption(f"Zero-Knowledge Mode Active (AES-256)")

    if st.sidebar.button("Logout of Workspace"):
        db.sign_out_user(supabase)
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        st.rerun()

    with st.sidebar.expander("🔑 Change Password"):
        st.caption("Your journals will be decrypted and re-encrypted with the new password. No data is lost.")
        with st.form("change_password_form"):
            current_pass = st.text_input("Current Password", type="password")
            change_new_pass = st.text_input("New Password (8+ characters)", type="password")
            change_new_conf = st.text_input("Confirm New Password", type="password")
            btn_change = st.form_submit_button("Re-Encrypt & Update")

            if btn_change:
                old_key = st.session_state.encryption_key
                salt = st.session_state.encryption_salt

                if not current_pass or not change_new_pass:
                    st.error("All fields are required.")
                elif derive_encryption_key(current_pass, salt) != old_key:
                    st.error("Current password is incorrect.")
                elif len(change_new_pass) < 8:
                    st.error("New password must be at least 8 characters long.")
                elif change_new_pass == current_pass:
                    st.error("New password must be different from the current one.")
                elif change_new_pass != change_new_conf:
                    st.error("New passwords do not match.")
                else:
                    # Decrypt every session up-front so a bad key can't strand us mid-rewrite
                    rows = db.fetch_sessions(supabase, st.session_state.user_id)
                    decrypted_rows = []
                    skipped = 0
                    for row in rows:
                        try:
                            decrypted_rows.append((
                                row["id"],
                                decrypt_data(row["profile_details"], old_key),
                                decrypt_data(row["questions"], old_key),
                                decrypt_data(row["journal_entries"], old_key),
                            ))
                        except Exception:
                            # Sessions orphaned by a past forgotten-password reset stay as-is
                            skipped += 1

                    error_msg = db.update_password(supabase, change_new_pass)
                    if error_msg:
                        st.error(f"Password update failed (no data was changed): {error_msg}")
                    else:
                        new_key = derive_encryption_key(change_new_pass, salt)
                        failed_ids = []
                        for session_id, dec_profile, dec_questions, dec_journals in decrypted_rows:
                            enc_payloads = (
                                encrypt_data(dec_profile, new_key),
                                encrypt_data(dec_questions, new_key),
                                encrypt_data(dec_journals, new_key),
                            )
                            # One automatic retry per row before giving up
                            for attempt in range(2):
                                try:
                                    db.update_session_payloads(supabase, session_id, *enc_payloads)
                                    break
                                except Exception:
                                    if attempt == 1:
                                        failed_ids.append(session_id)

                        st.session_state.encryption_key = new_key
                        if failed_ids:
                            st.error(
                                f"Password changed, but {len(failed_ids)} session(s) could not be rewritten "
                                "and remain encrypted under your OLD password. They will show as unreadable "
                                "until rewritten — keep your old password noted somewhere safe."
                            )
                        else:
                            msg = "Password changed and all journals re-encrypted!"
                            if skipped:
                                msg += f" ({skipped} previously unreadable session(s) were left untouched.)"
                            st.success(msg)

    st.title("🧩 ContextAI")
    st.subheader(f"Questions shaped by your story, {st.session_state.display_name}.")

    tab_generate, tab_history = st.tabs(["✨ Generate Reflections", "📚 Saved Journals & History"])

    # ==========================================
    # WORKSPACE TAB 1: FORM GENERATION
    # ==========================================
    with tab_generate:
        generations_used = db.count_generations_today(supabase, st.session_state.user_id)
        generations_left = max(0, DAILY_GENERATION_LIMIT - generations_used)

        if not st.session_state.survey_submitted:
            st.write("Tell us about your current baseline. No generic prompt builders here. Your data is encrypted with your password before it ever leaves this app.")
            st.caption(f"⚡ Daily generations remaining: **{generations_left} of {DAILY_GENERATION_LIMIT}**")

            with st.form("intake_survey"):
                st.header("1. Your Baseline")

                life_stage_options = list(LifeStage)
                try:
                    stored_stage_str = st.session_state.form_defaults["life_stage"]
                    default_life_stage = next((e for e in life_stage_options if e.value == stored_stage_str), life_stage_options[0])
                    default_life_stage_idx = life_stage_options.index(default_life_stage)
                except Exception:
                    default_life_stage_idx = 0

                selected_life_stage_enum = st.selectbox(
                    "What is your current life stage?",
                    options=life_stage_options,
                    index=default_life_stage_idx,
                    format_func=lambda e: e.value
                )

                living_options = list(LivingSituation)
                try:
                    stored_living_str = st.session_state.form_defaults["living_situation"]
                    default_living = next((e for e in living_options if e.value == stored_living_str), living_options[0])
                    default_living_idx = living_options.index(default_living)
                except Exception:
                    default_living_idx = 0

                selected_living_enum = st.selectbox(
                    "What is your primary living situation?",
                    options=living_options,
                    index=default_living_idx,
                    format_func=lambda e: e.value
                )

                prof_focus_val = st.text_input("What is your primary professional/daily focus?", value=st.session_state.form_defaults["professional_focus"], placeholder="e.g., Cybersecurity, Developer, Creative")

                st.header("2. Relationship Architecture")

                rel_options = list(RelationshipStatus)
                try:
                    stored_rel_str = st.session_state.form_defaults["relationship_status"]
                    default_rel = next((e for e in rel_options if e.value == stored_rel_str), rel_options[0])
                    default_rel_idx = rel_options.index(default_rel)
                except Exception:
                    default_rel_idx = 0

                selected_relationship_enum = st.selectbox(
                    "What is your relationship status?",
                    options=rel_options,
                    index=default_rel_idx,
                    format_func=lambda e: e.value
                )

                has_dep_val = st.checkbox("Do you manage custody, children, or dependents?", value=st.session_state.form_defaults["has_dependents"])
                custody_details_val = st.text_input("Optional family or custody dynamics context (e.g. co-parenting split weeks):", value=st.session_state.form_defaults["custody_details"])

                key_pillars_input = st.text_input("Who is in your direct inner circle? (separate with commas):", value=st.session_state.form_defaults["key_pillars"], placeholder="e.g., Spouse, Best Friend, Sister")

                st.header("3. Outlets & Rituals")
                creative_val = st.text_input("Creative or technical outlets:", value=st.session_state.form_defaults["creative"], placeholder="e.g., Python engineering, playing piano")
                recreation_val = st.text_input("How do you unwind?", value=st.session_state.form_defaults["recreation"], placeholder="e.g., Gaming/MMOs, hiking, vinyl records")
                rituals_val = st.text_input("Daily micro-rituals or habits:", value=st.session_state.form_defaults["rituals"], placeholder="e.g., Dedicated V60 coffee brewing, working out")

                st.header("4. Core Focus")

                theme_options = list(LifeTheme)
                stored_themes = st.session_state.form_defaults["themes"]
                default_themes = [t for t in theme_options if t.value in stored_themes or t in stored_themes]

                themes_val = st.multiselect(
                    "Select up to 2 primary life themes to center your questions around:",
                    options=theme_options,
                    default=default_themes,
                    max_selections=2,
                    format_func=lambda e: e.value
                )

                additional_notes_val = st.text_area("Any specific situational friction or context to consider?", value=st.session_state.form_defaults["additional_notes"], placeholder="Optional context...")

                submitted = st.form_submit_button("Generate Reflective Workbook")

                if submitted:
                    if not themes_val:
                        st.error("Please choose at least one core life theme to direct the API.")
                    elif generations_left <= 0:
                        st.error(f"You've used all {DAILY_GENERATION_LIMIT} of your daily generations. Your limit resets at midnight UTC.")
                    else:
                        parse_list = lambda s: [item.strip() for item in s.split(",") if item.strip()] if s else []

                        # Extract clean string primitives
                        val_life_stage = selected_life_stage_enum.value if hasattr(selected_life_stage_enum, 'value') else selected_life_stage_enum
                        val_living_situation = selected_living_enum.value if hasattr(selected_living_enum, 'value') else selected_living_enum
                        val_relationship_status = selected_relationship_enum.value if hasattr(selected_relationship_enum, 'value') else selected_relationship_enum
                        val_themes = [t.value if hasattr(t, 'value') else str(t) for t in themes_val]

                        # Pack clean primitive dictionaries to match the exact schema shape
                        raw_profile_dict = {
                            "name": st.session_state.display_name,
                            "baseline": {
                                "name": st.session_state.display_name,  # Fulfills required 'name' field inside BaselineProfile definition
                                "life_stage": val_life_stage,
                                "living_situation": val_living_situation,
                                "professional_focus": prof_focus_val
                            },
                            "relationships": {
                                "status": val_relationship_status,
                                "has_dependents": has_dep_val,
                                "custody_details": custody_details_val if custody_details_val else None,
                                "key_pillars": parse_list(key_pillars_input)
                            },
                            "outlets": {
                                "creative_technical": parse_list(creative_val),
                                "recreation_unwinding": parse_list(recreation_val),
                                "daily_rituals": parse_list(rituals_val)
                            },
                            "primary_themes": val_themes,
                            "additional_notes": additional_notes_val if additional_notes_val else None
                        }

                        # Save values to cache for history tracking
                        theme_labels = ", ".join([t.split(" (")[0] for t in val_themes])
                        st.session_state.active_summary_label = f"{val_life_stage} | {theme_labels}"
                        st.session_state.active_raw_profile = raw_profile_dict

                        # Instantiate schemas with unpacked configurations
                        baseline_profile = BaselineProfile(**raw_profile_dict["baseline"])
                        relationships_profile = RelationshipProfile(**raw_profile_dict["relationships"])
                        outlets_profile = OutletsProfile(**raw_profile_dict["outlets"])

                        profile = UserContextProfile(
                            name=st.session_state.display_name,
                            baseline=baseline_profile,
                            relationships=relationships_profile,
                            outlets=outlets_profile,
                            primary_themes=themes_val,
                            additional_notes=additional_notes_val if additional_notes_val else None
                        )

                        st.session_state.form_defaults = {
                            "life_stage": val_life_stage,
                            "living_situation": val_living_situation,
                            "professional_focus": prof_focus_val,
                            "relationship_status": val_relationship_status,
                            "has_dependents": has_dep_val,
                            "custody_details": custody_details_val,
                            "key_pillars": key_pillars_input,
                            "creative": creative_val,
                            "recreation": recreation_val,
                            "rituals": rituals_val,
                            "themes": val_themes,
                            "additional_notes": additional_notes_val
                        }

                        st.session_state.user_profile = profile
                        st.session_state.survey_submitted = True
                        st.session_state.current_response = None
                        st.rerun()

        else:
            profile = st.session_state.user_profile

            with st.expander("🔍 View Active Prompt Structures"):
                st.markdown("**Prompt Generation Engine Instructions:**")
                st.code(PromptEngine.generate_system_instruction())
                st.markdown("**User Context Model Payload:**")
                st.code(PromptEngine.generate_user_prompt(profile))

            st.markdown("---")
            st.header("🎯 Your Curated Reflections")

            if st.session_state.current_response is None:
                if generations_left <= 0:
                    st.error(f"You've used all {DAILY_GENERATION_LIMIT} of your daily generations. Your limit resets at midnight UTC.")
                else:
                    with st.spinner("Refining context profile and streaming tailored cloud reflections..."):
                        try:
                            ai_response = PromptEngine.execute_google_inference(profile, model_name="gemini-2.5-flash")
                            st.session_state.current_response = ai_response

                            db.log_generation(supabase, st.session_state.user_id)
                            save_session_to_history(
                                supabase,
                                st.session_state.user_id,
                                st.session_state.active_summary_label,
                                st.session_state.active_raw_profile,
                                ai_response.curated_questions,
                                st.session_state.encryption_key
                            )

                        except Exception as e:
                            st.error("Failed to generate reflections. Please check terminal console.")
                            st.info("Check that you have a valid `GEMINI_API_KEY` exported in your system profile or command environment.")
                            st.exception(e)

            if st.session_state.current_response is not None:
                for idx, q in enumerate(st.session_state.current_response.curated_questions):
                    st.markdown(f"### Question {idx + 1}: *{q.category}*")
                    st.info(q.question_text)
                    st.caption(f"💡 **ContextAI Note:** {q.insight_trigger}")
                    st.markdown("---")

                st.success("🔒 This session has been encrypted with your key and saved to your private cloud workspace!")

            if st.button("🔄 Edit Survey / Adjust Themes"):
                st.session_state.survey_submitted = False
                st.session_state.user_profile = None
                st.session_state.current_response = None
                st.rerun()

    # ==========================================
    # WORKSPACE TAB 2: PERSONAL SECURE JOURNAL
    # ==========================================
    with tab_history:
        st.header("📚 Your Cryptographic Reflection Logs")

        decrypted_history = load_and_decrypt_history(
            supabase,
            st.session_state.user_id,
            st.session_state.encryption_key
        )

        if not decrypted_history:
            st.info("No logs on record. Return to the generation tab to initiate your first context survey!")
        else:
            st.write("Browse your history below. Write your answers and thoughts—your updates will save securely to your encrypted cloud workspace.")

            for session in decrypted_history:
                session_title = f"📅 {session['timestamp']} — {session['summary']}"
                if session.get("decryption_failed", False):
                    st.error(f"⚠️ {session['timestamp']} - Decryption Error (Invalid Key or Data Modified)")
                    continue

                with st.expander(session_title):
                    col1, col2 = st.columns([1, 1])

                    with col1:
                        if st.button("📋 Load Context to Active Survey", key=f"load_{session['id']}"):
                            prev_prof = session["profile_details"]
                            join_list = lambda x: ", ".join(x) if isinstance(x, list) else ""

                            st.session_state.form_defaults = {
                                "life_stage": prev_prof["baseline"]["life_stage"],
                                "living_situation": prev_prof["baseline"]["living_situation"],
                                "professional_focus": prev_prof["baseline"]["professional_focus"],
                                "relationship_status": prev_prof["relationships"]["status"],
                                "has_dependents": prev_prof["relationships"]["has_dependents"],
                                "custody_details": prev_prof["relationships"].get("custody_details") or "",
                                "key_pillars": join_list(prev_prof["relationships"].get("key_pillars")),
                                "creative": join_list(prev_prof["outlets"].get("creative_technical")),
                                "recreation": join_list(prev_prof["outlets"].get("recreation_unwinding")),
                                "rituals": join_list(prev_prof["outlets"].get("daily_rituals")),
                                "themes": prev_prof.get("primary_themes", []),
                                "additional_notes": prev_prof.get("additional_notes") or ""
                            }
                            st.session_state.survey_submitted = False
                            st.session_state.user_profile = None
                            st.session_state.current_response = None
                            st.rerun()

                    with col2:
                        md_content = format_export_markdown(session, st.session_state.display_name)

                        mail_subject = f"ContextAI Reflection Workbook - {session['timestamp']}"
                        mail_body = f"Find my completed ContextAI personal reflections below:\n\n{md_content}"

                        encoded_subject = urllib.parse.quote(mail_subject)
                        encoded_body = urllib.parse.quote(mail_body)
                        mailto_link = f"mailto:?subject={encoded_subject}&body={encoded_body}"

                        st.markdown(
                            f'<a href="{mailto_link}" style="text-decoration:none;">'
                            '<button style="width:100%; border:1px solid #d3d3d3; padding:6px; border-radius:4px; background-color:#fcfcfc; cursor:pointer;">'
                            '📧 Share Reflection Workbook via Email</button></a>',
                            unsafe_allow_html=True
                        )

                    st.write("")
                    st.caption("📋 **One-Click Clipboard Export:** Click the copy button in the top-right of the box below to export your entire workbook:")
                    st.code(md_content, language="markdown")

                    st.markdown("---")
                    st.subheader("📝 Secure Reflection Notebook")

                    for idx, q in enumerate(session['questions']):
                        st.markdown(f"##### Q{idx + 1}: {q['category']}")
                        st.info(q['question_text'])
                        st.caption(f"💡 *{q['insight_trigger']}*")

                        existing_answer = session.get("journal_entries", {}).get(str(idx), "")
                        text_area_key = f"journal_edit_{session['id']}_{idx}"

                        user_ref = st.text_area(
                            "My Written Reflection:",
                            value=existing_answer,
                            key=text_area_key,
                            placeholder="Write your personal answer or notes here..."
                        )

                        if st.button("Save Secure Reflection", key=f"btn_save_{session['id']}_{idx}"):
                            save_journal_answer(
                                supabase,
                                session,
                                idx,
                                user_ref,
                                st.session_state.encryption_key
                            )
                            st.success("Journal answer encrypted and saved!")

                        st.markdown("---")
