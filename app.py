import streamlit as st
import json
import os
import hashlib
import base64
from datetime import datetime

# Secure Cryptographic Imports
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

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

# Database and configuration paths
USERS_FILE = "users.json"
HISTORY_FILE = "context_history.json"

# ==========================================
# ZERO-KNOWLEDGE CRYPTOGRAPHY HELPERS
# ==========================================
def hash_password(password: str, salt_hex: str) -> str:
    """Hashes a password with a salt using standard PBKDF2-HMAC-SHA256."""
    salt = bytes.fromhex(salt_hex)
    pw_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000  # High iteration count for password safety
    )
    return pw_hash.hex()

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
# USER ACCOUNTS & DATABASE FILE MANAGEMENT
# ==========================================
def load_users():
    """Loads current credential registry from local disk storage."""
    if not os.path.exists(USERS_FILE):
        return {}
    try:
        with open(USERS_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}

def save_users(users_dict):
    """Saves updated credentials list to disk."""
    with open(USERS_FILE, "w") as f:
        json.dump(users_dict, f, indent=4)

def register_user(username, display_name, password):
    """Registers a new user, deriving cryptographic hashes and salts securely."""
    users = load_users()
    clean_username = username.strip().lower()
    
    if clean_username in users:
        return False, "Username is already taken."
        
    salt = os.urandom(16)
    salt_hex = salt.hex()
    
    hashed_pw = hash_password(password, salt_hex)
    user_id = hashlib.sha256(clean_username.encode()).hexdigest()[:12]
    
    users[clean_username] = {
        "user_id": user_id,
        "display_name": display_name.strip(),
        "password_hash": hashed_pw,
        "salt": salt_hex
    }
    
    save_users(users)
    return True, users[clean_username]

def authenticate_user(username, password):
    """Authenticates credentials and returns user details with derived encryption key."""
    users = load_users()
    clean_username = username.strip().lower()
    
    if clean_username not in users:
        return None, "Invalid username or password."
        
    user_record = users[clean_username]
    salt_hex = user_record["salt"]
    target_hash = hash_password(password, salt_hex)
    
    if target_hash == user_record["password_hash"]:
        encryption_key = derive_encryption_key(password, salt_hex)
        return {
            "user_id": user_record["user_id"],
            "display_name": user_record["display_name"],
            "username": clean_username,
            "encryption_key": encryption_key
        }, None
        
    return None, "Invalid username or password."

# ==========================================
# ENCRYPTED HISTORY MANAGEMENT
# ==========================================
def load_history():
    """Reads raw session logs from disk."""
    if not os.path.exists(HISTORY_FILE):
        return []
    try:
        with open(HISTORY_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return []

def load_and_decrypt_history(active_user_id, key_str):
    """Loads, filters, and decrypts historical journal entries for the current user."""
    raw_history = load_history()
    user_history = []
    
    for entry in raw_history:
        if entry.get("user_id") == active_user_id:
            if entry.get("is_encrypted", False):
                try:
                    entry["profile_details"] = decrypt_data(entry["profile_details"], key_str)
                    entry["questions"] = decrypt_data(entry["questions"], key_str)
                    entry["journal_entries"] = decrypt_data(entry["journal_entries"], key_str)
                    entry["is_encrypted_runtime"] = False
                    user_history.append(entry)
                except Exception as e:
                    entry["profile_details"] = {}
                    entry["questions"] = []
                    entry["journal_entries"] = {}
                    entry["decryption_failed"] = True
                    user_history.append(entry)
            else:
                entry["is_encrypted_runtime"] = False
                user_history.append(entry)
                
    return user_history

def save_session_to_history(user_id, profile: UserContextProfile, curated_questions, key_str):
    """Formats, encrypts, and appends a newly generated reflection session to the JSON file."""
    history = load_history()
    
    # Safely pull the theme value text string
    theme_labels = ", ".join([t.value.split(" (")[0] if hasattr(t, 'value') else str(t).split(" (")[0] for t in profile.primary_themes])
    baseline_stage = profile.baseline.life_stage.value if hasattr(profile.baseline.life_stage, 'value') else str(profile.baseline.life_stage)
    summary_label = f"{baseline_stage} | {theme_labels}"
    
    serialized_questions = []
    for q in curated_questions:
        serialized_questions.append({
            "category": q.category,
            "question_text": q.question_text,
            "insight_trigger": q.insight_trigger
        })

    profile_dict = profile.model_dump()
    journal_entries_dict = {}

    enc_profile = encrypt_data(profile_dict, key_str)
    enc_questions = encrypt_data(serialized_questions, key_str)
    enc_journals = encrypt_data(journal_entries_dict, key_str)

    session_data = {
        "id": datetime.now().strftime("%Y%m%d_%H%M%S"),
        "user_id": user_id,
        "timestamp": datetime.now().strftime("%Y-%m-%d %I:%M %p"),
        "summary": summary_label,
        "is_encrypted": True,
        "profile_details": enc_profile,
        "questions": enc_questions,
        "journal_entries": enc_journals
    }
    
    history.insert(0, session_data)
    
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=4)
    return session_data

def update_journal_entry(session_id, question_idx, answer_text, key_str):
    """Updates a reflection answer and encrypts/upgrades the payload on-the-fly."""
    history = load_history()
    for session in history:
        if session["id"] == session_id:
            if session.get("is_encrypted", False):
                try:
                    current_journals = decrypt_data(session["journal_entries"], key_str)
                except Exception:
                    current_journals = {}
            else:
                current_journals = session.get("journal_entries", {})

            current_journals[str(question_idx)] = answer_text

            if session.get("is_encrypted", False):
                session["journal_entries"] = encrypt_data(current_journals, key_str)
            else:
                session["profile_details"] = encrypt_data(session["profile_details"], key_str)
                session["questions"] = encrypt_data(session["questions"], key_str)
                session["journal_entries"] = encrypt_data(current_journals, key_str)
                session["is_encrypted"] = True
            break
            
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=4)

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

# Initialize persistent users log directly on app boot
existing_users = load_users()

# Track authentication status
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "user_id" not in st.session_state:
    st.session_state.user_id = None
if "username" not in st.session_state:
    st.session_state.username = None
if "display_name" not in st.session_state:
    st.session_state.display_name = None
if "encryption_key" not in st.session_state:
    st.session_state.encryption_key = None

# Track generation workflow states
if "survey_submitted" not in st.session_state:
    st.session_state.survey_submitted = False
if "user_profile" not in st.session_state:
    st.session_state.user_profile = None
if "current_response" not in st.session_state:
    st.session_state.current_response = None

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

# ==========================================
# GUEST / SECURE PORTAL INTERFACE
# ==========================================
if not st.session_state.logged_in:
    st.title("🧩 ContextAI Secure Portal")
    st.write("Welcome to your local private prompt refinery. Sign in to load and encrypt your customized journals.")
    
    auth_mode = st.radio("Choose Action", ["Sign In", "Register Private Profile"], horizontal=True)
    
    if auth_mode == "Sign In":
        with st.form("login_form"):
            user_input = st.text_input("Username").strip()
            pass_input = st.text_input("Password", type="password")
            btn_submit = st.form_submit_button("Access Secure Sandbox")
            
            if btn_submit:
                if not user_input or not pass_input:
                    st.error("Fields cannot be empty.")
                else:
                    user_data, error_msg = authenticate_user(user_input, pass_input)
                    if error_msg:
                        st.error(error_msg)
                    else:
                        st.session_state.logged_in = True
                        st.session_state.user_id = user_data["user_id"]
                        st.session_state.username = user_data["username"]
                        st.session_state.display_name = user_data["display_name"]
                        st.session_state.encryption_key = user_data["encryption_key"]
                        st.success(f"Hello, {user_data['display_name']}!")
                        st.rerun()
                        
    else:
        with st.form("register_form"):
            st.info("Your password is cryptographically combined with a randomized salt to encrypt your files. Please remember it.")
            reg_username = st.text_input("Preferred Username (Lowercase, letters/numbers only)").strip()
            reg_display = st.text_input("Preferred Nickname (addressed by AI)").strip()
            reg_pass = st.text_input("Secure Password", type="password")
            reg_pass_conf = st.text_input("Confirm Password", type="password")
            
            btn_register = st.form_submit_button("Instantiate My Account")
            
            if btn_register:
                if not reg_username or not reg_display or not reg_pass:
                    st.error("All credentials are required.")
                elif reg_pass != reg_pass_conf:
                    st.error("Passwords do not match.")
                else:
                    success, result = register_user(reg_username, reg_display, reg_pass)
                    if not success:
                        st.error(result)
                    else:
                        derived_key = derive_encryption_key(reg_pass, result["salt"])
                        st.session_state.logged_in = True
                        st.session_state.user_id = result["user_id"]
                        st.session_state.username = reg_username.lower()
                        st.session_state.display_name = result["display_name"]
                        st.session_state.encryption_key = derived_key
                        st.success("Account created securely! Launching platform...")
                        st.rerun()

# ==========================================
# SECURE LOGGED-IN PLATFORM WORKSPACE
# ==========================================
else:
    # Sidebar controls
    st.sidebar.title("🔒 Sandbox Locked")
    st.sidebar.markdown(f"**Operator:** {st.session_state.display_name}")
    st.sidebar.caption(f"Zero-Knowledge Mode Active (AES-256)")
    
    if st.sidebar.button("Logout of Workspace"):
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        st.rerun()
        
    st.title("🧩 ContextAI")
    st.subheader(f"Questions shaped by your story, {st.session_state.display_name}.")
    
    tab_generate, tab_history = st.tabs(["✨ Generate Reflections", "📚 Saved Journals & History"])

    # ==========================================
    # WORKSPACE TAB 1: FORM GENERATION
    # ==========================================
    with tab_generate:
        if not st.session_state.survey_submitted:
            st.write("Tell us about your current baseline. No generic prompt builders here. This data remains fully encrypted on your local machine.")
            
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
                    else:
                        parse_list = lambda s: [item.strip() for item in s.split(",") if item.strip()] if s else []
                        
                        # Extract clean string primitives
                        val_life_stage = selected_life_stage_enum.value if hasattr(selected_life_stage_enum, 'value') else selected_life_stage_enum
                        val_living_situation = selected_living_enum.value if hasattr(selected_living_enum, 'value') else selected_living_enum
                        val_relationship_status = selected_relationship_enum.value if hasattr(selected_relationship_enum, 'value') else selected_relationship_enum
                        val_themes = [t.value if hasattr(t, 'value') else t for t in themes_val]

                        # Pack structural mappings
                        baseline_dict = {
                            "life_stage": val_life_stage,
                            "living_situation": val_living_situation,
                            "professional_focus": prof_focus_val
                        }
                        
                        relationships_dict = {
                            "status": val_relationship_status,
                            "has_dependents": has_dep_val,
                            "custody_details": custody_details_val if custody_details_val else None,
                            "key_pillars": parse_list(key_pillars_input)
                        }
                        
                        outlets_dict = {
                            "creative_technical": parse_list(creative_val),
                            "recreation_unwinding": parse_list(recreation_val),
                            "daily_rituals": parse_list(rituals_val)
                        }

                        # CRITICAL FIX: Use .model_construct() to skip strict type coercion for localized schemas
                        baseline_profile = BaselineProfile.model_construct(**baseline_dict)
                        relationships_profile = RelationshipProfile.model_construct(**relationships_dict)
                        outlets_profile = OutletsProfile.model_construct(**outlets_dict)

                        # Form the master context schema smoothly without validation errors
                        profile = UserContextProfile.model_construct(
                            name=st.session_state.display_name,
                            baseline=baseline_profile,
                            relationships=relationships_profile,
                            outlets=outlets_profile,
                            primary_themes=themes_val,  # Pass active enums to engine
                            additional_notes=additional_notes_val if additional_notes_val else None
                        )
                        
                        # Store properties as primitives for continuous state reload retention
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
                with st.spinner("Refining context profile and streaming tailored cloud reflections..."):
                    try:
                        ai_response = PromptEngine.execute_google_inference(profile, model_name="gemini-2.5-flash")
                        st.session_state.current_response = ai_response
                        
                        save_session_to_history(
                            st.session_state.user_id, 
                            profile, 
                            ai_response.curated_questions,
                            st.session_state.encryption_key
                        )
                        
                    except Exception as e:
                        st.error("Failed to authenticate or contact Gemini cloud services. Please check terminal console.")
                        st.info("Check that you have a valid `GEMINI_API_KEY` exported in your system profile or command environment.")
                        st.exception(e)
            
            if st.session_state.current_response is not None:
                for idx, q in enumerate(st.session_state.current_response.curated_questions):
                    st.markdown(f"### Question {idx + 1}: *{q.category}*")
                    st.info(q.question_text)
                    st.caption(f"💡 **ContextAI Note:** {q.insight_trigger}")
                    st.markdown("---")
                    
                st.success("🔒 This session data has been fully encrypted and written locally to disk!")

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
            st.session_state.user_id, 
            st.session_state.encryption_key
        )
        
        if not decrypted_history:
            st.info("No logs on record. Return to the generation tab to initiate your first context survey!")
        else:
            st.write("Browse your history below. Write your answers and thoughts—your updates will save securely to your encrypted files on disk.")
            
            for session in decrypted_history:
                session_title = f"📅 {session['timestamp']} — {session['summary']}"
                if session.get("decryption_failed", False):
                    st.error(f"⚠️ {session['timestamp']} - Decryption Error (Invalid Key or File Modified)")
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
                            st.success("Prior profile metrics loaded into editor! Swap tabs to tweak themes.")
                            st.rerun()
                            
                    with col2:
                        md_content = format_export_markdown(session, st.session_state.display_name)
                        
                        mail_subject = f"ContextAI Reflection Workbook - {session['timestamp']}"
                        mail_body = f"Find my completed ContextAI personal reflections below:\n\n{md_content}"
                        
                        import urllib.parse
                        encoded_subject = urllib.parse.quote(mail_subject)
                        encoded_body = urllib.parse.quote(mail_body)
                        mailto_link = f"mailto:?subject={encoded_subject}&body={encoded_body}"
                        
                        st.markdown(
                            f'<a href="{mailto_link}" style="text-decoration:none;">'
                            '<button style="width:100%; border:1px solid #d3d3d3; padding:6px; border-radius:4px; background-color:#fcfcfc; cursor:pointer;">'
                            '📧 Share Reflection Workbook via Email</button></a>',
                            unsafe_allow_code=True
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
                            update_journal_entry(
                                session["id"], 
                                idx, 
                                user_ref, 
                                st.session_state.encryption_key
                            )
                            st.success("Journal answer encrypted and saved to disk!")
                            
                        st.markdown("---")