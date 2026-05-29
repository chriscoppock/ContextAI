import streamlit as st
import json
import os
import urllib.parse
import uuid
import hashlib
from datetime import datetime
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
# CONFIGURATION & FILE PATHS
# ==========================================
HISTORY_FILE = "context_history.json"
USER_DB_FILE = "users.json"

# ==========================================
# SECURITY & AUTHENTICATION UTILITIES
# ==========================================
def hash_password(password: str, salt: bytes = None) -> tuple[str, str]:
    """
    Hashes a password securely using PBKDF2-HMAC-SHA256 with a randomized salt.
    Returns (hex_hash, hex_salt).
    """
    if salt is None:
        salt = os.urandom(16)
    # Perform 100,000 iterations of SHA-256 (industry secure standard)
    hashed_key = hashlib.pbkdf2_hmac(
        'sha256', 
        password.encode('utf-8'), 
        salt, 
        100000
    )
    return hashed_key.hex(), salt.hex()

def verify_password(password: str, stored_hash: str, stored_salt_hex: str) -> bool:
    """Verifies a password against the stored secure PBKDF2 hash."""
    salt = bytes.fromhex(stored_salt_hex)
    new_hash, _ = hash_password(password, salt)
    return new_hash == stored_hash

def load_users() -> dict:
    """Loads authenticated users from the secure credentials database."""
    if not os.path.exists(USER_DB_FILE):
        return {}
    try:
        with open(USER_DB_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}

def save_users(users: dict):
    """Saves updated user credentials to the database."""
    with open(USER_DB_FILE, "w") as f:
        json.dump(users, f, indent=4)

def register_user(username: str, password: str) -> tuple[bool, str]:
    """
    Registers a new user. Checks for existing matching user records 
    in history to preserve legacy journals.
    """
    users = load_users()
    clean_username = username.strip().lower()
    display_name = username.strip()
    
    if not clean_username or not password:
        return False, "Username and password cannot be blank."
        
    if clean_username in users:
        return False, "This username is already taken."
        
    # Generate cryptographic hash
    hashed_pass, salt = hash_password(password)
    
    # Backward compatibility logic: Match legacy history by name if it exists
    matched_uid = None
    all_history = load_history()
    for session in all_history:
        baseline_name = session.get("profile_details", {}).get("baseline", {}).get("name", "")
        if baseline_name.strip().lower() == clean_username:
            matched_uid = session.get("user_id")
            break
            
    # Fallback to generating a brand-new clean 8-character ID
    user_id = matched_uid if matched_uid else str(uuid.uuid4())[:8]
    
    users[clean_username] = {
        "display_name": display_name,
        "password_hash": hashed_pass,
        "salt": salt,
        "user_id": user_id
    }
    
    save_users(users)
    return True, user_id

def authenticate_user(username: str, password: str) -> tuple[bool, str, str]:
    """
    Verifies user credentials.
    Returns (success_status, user_id, display_name).
    """
    users = load_users()
    clean_username = username.strip().lower()
    
    if clean_username not in users:
        return False, "", ""
        
    user_data = users[clean_username]
    is_valid = verify_password(
        password, 
        user_data["password_hash"], 
        user_data["salt"]
    )
    
    if is_valid:
        return True, user_data["user_id"], user_data["display_name"]
    return False, "", ""

# ==========================================
# LOCAL DATABASE HELPER FUNCTIONS
# ==========================================
def load_history():
    """Loads past session logs from the local JSON file securely."""
    if not os.path.exists(HISTORY_FILE):
        return []
    try:
        with open(HISTORY_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return []

def save_session_to_history(profile: UserContextProfile, user_id: str, curated_questions):
    """Saves a newly generated reflection session to the history database linked to a specific user_id."""
    history = load_history()
    
    # Create a nice visual summary label for this session
    theme_labels = ", ".join([t.value.split(" (")[0] for t in profile.primary_themes])
    summary_label = f"{profile.baseline.life_stage.value} | {theme_labels}"
    
    # Format the questions for storage
    serialized_questions = []
    for q in curated_questions:
        serialized_questions.append({
            "category": q.category,
            "question_text": q.question_text,
            "insight_trigger": q.insight_trigger
        })

    session_data = {
        "id": datetime.now().strftime("%Y%m%d_%H%M%S"),
        "user_id": user_id,
        "timestamp": datetime.now().strftime("%Y-%m-%d %I:%M %p"),
        "summary": summary_label,
        "profile_details": profile.model_dump(),
        "questions": serialized_questions,
        "journal_entries": {}  # Stores users answers to each question
    }
    
    # Prepend to history list so the newest is always on top
    history.insert(0, session_data)
    
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=4)
    return session_data

def update_journal_entry(session_id, question_idx, answer_text):
    """Saves or updates a personal reflection answer for a specific question."""
    history = load_history()
    for session in history:
        if session["id"] == session_id:
            if "journal_entries" not in session:
                session["journal_entries"] = {}
            session["journal_entries"][str(question_idx)] = answer_text
            break
            
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=4)

def populate_form_defaults(profile_source):
    """
    Standardizes user profile inputs (either a model object or dictionary from history)
    and populates the Session State so that the input widgets render them as defaults.
    """
    if hasattr(profile_source, "model_dump"):
        data = profile_source.model_dump()
    else:
        data = profile_source

    # Robust safety helper to pull enum values or safe fallbacks
    def get_val(item):
        if item is None:
            return ""
        if hasattr(item, "value"):
            return item.value
        return str(item)

    st.session_state.form_defaults = {
        "name": data.get("baseline", {}).get("name", ""),
        "life_stage": get_val(data.get("baseline", {}).get("life_stage")),
        "living_situation": get_val(data.get("baseline", {}).get("living_situation")),
        "professional_focus": data.get("baseline", {}).get("professional_focus", ""),
        "status": get_val(data.get("relationships", {}).get("status")),
        "has_dependents": data.get("relationships", {}).get("has_dependents", False),
        "custody_details": data.get("relationships", {}).get("custody_details", "") or "",
        "key_pillars": ", ".join(data.get("relationships", {}).get("key_pillars", []) or []),
        "creative_technical": ", ".join(data.get("outlets", {}).get("creative_technical", []) or []),
        "recreation_unwinding": ", ".join(data.get("outlets", {}).get("recreation_unwinding", []) or []),
        "daily_rituals": ", ".join(data.get("outlets", {}).get("daily_rituals", []) or []),
        "primary_themes": [get_val(t) for t in data.get("primary_themes", []) or []],
        "additional_notes": data.get("additional_notes", "") or ""
    }

# ==========================================
# SHARING & EXPORT LOGIC
# ==========================================
def generate_shareable_text(session_summary, questions, journal_entries=None):
    """Formats questions and journal answers into a clean, markdown document."""
    if journal_entries is None:
        journal_entries = {}
        
    text = f"# 🧩 ContextAI: My Reflection Journal\n"
    text += f"**Context/Theme:** {session_summary}\n"
    text += f"Generated on: {datetime.now().strftime('%Y-%m-%d %I:%M %p')}\n\n"
    text += "----------------------------------------\n\n"
    
    for idx, q in enumerate(questions):
        category = q.get("category") if isinstance(q, dict) else getattr(q, "category", "")
        question_text = q.get("question_text") if isinstance(q, dict) else getattr(q, "question_text", "")
        insight_trigger = q.get("insight_trigger") if isinstance(q, dict) else getattr(q, "insight_trigger", "")
        
        text += f"### Q{idx + 1}: [{category}]\n"
        text += f"**Question:** *{question_text}*\n"
        text += f"*Context Trigger:* {insight_trigger}\n\n"
        
        answer = journal_entries.get(str(idx), "")
        if answer:
            text += f"**My Reflection:**\n{answer}\n"
        else:
            text += "*[Unanswered]*\n"
        text += "\n" + "-"*40 + "\n\n"
        
    text += "Processed privately with ContextAI."
    return text

def render_sharing_ui(session_summary, questions, journal_entries=None, unique_id=""):
    """Renders sleek, unified UI sharing controls within an expander container."""
    share_text = generate_shareable_text(session_summary, questions, journal_entries)
    
    with st.expander("📤 Share & Export reflections"):
        st.write("Share these hyper-tailored prompts or archive your saved answers using the tools below:")
        
        # 1. Create native email mailto handler
        subject = urllib.parse.quote(f"My ContextAI Reflections - {session_summary}")
        body = urllib.parse.quote(share_text)
        mailto_url = f"mailto:?subject={subject}&body={body}"
        
        st.markdown(
            f'''
            <a href="{mailto_url}" target="_blank" style="text-decoration: none;">
                <div style="
                    display: inline-block;
                    background-color: #FF4B4B;
                    color: white;
                    padding: 0.6rem 1.2rem;
                    border-radius: 8px;
                    font-weight: 600;
                    margin-bottom: 1.2rem;
                    text-align: center;
                    cursor: pointer;
                    transition: background-color 0.2s;
                ">
                    📧 Email My Journal Entries
                </div>
            </a>
            ''',
            unsafe_allow_html=True
        )
        
        # 2. Native copy-paste tool container using Streamlit's code block copy button
        st.write("📋 **Copy Raw Text**")
        st.caption("Click the copy icon on the top-right of the box below to save it to your device clipboard:")
        st.code(share_text, language="markdown")

# ==========================================
# STREAMLIT WINDOW & PAGE SETUP
# ==========================================
st.set_page_config(page_title="ContextAI", page_icon="🧩", layout="centered")

# Initialize global identity session state tracking values
if "active_user_id" not in st.session_state:
    st.session_state.active_user_id = None
if "active_user_name" not in st.session_state:
    st.session_state.active_user_name = None

# ==========================================
# PHASE 1: LOGIN PORTAL (CRITICAL ENFORCED AUTH)
# ==========================================
if st.session_state.active_user_id is None:
    st.title("🧩 ContextAI Portal")
    st.subheader("Sign in to your private reflection vault.")
    
    auth_mode = st.radio("Choose an option:", ["Sign In", "Register New Account"], horizontal=True)
    
    with st.form("auth_form"):
        username_input = st.text_input("Username / Nickname:")
        password_input = st.text_input("Password:", type="password")
        
        submit_btn = st.form_submit_button("Submit")
        
        if submit_btn:
            if auth_mode == "Sign In":
                success, user_id, display_name = authenticate_user(username_input, password_input)
                if success:
                    st.session_state.active_user_id = user_id
                    st.session_state.active_user_name = display_name
                    
                    # Pre-fill form values with user's most recent session if available
                    user_sessions = [s for s in load_history() if s.get("user_id") == user_id]
                    if user_sessions:
                        populate_form_defaults(user_sessions[0]["profile_details"])
                    
                    st.success("Successfully logged in!")
                    st.rerun()
                else:
                    st.error("Invalid username or password. Please try again.")
            else:
                # Registration Path
                if len(password_input) < 6:
                    st.error("For security, passwords must be at least 6 characters.")
                else:
                    success, result_msg = register_user(username_input, password_input)
                    if success:
                        st.success("Account successfully created! Please toggle to 'Sign In' to log in.")
                    else:
                        st.error(result_msg)

# ==========================================
# PHASE 2: PRIMARY OPERATION DASHBOARD
# ==========================================
else:
    # Sidebar control module
    st.sidebar.markdown(f"### 👤 Logged in as:")
    st.sidebar.success(f"**{st.session_state.active_user_name}**")
    if st.sidebar.button("🚪 Log Out of Profile"):
        st.session_state.active_user_id = None
        st.session_state.active_user_name = None
        st.session_state.survey_submitted = False
        st.session_state.user_profile = None
        st.session_state.current_response = None
        st.rerun()

    st.title("🧩 ContextAI")
    st.subheader(f"Welcome back, {st.session_state.active_user_name}.")

    # Navigation Tabs
    tab_generate, tab_history = st.tabs(["✨ Generate Reflections", "📚 Saved Journals & History"])

    # Initialize state management variables
    if "survey_submitted" not in st.session_state:
        st.session_state.survey_submitted = False
    if "user_profile" not in st.session_state:
        st.session_state.user_profile = None
    if "current_response" not in st.session_state:
        st.session_state.current_response = None

    # Ensure form_defaults includes the logged-in user's name
    if "form_defaults" not in st.session_state:
        st.session_state.form_defaults = {
            "name": st.session_state.active_user_name,
            "life_stage": LifeStage.EARLY_20S.value,
            "living_situation": LivingSituation.RENT_TOWNHOUSE.value,
            "professional_focus": "",
            "status": RelationshipStatus.SINGLE.value,
            "has_dependents": False,
            "custody_details": "",
            "key_pillars": "",
            "creative_technical": "",
            "recreation_unwinding": "",
            "daily_rituals": "",
            "primary_themes": [],
            "additional_notes": ""
        }

    # ==========================================
    # TAB 1: GENERATE REFLECTIONS
    # ==========================================
    with tab_generate:
        if not st.session_state.survey_submitted:
            st.write("To curate deep, meaningful reflections, tell us a bit about your reality. No generic icebreakers here.")
            
            with st.form("intake_survey"):
                st.header("1. The Baseline")
                
                # Auto-lock user name in form
                name_val = st.text_input("Name or Nickname:", value=st.session_state.form_defaults.get("name", st.session_state.active_user_name))
                
                # Map enum default indices safely to prevent compilation boundary errors
                life_stages = [e.value for e in LifeStage]
                try:
                    ls_idx = life_stages.index(st.session_state.form_defaults["life_stage"])
                except ValueError:
                    ls_idx = 0
                life_stage_val = st.selectbox("What is your current life stage?", life_stages, index=ls_idx)
                
                living_situations = [e.value for e in LivingSituation]
                try:
                    lv_idx = living_situations.index(st.session_state.form_defaults["living_situation"])
                except ValueError:
                    lv_idx = 0
                living_sit_val = st.selectbox("What is your primary living situation?", living_situations, index=lv_idx)
                
                prof_focus_val = st.text_input(
                    "What is your primary professional or daily focus?", 
                    value=st.session_state.form_defaults["professional_focus"],
                    placeholder="e.g., Cybersecurity, Software Dev, Creative, Executive"
                )
                
                st.header("2. Relationship Architecture")
                relationship_statuses = [e.value for e in RelationshipStatus]
                try:
                    rs_idx = relationship_statuses.index(st.session_state.form_defaults["status"])
                except ValueError:
                    rs_idx = 0
                rel_status_val = st.selectbox("What is your current relationship status?", relationship_statuses, index=rs_idx)
                
                has_dep_val = st.checkbox(
                    "Do you manage custody, children, or dependents?", 
                    value=st.session_state.form_defaults["has_dependents"]
                )
                
                custody_details_val = st.text_input(
                    "Optional family or custody dynamics context:", 
                    value=st.session_state.form_defaults["custody_details"],
                    placeholder="e.g., Shared custody tracking alternate weeks, co-parenting"
                )
                
                key_pillars_input = st.text_input(
                    "Who are the critical people in your immediate inner circle?", 
                    value=st.session_state.form_defaults["key_pillars"],
                    placeholder="e.g., Spouse, Best Friend, Parent (separated by commas)"
                )
                
                st.header("3. Outlets & Rituals")
                creative_val = st.text_input(
                    "Creative or technical outlets:", 
                    value=st.session_state.form_defaults["creative_technical"],
                    placeholder="e.g., Python engineering, playing music, grilling (comma separated)"
                )
                recreation_val = st.text_input(
                    "How do you unwind or recreate?", 
                    value=st.session_state.form_defaults["recreation_unwinding"],
                    placeholder="e.g., Gaming/MMOs, hiking, fishing, concerts (comma separated)"
                )
                rituals_val = st.text_input(
                    "Daily micro-rituals or habits:", 
                    value=st.session_state.form_defaults["daily_rituals"],
                    placeholder="e.g., Dedicated V60 coffee brewing, working out (comma separated)"
                )
                
                st.header("4. Core Focus")
                themes_val = st.multiselect(
                    "Select up to 2 primary life themes to center your questions around:",
                    options=[e.value for e in LifeTheme],
                    default=st.session_state.form_defaults["primary_themes"],
                    max_selections=2
                )
                
                additional_notes_val = st.text_area(
                    "Any specific context or situational friction you want the AI to consider?", 
                    value=st.session_state.form_defaults["additional_notes"],
                    placeholder="Optional..."
                )
                
                submitted = st.form_submit_button("Generate My Context Profile")
                
                if submitted:
                    if not themes_val:
                        st.error("Please select at least one primary life theme to direct the AI engine.")
                    else:
                        parse_list = lambda s: [item.strip() for item in s.split(",") if item.strip()] if s else []
                        
                        profile = UserContextProfile(
                            baseline=BaselineProfile(
                                name=name_val if name_val else st.session_state.active_user_name,
                                life_stage=LifeStage(life_stage_val),
                                living_situation=LivingSituation(living_sit_val),
                                professional_focus=prof_focus_val
                            ),
                            relationships=RelationshipProfile(
                                status=RelationshipStatus(rel_status_val),
                                has_dependents=has_dep_val,
                                custody_details=custody_details_val if custody_details_val else None,
                                key_pillars=parse_list(key_pillars_input)
                            ),
                            outlets=OutletsProfile(
                                creative_technical=parse_list(creative_val),
                                recreation_unwinding=parse_list(recreation_val),
                                daily_rituals=parse_list(rituals_val)
                            ),
                            primary_themes=[LifeTheme(t) for t in themes_val],
                            additional_notes=additional_notes_val if additional_notes_val else None
                        )
                        
                        st.session_state.user_profile = profile
                        st.session_state.survey_submitted = True
                        st.session_state.current_response = None
                        
                        # Store current profile directly back into default inputs in case they edit
                        populate_form_defaults(profile)
                        st.rerun()

        else:
            st.success("Profile Structured Successfully!")
            profile = st.session_state.user_profile
            
            # Calculate visual context tags dynamically
            theme_labels = ", ".join([t.value.split(" (")[0] for t in profile.primary_themes])
            summary_label = f"{profile.baseline.life_stage.value} | {theme_labels}"
            
            with st.expander("🔍 View AI Prompt Context Data"):
                st.markdown("**System Instructions:**")
                st.code(PromptEngine.generate_system_instruction())
                st.markdown("**Generated User Payload:**")
                st.code(PromptEngine.generate_user_prompt(profile))
                
            st.markdown("---")
            st.header(f"🎯 Curated Reflections for {profile.baseline.name}")
            
            # Only query the model if we don't already have results saved in this page state session
            if st.session_state.current_response is None:
                with st.spinner("Analyzing your context profile and manufacturing tailored reflections via Gemini..."):
                    try:
                        # Query live Google Gemini using the upgraded SDK and the stable model ID
                        ai_response = PromptEngine.execute_google_inference(profile, model_name="gemini-2.5-flash")
                        st.session_state.current_response = ai_response
                        
                        # Store session details inside the local json history automatically linked to current user
                        save_session_to_history(profile, st.session_state.active_user_id, ai_response.curated_questions)
                        
                    except Exception as e:
                        st.error("Failed to connect or parse response from live Google Gemini API.")
                        st.info("Make sure your GEMINI_API_KEY environment variable is configured properly.")
                        st.exception(e)
            
            # Display the freshly generated insights
            if st.session_state.current_response is not None:
                for idx, q in enumerate(st.session_state.current_response.curated_questions):
                    st.markdown(f"### Question {idx + 1}: *{q.category}*")
                    st.info(q.question_text)
                    st.caption(f"💡 **ContextAI Note:** {q.insight_trigger}")
                    st.markdown("---")
                    
                st.success("💾 This session has been saved automatically to your history!")
                
                # Render immediate sharing options for the fresh question pool
                render_sharing_ui(
                    session_summary=summary_label,
                    questions=st.session_state.current_response.curated_questions,
                    unique_id="fresh_share"
                )

            if st.button("🔄 Edit Survey (Change Themes or Details)"):
                st.session_state.survey_submitted = False
                st.session_state.current_response = None
                st.rerun()

    # ==========================================
    # TAB 2: SAVED JOURNALS & HISTORY (PER-USER)
    # ==========================================
    with tab_history:
        st.header(f"📚 {st.session_state.active_user_name}'s Reflection Logs")
        
        # Filter full database records to show only logs belonging to active_user_id
        all_history = load_history()
        user_history_data = [session for session in all_history if session.get("user_id") == st.session_state.active_user_id]
        
        if not user_history_data:
            st.info("No saved sessions found. Fill out the intake survey to generate your first reflection session!")
        else:
            st.write("Browse your past generated questions. Write down your personal reflections or answers to save them securely.")
            
            for session in user_history_data:
                # Dropdowns for past entries
                session_title = f"📅 {session['timestamp']} — {session['summary']}"
                with st.expander(session_title):
                    
                    # Dynamic action button to load this past run back to our main survey form
                    if st.button("📋 Load This Profile back into Survey Form", key=f"load_p_{session['id']}"):
                        populate_form_defaults(session['profile_details'])
                        st.session_state.survey_submitted = False
                        st.session_state.user_profile = None
                        st.session_state.current_response = None
                        st.toast("Loaded profile details! Check the '✨ Generate Reflections' tab to edit.", icon="🧩")
                        st.rerun()

                    st.markdown("**Profile Details:**")
                    st.json(session['profile_details'])
                    st.markdown("---")
                    
                    # Render historical questions and allow logging answers
                    for idx, q in enumerate(session['questions']):
                        st.markdown(f"#### Q{idx + 1}: {q['category']}")
                        st.info(q['question_text'])
                        st.caption(f"💡 *{q['insight_trigger']}*")
                        
                        # Retrieve the existing response if one has been saved
                        existing_entry = session.get("journal_entries", {}).get(str(idx), "")
                        
                        # Create unique key based on session ID and index
                        input_key = f"journal_{session['id']}_{idx}"
                        
                        user_journal = st.text_area(
                            "Write your thoughts/answer here:",
                            value=existing_entry,
                            key=input_key,
                            placeholder="Type your reflection..."
                        )
                        
                        # Individual question save button
                        if st.button("Save Answer", key=f"btn_{session['id']}_{idx}"):
                            update_journal_entry(session["id"], idx, user_journal)
                            st.success("Reflection answer saved successfully!")
                            
                        st.markdown("---")
                    
                    # Render historical sharing options inside each history record
                    st.subheader("📤 Share This Log File")
                    render_sharing_ui(
                        session_summary=session['summary'],
                        questions=session['questions'],
                        journal_entries=session.get('journal_entries', {}),
                        unique_id=session['id']
                    )