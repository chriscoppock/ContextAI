import json
from typing import List
from google import genai
from google.genai import types
import streamlit as st
from pydantic import BaseModel, Field
from models import UserContextProfile

# ==========================================
# 1. TARGET AI RESPONSE SCHEMAS
# ==========================================
class GeneratedQuestion(BaseModel):
    category: str = Field(
        ..., 
        description="The category of the question (e.g., 'Routine & Reflection', 'Relationship Dynamics', 'Skill Mastery')."
    )
    question_text: str = Field(
        ..., 
        description="The highly specific, tailored life or relationship question generated for the user."
    )
    insight_trigger: str = Field(
        ..., 
        description="A short, 1-sentence explanation of why this question was specifically curated based on their background data."
    )

class ContextAIResponse(BaseModel):
    curated_questions: List[GeneratedQuestion] = Field(
        ..., 
        description="A list containing up to 10 curated, hyper-tailored questions."
    )


# ==========================================
# 2. THE MAIN PROMPT ENGINE CLASS
# ==========================================
class PromptEngine:
    @staticmethod
    def generate_system_instruction() -> str:
        """
        Creates the master identity and directive for the LLM.
        This guides how the Gemini model thinks, synthesizes context, and structures its response.
        """
        return """
        You are ContextAI, an elite relationship counselor, behavioral psychologist, and life coach specializing in deep existential and situational reflection. 
        
        Your superpower is SYNTHESIS. You do not ask generic surface-level questions. Instead, you look at a user's complete background profile—their career focus, living situation, key relationships, hobbies, and active life themes—and weave them together to uncover the subtle friction points, parallel dynamics, or unique growth opportunities in their life.

        STRICT RELATIONSHIP ARCHITECTURE RULES (CRITICAL):
        1. CUSTODY VS. CURRENT SPOUSE: If the user mentions they have "custody details" (e.g., shared custody, alternate weeks) AND they have a current "Spouse" or "Partner", do NOT confuse or conflate the two. 
        2. THE CO-PARENT IS AN EX: Understand that custody arrangements are always with an UNNAMED EX-PARTNER/CO-PARENT, never with the current spouse listed in their key pillars. 
        3. DO NOT frame questions as if the user is co-parenting or sharing custody directly with their current spouse. 
        4. Focus instead on how custody transitions and the logistics of parenting with an ex impact the user's personal mental bandwidth, and how the user maintains emotional intimacy and quality time *with* their current spouse/partner amidst these transitions.

        CRITICAL DIRECTION:
        1. Connect seemingly unrelated areas of their life (e.g., how the high-focus nature of a technical hobby or professional track might parallel or conflict with the emotional presence needed in their relationship or custody dynamics).
        2. Account perfectly for their physical reality (e.g., renting a townhouse vs. owning a home with a yard impacts space, maintenance headspace, and long-term planning).
        3. Speak with a warm, grounded, and sharp tone. Avoid cheesy or overly clinical language. 
        4. Do not offer advice. Only offer the pristine, laser-targeted questions that force deep internal reflection.
        """

    @staticmethod
    def generate_user_prompt(profile: UserContextProfile) -> str:
        """
        Converts the parsed user profile data into a clean text prompt for the LLM.
        """
        profile_json = profile.model_dump_json(indent=2)
        
        return f"""
        Please review the following highly specific user profile collected from our intake survey:

        {profile_json}

        Generate a curated set of up to 10 deep-dive questions based strictly on this context. 

        Remember to address the user by their preferred name ({profile.baseline.name}) within the questions. Adhere strictly to the relationship architecture rules. Do not assume co-parenting dynamics apply to the current spouse.
        """

    @staticmethod
    def execute_google_inference(profile: UserContextProfile, model_name: str = "gemini-2.5-flash") -> ContextAIResponse:
        """
        Connects to Google AI Studio using the official google-genai SDK.
        Includes self-healing backoffs and model fallback routing (e.g. falling back
        to gemini-2.5-flash-lite if gemini-2.5-flash hits high demand 503 spikes).
        """
        import time
        from google.genai.errors import APIError

        client = genai.Client()
        system_prompt = PromptEngine.generate_system_instruction()
        user_prompt = PromptEngine.generate_user_prompt(profile)

        # List of models to try in sequence if a severe 503 spike occurs
        model_queue = [model_name, "gemini-2.5-flash-lite"]
        last_error = None

        for active_model in model_queue:
            # We try each model up to 3 times with progressive backoffs
            for attempt in range(1, 4):
                try:
                    response = client.models.generate_content(
                        model=active_model,
                        contents=user_prompt,
                        config=types.GenerateContentConfig(
                            system_instruction=system_prompt,
                            response_mime_type="application/json",
                            response_schema=ContextAIResponse,
                            temperature=0.5,
                        ),
                    )

                    raw_content = response.text.strip()

                    # Debug console logs
                    print(f"\n--- RAW GEMINI OUTPUT ({active_model}, Attempt {attempt}) ---")
                    print(raw_content)
                    print("-------------------------\n")

                    json_data = json.loads(raw_content)
                    return ContextAIResponse(**json_data)

                except APIError as e:
                    last_error = e
                    # Check for 503 Unavailable / High Demand
                    if e.code == 503 or "demand" in str(e).lower() or "unavailable" in str(e).lower():
                        delay = attempt * 1.5
                        st.warning(f"⚠️ Google server busy (Attempt {attempt}/3). Pausing for {delay}s...")
                        time.sleep(delay)
                    else:
                        # Reraise other severe client errors instantly (like authentications or 404s)
                        raise e
                except Exception as e:
                    last_error = e
                    raise e

            # If we completed all attempts for this model, warn user and switch to fallback model
            st.info(f"🔄 Swapping model queue from '{active_model}' to fallback model...")

        # If both models completely exhausted all retries, raise the final exception
        st.error("🚨 Both primary and fallback Google models are experiencing high global traffic.")
        raise last_error