from typing import List, Optional
from enum import Enum
from pydantic import BaseModel, Field

class LifeStage(str, Enum):
    EARLY_20S = "Early 20s"
    LATE_20S_EARLY_30S = "Late 20s to Early 30s"
    MID_30S_EARLY_40S = "Mid 30s to Early 40s"
    MID_40S = "Mid 40s"
    FIFTIES_PLUS = "50s or beyond"

class LivingSituation(str, Enum):
    RENT_TOWNHOUSE = "Renting a townhouse / condo"
    OWN_HOUSE_YARD = "Owning a house with a yard"
    URBAN_APARTMENT = "Urban apartment living"
    NOMADIC_OTHER = "Nomadic or alternative living situation"

class RelationshipStatus(str, Enum):
    SINGLE = "Single"
    DATING = "Dating / New Relationship"
    LONG_TERM_PARTNER = "Long-term partnership"
    MARRIED = "Married"
    DIVORCED_COPARENTING = "Divorced and co-parenting"

class LifeTheme(str, Enum):
    GROWTH_LEARNING = "Growth & Learning (Skills, certifications, career pivots)"
    CONNECTION_DEPTH = "Connection & Depth (Nurturing key relationships, family)"
    BALANCE_TRANSITION = "Balance & Transition (Juggling professional demands and personal time)"

class BaselineProfile(BaseModel):
    name: str = Field(..., description="The user's first name or preferred nickname.")
    life_stage: LifeStage = Field(..., description="The user's current decade or general life stage.")
    living_situation: LivingSituation = Field(..., description="The user's primary housing/living dynamic.")
    professional_focus: str = Field(..., description="Primary daily focus or industry, e.g., Tech, Creative, Corporate.")

class RelationshipProfile(BaseModel):
    status: RelationshipStatus = Field(..., description="Current romantic or relationship status.")
    has_dependents: bool = Field(..., description="Whether the user manages custody, kids, or dependents.")
    custody_details: Optional[str] = Field(None, description="Optional specifics about shared custody or family structures.")
    key_pillars: List[str] = Field(
        default=[], 
        description="List of critical people in their immediate inner circle (e.g., 'Spouse', 'Best friend', 'Parent')."
    )

class OutletsProfile(BaseModel):
    creative_technical: List[str] = Field(default=[], description="Outlets like coding, music, photography, grilling.")
    recreation_unwinding: List[str] = Field(default=[], description="Activities like gaming, hiking, fishing, concerts.")
    daily_rituals: List[str] = Field(default=[], description="Small daily habits like coffee rituals, reading, or working out.")

class UserContextProfile(BaseModel):
    """
    The master data structure containing all validated user demographics and configurations.
    """
    baseline: BaselineProfile
    relationships: RelationshipProfile
    outlets: OutletsProfile
    primary_themes: List[LifeTheme] = Field(
        ..., 
        max_length=2, 
        description="The 1-2 primary focus themes the user wants to center questions around."
    )
    additional_notes: Optional[str] = Field(None, description="Any specific real-world context the user wants to add manually.")