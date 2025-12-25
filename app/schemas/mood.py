from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class SupportMode(str, Enum):
    LISTENING = "listening"
    CALMING = "calming"
    MOTIVATION = "motivation"
    STABILITY = "stability"
    CRISIS_AWARE = "crisis_aware"


class TextEmotionResult(BaseModel):
    emotion: str = "neutral"
    intensity: float = Field(0.0, ge=0.0, le=1.0)
    energy: str = "medium"
    crisis_keywords: List[str] = []
    medical_keywords: List[str] = []
    confidence: float = Field(0.0, ge=0.0, le=1.0)


class FaceEmotionResult(BaseModel):
    emotion_probs: Dict[str, float] = {}
    dominant_emotion: str = "neutral"
    face_detected: bool = False
    multiple_faces: bool = False
    confidence: float = Field(0.0, ge=0.0, le=1.0)


class VoiceEmotionResult(BaseModel):
    emotion_probs: Dict[str, float] = {}
    arousal: str = "neutral"
    dominant_emotion: str = "neutral"
    confidence: float = Field(0.0, ge=0.0, le=1.0)


class MoodState(BaseModel):
    dominant_mood: str = "neutral"
    energy_level: str = "medium"
    stability: str = "stable"
    risk_score: float = Field(0.0, ge=0.0, le=1.0)
    sources: Dict[str, Optional[BaseModel]] = {}


class TextMoodRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=4000)
    conversation_id: Optional[str] = None
    admin_password: Optional[str] = None


class RiskFlags(BaseModel):
    crisis_keywords: List[str] = []
    risk_score: float = Field(0.0, ge=0.0, le=1.0)
    is_crisis: bool = False


class MoodResponse(BaseModel):
    response_text: str
    mood_state: MoodState
    mode: SupportMode
    risk: RiskFlags


class MultimodalMoodResponse(MoodResponse):
    has_text: bool = False
    has_face: bool = False
    has_voice: bool = False


