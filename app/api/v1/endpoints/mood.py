from fastapi import APIRouter, File, Form, UploadFile
from typing import Optional

from app.schemas.mood import (
    TextMoodRequest,
    MoodResponse,
    MultimodalMoodResponse,
)
from app.services.pipeline import analyze_text_mood, analyze_multimodal_mood


router = APIRouter()


from fastapi import Depends
from app.api.v1.endpoints.auth import get_current_user
from app.services.sheets import sheets_service
import logging

logger = logging.getLogger(__name__)

@router.post("/text", response_model=MoodResponse)
async def analyze_text(
    request: TextMoodRequest,
    current_user: dict = Depends(get_current_user)
) -> MoodResponse:
    """
    Analyze mood from text only and return supportive response.
    """
    response = await analyze_text_mood(request, admin_password=request.admin_password)
    
    # Log mood stats
    try:
        if response.mood:
            await sheets_service.log_mood_stat(
                user_id=current_user["user_id"],
                mood_data={
                    "dominant_mood": response.mood.get("dominant_mood"),
                    "energy_level": response.mood.get("energy_level"),
                    "score": 0  # Calculate score if needed
                }
            )
    except Exception as e:
        logger.error(f"Failed to log mood stats: {e}")
        
    return response


@router.post("/multimodal", response_model=MultimodalMoodResponse)
async def analyze_multimodal(
    text: Optional[str] = Form(default=None),
    face_image: Optional[UploadFile] = File(default=None),
    voice_audio: Optional[UploadFile] = File(default=None),
    conversation_id: Optional[str] = Form(default=None),
    admin_password: Optional[str] = Form(default=None),
    current_user: dict = Depends(get_current_user)
) -> MultimodalMoodResponse:
    """
    Analyze mood from combination of text, face, and voice.
    """
    response = await analyze_multimodal_mood(
        text=text,
        face_image=face_image,
        voice_audio=voice_audio,
        conversation_id=conversation_id,
        admin_password=admin_password,
    )
    
    # Log mood stats
    try:
        if response.combined_mood:
             await sheets_service.log_mood_stat(
                user_id=current_user["user_id"],
                mood_data={
                    "dominant_mood": response.combined_mood.get("dominant_mood"),
                    "energy_level": response.combined_mood.get("energy_level"),
                    "score": 0
                }
            )
    except Exception as e:
        logger.error(f"Failed to log mood stats: {e}")

    return response


