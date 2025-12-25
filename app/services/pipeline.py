from typing import Optional

from fastapi import UploadFile

from app.schemas.mood import (
    TextMoodRequest,
    MoodResponse,
    MultimodalMoodResponse,
    SupportMode,
)
from app.services.text_emotion import analyze_text
from app.services.face_emotion import analyze_face
from app.services.voice_emotion import analyze_voice
from app.services.fusion import fuse_emotions
from app.services.safety import compute_risk_flags
from app.services.llm_client import generate_supportive_response
from app.services.memory import memory_store
from app.services.admin_storage import admin_storage
from app.core.config import get_settings


async def _select_mode(risk_score: float, dominant_mood: str) -> SupportMode:
    if risk_score >= 0.6:
        return SupportMode.CRISIS_AWARE
    if dominant_mood in {"sad", "anxious", "overwhelmed"}:
        return SupportMode.CALMING
    if dominant_mood in {"tired", "exhausted"}:
        return SupportMode.STABILITY
    if dominant_mood in {"neutral"}:
        return SupportMode.LISTENING
    return SupportMode.MOTIVATION


async def analyze_text_mood(request: TextMoodRequest, admin_password: Optional[str] = None) -> MoodResponse:
    text_result = await analyze_text(request.text)
    mood_state = fuse_emotions(text=text_result, face=None, voice=None)
    risk = compute_risk_flags(mood_state, text_result.crisis_keywords)
    mode = await _select_mode(risk.risk_score, mood_state.dominant_mood)

    # Get conversation history if conversation_id provided
    conversation_id = request.conversation_id or "default"
    history = await memory_store.get_conversation_history(conversation_id, max_messages=10)

    response_text = await generate_supportive_response(
        user_text=request.text,
        mood_state=mood_state,
        mode=mode,
        is_crisis=risk.is_crisis,
        history=history if history else None,
    )

    # Check if admin
    settings = get_settings()
    is_admin = (admin_password or request.admin_password) == settings.ADMIN_PASSWORD if settings.ADMIN_PASSWORD else False
    
    mood_dict = mood_state.model_dump() if hasattr(mood_state, "model_dump") else mood_state.dict() if hasattr(mood_state, "dict") else None
    mode_str = mode.value if hasattr(mode, "value") else str(mode)
    
    # Save to admin_conversations.json if admin, otherwise Memory.json
    if is_admin:
        admin_storage.save_admin_conversation(request.text, response_text)
    else:
        await memory_store.save_message(
            conversation_id=conversation_id,
            role="user",
            content=request.text,
            mood_state=mood_dict,
            mode=mode_str,
        )
        await memory_store.save_message(
            conversation_id=conversation_id,
            role="assistant",
            content=response_text,
            mood_state=mood_dict,
            mode=mode_str,
        )

    return MoodResponse(
        response_text=response_text,
        mood_state=mood_state,
        mode=mode,
        risk=risk,
    )


async def analyze_multimodal_mood(
    text: Optional[str],
    face_image: Optional[UploadFile],
    voice_audio: Optional[UploadFile],
    conversation_id: Optional[str],
    admin_password: Optional[str] = None,
) -> MultimodalMoodResponse:
    text_result = None
    face_result = None
    voice_result = None

    text_content = text.strip() if text and text.strip() else ""
    if text_content:
        text_result = await analyze_text(text_content)

    if face_image is not None:
        image_bytes = await face_image.read()
        face_result = await analyze_face(image_bytes)

    if voice_audio is not None:
        audio_bytes = await voice_audio.read()
        voice_result = await analyze_voice(audio_bytes)

    mood_state = fuse_emotions(text=text_result, face=face_result, voice=voice_result)

    crisis_keywords = text_result.crisis_keywords if text_result else []
    risk = compute_risk_flags(mood_state, crisis_keywords)
    mode = await _select_mode(risk.risk_score, mood_state.dominant_mood)

    # Get conversation history if conversation_id provided
    conv_id = conversation_id or "default"
    history = await memory_store.get_conversation_history(conv_id, max_messages=10)

    response_text = await generate_supportive_response(
        user_text=text_content if text_content else None,
        mood_state=mood_state,
        mode=mode,
        is_crisis=risk.is_crisis,
        history=history if history else None,
    )

    # Check if admin
    settings = get_settings()
    is_admin = admin_password == settings.ADMIN_PASSWORD if settings.ADMIN_PASSWORD else False
    
    mood_dict = mood_state.model_dump() if hasattr(mood_state, "model_dump") else mood_state.dict() if hasattr(mood_state, "dict") else None
    mode_str = mode.value if hasattr(mode, "value") else str(mode)
    
    # Save to admin_conversations.json if admin, otherwise Memory.json
    if is_admin and text_content:
        admin_storage.save_admin_conversation(text_content, response_text)
    elif text_content:
        await memory_store.save_message(
            conversation_id=conv_id,
            role="user",
            content=text_content,
            mood_state=mood_dict,
            mode=mode_str,
        )
        await memory_store.save_message(
            conversation_id=conv_id,
            role="assistant",
            content=response_text,
            mood_state=mood_dict,
            mode=mode_str,
        )

    return MultimodalMoodResponse(
        response_text=response_text,
        mood_state=mood_state,
        mode=mode,
        risk=risk,
        has_text=bool(text_content),
        has_face=face_result is not None,
        has_voice=voice_result is not None,
    )


