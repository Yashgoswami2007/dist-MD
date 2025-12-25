from typing import Any, Dict

from fastapi import WebSocket

from app.schemas.mood import SupportMode
from app.services.text_emotion import analyze_text
from app.services.face_emotion import analyze_face
from app.services.voice_emotion import analyze_voice
from app.services.fusion import fuse_emotions
from app.services.safety import compute_risk_flags
from app.services.llm_client import generate_supportive_response


class StreamingSessionManager:
    """
    Very lightweight streaming session handler.

    For each websocket, we keep the latest modality results and recompute
    mood/response on each message.
    """

    def __init__(self) -> None:
        self.connections: Dict[WebSocket, Dict[str, Any]] = {}

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.connections[websocket] = {
            "text": None,
            "face": None,
            "voice": None,
        }

    async def disconnect(self, websocket: WebSocket) -> None:
        self.connections.pop(websocket, None)

    async def handle_message(
        self, websocket: WebSocket, data: Dict[str, Any]
    ) -> Dict[str, Any] | None:
        session = self.connections.get(websocket)
        if session is None:
            return None

        msg_type = data.get("type")
        payload = data.get("payload")

        if msg_type == "text" and isinstance(payload, str):
            session["text"] = await analyze_text(payload)
            user_text = payload
        elif msg_type == "image" and isinstance(payload, list):
            # Expect base64 or raw bytes in real impl; here we skip actual decode.
            session["face"] = await analyze_face(bytes(payload))
            user_text = None
        elif msg_type == "audio" and isinstance(payload, list):
            session["voice"] = await analyze_voice(bytes(payload))
            user_text = None
        else:
            return {"error": "Invalid message format"}

        mood_state = fuse_emotions(
            text=session["text"],
            face=session["face"],
            voice=session["voice"],
        )
        crisis_keywords = session["text"].crisis_keywords if session["text"] else []
        risk = compute_risk_flags(mood_state, crisis_keywords)

        mode = await self._select_mode(risk.risk_score, mood_state.dominant_mood)

        response_text = await generate_supportive_response(
            user_text=user_text,
            mood_state=mood_state,
            mode=mode,
            is_crisis=risk.is_crisis,
            history=None,
        )

        return {
            "response_text": response_text,
            "mood_state": mood_state.model_dump(),
            "risk": risk.model_dump(),
            "mode": mode.value,
        }

    async def _select_mode(self, risk_score: float, dominant_mood: str) -> SupportMode:
        if risk_score >= 0.6:
            return SupportMode.CRISIS_AWARE
        if dominant_mood in {"sad", "anxious", "overwhelmed"}:
            return SupportMode.CALMING
        if dominant_mood in {"tired", "exhausted"}:
            return SupportMode.STABILITY
        if dominant_mood in {"neutral"}:
            return SupportMode.LISTENING
        return SupportMode.MOTIVATION


