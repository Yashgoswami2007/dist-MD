from typing import Optional

from app.schemas.mood import (
    MoodState,
    TextEmotionResult,
    FaceEmotionResult,
    VoiceEmotionResult,
)


def fuse_emotions(
    text: Optional[TextEmotionResult],
    face: Optional[FaceEmotionResult],
    voice: Optional[VoiceEmotionResult],
) -> MoodState:
    """
    Combine available modality results into a single MoodState.

    Simple weighted heuristic:
    - Text: weight 0.5
    - Face: weight 0.3
    - Voice: weight 0.2
    We bias toward nonverbal when text says \"I'm fine\" but is negative.
    """
    # Defaults
    dominant_mood = "neutral"
    energy_level = "medium"
    stability = "stable"
    risk_score = 0.0

    weights = {"text": 0.5, "face": 0.3, "voice": 0.2}

    # Simple mood voting
    mood_votes = {}

    if text is not None:
        mood_votes[text.emotion] = mood_votes.get(text.emotion, 0.0) + weights["text"]
        if text.emotion in {"sad", "anxious", "angry"}:
            risk_score += 0.2 * text.intensity

    if face is not None and face.face_detected:
        mood_votes[face.dominant_emotion] = mood_votes.get(
            face.dominant_emotion, 0.0
        ) + weights["face"] * face.confidence

    if voice is not None:
        mood_votes[voice.dominant_emotion] = mood_votes.get(
            voice.dominant_emotion, 0.0
        ) + weights["voice"] * voice.confidence

    if mood_votes:
        dominant_mood = max(mood_votes.items(), key=lambda x: x[1])[0]

    # Energy heuristic from text + voice
    if text is not None:
        energy_level = text.energy
    if voice is not None and voice.arousal == "agitated":
        energy_level = "high"
    elif voice is not None and voice.arousal == "calm":
        energy_level = "low"

    # Stability heuristic
    if risk_score >= 0.6:
        stability = "fragile"
    elif risk_score >= 0.3:
        stability = "overwhelmed"
    else:
        stability = "stable"

    risk_score = min(1.0, risk_score)

    return MoodState(
        dominant_mood=dominant_mood,
        energy_level=energy_level,
        stability=stability,
        risk_score=risk_score,
        sources={
            "text": text,
            "face": face,
            "voice": voice,
        },
    )


