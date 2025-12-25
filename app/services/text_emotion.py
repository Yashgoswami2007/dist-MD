from typing import List

from app.schemas.mood import TextEmotionResult

CRISIS_KEYWORDS: List[str] = [
    "suicide",
    "kill myself",
    "end it",
    "self-harm",
]

NEGATIVE_WORDS: List[str] = [
    "sad",
    "depressed",
    "anxious",
    "angry",
    "worried",
    "tired",
    "exhausted",
    "hopeless",
]

POSITIVE_WORDS: List[str] = [
    "happy",
    "excited",
    "grateful",
    "hopeful",
    "good",
]


async def analyze_text(text: str) -> TextEmotionResult:
    """
    Very simple heuristic text emotion analyzer.

    This is a placeholder – replace with a fine‑tuned transformer later.
    """
    lowered = text.lower()
    crisis_hits = [w for w in CRISIS_KEYWORDS if w in lowered]

    neg_score = sum(1 for w in NEGATIVE_WORDS if w in lowered)
    pos_score = sum(1 for w in POSITIVE_WORDS if w in lowered)

    if neg_score > pos_score and neg_score > 0:
        emotion = "sad"
        energy = "low"
        intensity = min(1.0, 0.2 * neg_score)
    elif pos_score > neg_score and pos_score > 0:
        emotion = "happy"
        energy = "medium"
        intensity = min(1.0, 0.2 * pos_score)
    else:
        emotion = "neutral"
        energy = "medium"
        intensity = 0.2

    confidence = min(1.0, 0.5 + 0.1 * (neg_score + pos_score))

    return TextEmotionResult(
        emotion=emotion,
        intensity=intensity,
        energy=energy,
        crisis_keywords=crisis_hits,
        medical_keywords=[],
        confidence=confidence,
    )


