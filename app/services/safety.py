from app.schemas.mood import MoodState, RiskFlags


CRISIS_THRESHOLD = 0.6


def compute_risk_flags(mood_state: MoodState, text_crisis_keywords: list[str]) -> RiskFlags:
    """
    Build RiskFlags from mood and text crisis signals.
    """
    risk_score = max(mood_state.risk_score, 0.0)

    if text_crisis_keywords:
        # Bump risk if explicit crisis language
        risk_score = max(risk_score, 0.7)

    is_crisis = risk_score >= CRISIS_THRESHOLD

    return RiskFlags(
        crisis_keywords=text_crisis_keywords,
        risk_score=risk_score,
        is_crisis=is_crisis,
    )


