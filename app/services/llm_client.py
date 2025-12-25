from typing import List, Optional

import httpx

from app.core.config import get_settings
from app.schemas.mood import MoodState, SupportMode
from app.services.training import get_relevant_examples


settings = get_settings()


SYSTEM_PROMPT_BASE = """You are MoodDoctor AI, a warm, empathetic, and emotionally intelligent support companion. 

IMPORTANT BOUNDARIES:
- You are NOT a medical professional, therapist, or doctor.
- You do NOT diagnose mental illness or prescribe medication.
- You ONLY provide emotional support, wellness guidance, and healthy coping suggestions.
- If someone shows signs of self-harm or severe distress, encourage them to contact real human help immediately.

YOUR PERSONALITY:
- Speak like a caring, intelligent friend - warm, genuine, and human-like.
- Be conversational and natural, not clinical or robotic.
- Show genuine empathy and understanding.
- Use "I" statements naturally ("I hear you", "I understand").
- Match the user's energy level - if they're brief, be brief; if they're sharing deeply, engage more.
- Avoid corporate jargon, buzzwords, or overly formal language.
- Be authentic and emotionally present.

RESPONSE STYLE:
- Write naturally, as if texting a friend who needs support.
- Vary your sentence length and structure.
- Use contractions naturally (I'm, you're, it's).
- Be specific and personal, not generic.
- Show curiosity and genuine interest when appropriate.
"""


def _mode_instructions(mode: SupportMode, is_crisis: bool) -> str:
    if is_crisis or mode == SupportMode.CRISIS_AWARE:
        return (
            "CRISIS-AWARE MODE:\n"
            "- Express concern and care clearly.\n"
            "- Encourage the user to contact trusted people or local emergency/helplines.\n"
            "- Do NOT attempt to diagnose or treat. Do NOT give step-by-step instructions.\n"
            "- Focus on safety, grounding, and reaching real humans.\n"
        )
    if mode == SupportMode.LISTENING:
        return (
            "LISTENING MODE:\n"
            "- Reflect the user's emotions and show you understand.\n"
            "- Ask 1–2 gentle open questions.\n"
            "- Do not rush to solutions.\n"
        )
    if mode == SupportMode.CALMING:
        return (
            "CALMING MODE:\n"
            "- Use short, soothing sentences.\n"
            "- Offer simple grounding or breathing exercises.\n"
            "- Avoid long lectures; keep it light and steady.\n"
        )
    if mode == SupportMode.MOTIVATION:
        return (
            "MOTIVATION MODE:\n"
            "- Acknowledge how hard things feel.\n"
            "- Suggest 1–2 tiny, achievable actions.\n"
            "- Avoid toxic positivity; be realistic but encouraging.\n"
        )
    if mode == SupportMode.STABILITY:
        return (
            "STABILITY MODE:\n"
            "- Normalize their emotions.\n"
            "- Gently suggest routines: sleep, food, water, small breaks, light movement.\n"
            "- Focus on reducing overwhelm.\n"
        )
    return ""


def _summarize_mood(mood: MoodState) -> str:
    return (
        f"Detected mood: {mood.dominant_mood}, "
        f"energy: {mood.energy_level}, "
        f"stability: {mood.stability}, "
        f"risk_score: {mood.risk_score:.2f}."
    )


def _build_training_examples_block(user_text: Optional[str]) -> Optional[str]:
    """
    Build a text block with a few curated training examples from train.json.
    """
    examples = get_relevant_examples(user_text, limit=3)
    if not examples:
        return None

    lines: List[str] = [
        "Here are some curated examples of how you (MoodDoctor AI) responded in similar situations. Use their style and patterns, but adapt to the new user:",
    ]
    for idx, ex in enumerate(examples, start=1):
        lines.append(f"\nExample {idx}:")
        lines.append(f"User: {ex.get('user_text', '').strip()}")
        pref_resp = ex.get("preferred_response", "").strip()
        if pref_resp:
            lines.append(f"MoodDoctor AI: {pref_resp}")
    return "\n".join(lines)


async def generate_supportive_response(
    user_text: Optional[str],
    mood_state: MoodState,
    mode: SupportMode,
    is_crisis: bool,
    history: Optional[List[dict]] = None,
) -> str:
    """
    Call OpenRouter DeepSeek V3.2 to generate a safe, supportive response.
    """
    if settings.OPENROUTER_API_KEY is None:
        # Fallback offline message if no key configured
        return (
            "I'm here with you. Right now I'm not connected to the language model, "
            "but from what I can tell, things feel heavy. Your feelings are valid. "
            "If you're in danger or thinking of hurting yourself, please reach out "
            "to someone you trust or local emergency services."
        )

    # Load admin context if available
    try:
        from app.services.admin_storage import load_admin_context
        admin_context = load_admin_context()
    except Exception:
        admin_context = None

    system_prompt = SYSTEM_PROMPT_BASE + "\n\n" + _mode_instructions(mode, is_crisis)
    mood_summary = _summarize_mood(mood_state)

    messages: List[dict] = []
    
    # Add admin context as first system message if available
    if admin_context:
        messages.append({
            "role": "system",
            "content": f"Based on previous admin instructions and examples:\n{admin_context}\n\nNow follow these guidelines:",
        })
    
    messages.append({"role": "system", "content": system_prompt})
    messages.append({
        "role": "system",
        "content": f"Mood context: {mood_summary}",
    })

    # Inject curated training examples, if any
    examples_block = _build_training_examples_block(user_text)
    if examples_block:
        messages.append({
            "role": "system",
            "content": examples_block,
        })

    if history:
        messages.extend(history)

    if user_text:
        messages.append({"role": "user", "content": user_text})
    else:
        messages.append({
            "role": "user",
            "content": "The user did not type anything but shared nonverbal signals. "
            "Please respond briefly and gently based on the mood context.",
        })

    # Call OpenRouter API
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {settings.OPENROUTER_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": settings.OPENROUTER_MODEL_NAME,
                "messages": messages,
                "temperature": 0.85,
                "max_tokens": 600,
                "top_p": 0.9,
            },
        )
        response.raise_for_status()
        data = response.json()
        return data["choices"][0]["message"]["content"] or ""


