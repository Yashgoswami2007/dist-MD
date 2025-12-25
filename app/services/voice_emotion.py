import base64
import json
import os
import tempfile
from io import BytesIO

import google.generativeai as genai

from app.core.config import get_settings
from app.schemas.mood import VoiceEmotionResult

# Initialize Gemini client
_settings = get_settings()
if _settings.GEMINI_API_KEY:
    genai.configure(api_key=_settings.GEMINI_API_KEY)


async def analyze_voice(audio_bytes: bytes) -> VoiceEmotionResult:
    """
    Analyze voice emotion using Google Gemini Audio API.

    Gemini 1.5 can process audio directly. We send the audio clip
    and ask it to analyze emotional tone, arousal level, etc.
    """
    if not _settings.GEMINI_API_KEY:
        # Fallback to neutral if no API key
        return VoiceEmotionResult(
            emotion_probs={"neutral": 1.0},
            arousal="neutral",
            dominant_emotion="neutral",
            confidence=0.0,
        )

    try:
        model = genai.GenerativeModel(_settings.GEMINI_MODEL_NAME)

        # Prepare audio (Gemini expects base64 or file-like object)
        # For now, we'll use BytesIO and let Gemini handle it
        audio_data = BytesIO(audio_bytes)

        # Prompt Gemini to analyze voice emotion
        prompt = """Analyze this audio clip for emotional tone and voice characteristics.

Please provide a JSON response with:
1. "emotions": an object with probabilities (0.0 to 1.0) for: happy, sad, anxious, angry, neutral, exhausted, excited, calm
2. "dominant_emotion": the most likely emotion based on voice tone (string)
3. "arousal": one of "calm", "neutral", or "agitated" based on voice energy/speed
4. "confidence": a float (0.0 to 1.0) indicating your confidence in the analysis

Example format:
{
  "emotions": {"anxious": 0.6, "sad": 0.2, "neutral": 0.15, "happy": 0.05, "angry": 0.0, "exhausted": 0.0, "excited": 0.0, "calm": 0.0},
  "dominant_emotion": "anxious",
  "arousal": "agitated",
  "confidence": 0.75
}

Respond ONLY with valid JSON, no other text."""

        # Gemini 1.5 can process audio files
        # We'll upload the audio bytes as a file and then reference it
        # Create a temporary file for the audio
        with tempfile.NamedTemporaryFile(delete=False, suffix='.wav') as tmp_file:
            tmp_file.write(audio_bytes)
            tmp_path = tmp_file.name
        
        try:
            # Upload audio file to Gemini
            uploaded_file = genai.upload_file(path=tmp_path)
            response = model.generate_content([prompt, uploaded_file])
        except Exception as upload_error:
            # Fallback: try direct bytes approach if upload fails
            try:
                # Some Gemini models can accept audio bytes directly
                response = model.generate_content([prompt, {"mime_type": "audio/wav", "data": audio_bytes}])
            except Exception:
                # Final fallback: return neutral if all else fails
                return VoiceEmotionResult(
                    emotion_probs={"neutral": 1.0},
                    arousal="neutral",
                    dominant_emotion="neutral",
                    confidence=0.0,
                )
        finally:
            # Clean up temp file
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

        # Parse Gemini's response
        response_text = response.text.strip()

        # Try to extract JSON from response
        if "```json" in response_text:
            response_text = response_text.split("```json")[1].split("```")[0].strip()
        elif "```" in response_text:
            response_text = response_text.split("```")[1].split("```")[0].strip()

        gemini_data = json.loads(response_text)

        # Normalize emotion probabilities
        emotions = gemini_data.get("emotions", {})
        total = sum(emotions.values())
        if total > 0:
            emotion_probs = {k: v / total for k, v in emotions.items()}
        else:
            emotion_probs = {"neutral": 1.0}

        # Get dominant emotion
        dominant = gemini_data.get("dominant_emotion", "neutral")
        if dominant not in emotion_probs:
            dominant = max(emotion_probs.items(), key=lambda x: x[1])[0]

        # Get arousal
        arousal = gemini_data.get("arousal", "neutral")
        if arousal not in ["calm", "neutral", "agitated"]:
            arousal = "neutral"

        return VoiceEmotionResult(
            emotion_probs=emotion_probs,
            arousal=arousal,
            dominant_emotion=dominant,
            confidence=min(1.0, max(0.0, gemini_data.get("confidence", 0.5))),
        )

    except Exception as e:
        # Fallback on any error (audio processing can be tricky)
        return VoiceEmotionResult(
            emotion_probs={"neutral": 1.0},
            arousal="neutral",
            dominant_emotion="neutral",
            confidence=0.0,
        )


