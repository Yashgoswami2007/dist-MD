import base64
import json
from io import BytesIO
from typing import Dict

import google.generativeai as genai

from app.core.config import get_settings
from app.schemas.mood import FaceEmotionResult

# Initialize Gemini client
_settings = get_settings()
if _settings.GEMINI_API_KEY:
    genai.configure(api_key=_settings.GEMINI_API_KEY)


async def analyze_face(image_bytes: bytes) -> FaceEmotionResult:
    """
    Analyze facial emotion using Google Gemini Vision API.

    Sends the image to Gemini with a prompt asking for emotion detection,
    then parses the response into structured emotion probabilities.
    """
    if not _settings.GEMINI_API_KEY:
        # Fallback to neutral if no API key
        return FaceEmotionResult(
            emotion_probs={"neutral": 1.0},
            dominant_emotion="neutral",
            face_detected=False,
            multiple_faces=False,
            confidence=0.0,
        )

    try:
        model = genai.GenerativeModel(_settings.GEMINI_MODEL_NAME)

        # Prepare image
        image_data = BytesIO(image_bytes)
        from PIL import Image

        pil_image = Image.open(image_data)

        # Prompt Gemini to analyze facial emotion
        prompt = """Analyze this image for facial emotion detection. 

Please provide a JSON response with:
1. "emotions": an object with probabilities (0.0 to 1.0) for: happy, sad, anxious, angry, neutral, exhausted, surprised, fearful
2. "dominant_emotion": the most likely emotion (string)
3. "face_detected": boolean indicating if a face is visible
4. "multiple_faces": boolean indicating if multiple faces are detected
5. "confidence": a float (0.0 to 1.0) indicating your confidence in the analysis

Example format:
{
  "emotions": {"happy": 0.7, "neutral": 0.2, "sad": 0.1, "anxious": 0.0, "angry": 0.0, "exhausted": 0.0, "surprised": 0.0, "fearful": 0.0},
  "dominant_emotion": "happy",
  "face_detected": true,
  "multiple_faces": false,
  "confidence": 0.85
}

Respond ONLY with valid JSON, no other text."""

        response = model.generate_content([prompt, pil_image])

        # Parse Gemini's response
        response_text = response.text.strip()

        # Try to extract JSON from response (sometimes Gemini wraps it in markdown)
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

        return FaceEmotionResult(
            emotion_probs=emotion_probs,
            dominant_emotion=dominant,
            face_detected=gemini_data.get("face_detected", False),
            multiple_faces=gemini_data.get("multiple_faces", False),
            confidence=min(1.0, max(0.0, gemini_data.get("confidence", 0.5))),
        )

    except Exception as e:
        # Fallback on any error
        return FaceEmotionResult(
            emotion_probs={"neutral": 1.0},
            dominant_emotion="neutral",
            face_detected=False,
            multiple_faces=False,
            confidence=0.0,
        )


