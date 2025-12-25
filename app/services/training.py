import json
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.core.config import get_settings


_settings = get_settings()
_lock = threading.Lock()

TRAIN_FILE_PATH = Path("train.json")


def _ensure_train_file() -> None:
    if not TRAIN_FILE_PATH.exists():
        TRAIN_FILE_PATH.write_text(json.dumps({"examples": []}, indent=2), encoding="utf-8")


def load_train_data() -> Dict[str, Any]:
    """Load the entire train.json file."""
    _ensure_train_file()
    with _lock:
        raw = TRAIN_FILE_PATH.read_text(encoding="utf-8")
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            data = {"examples": []}
            TRAIN_FILE_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")
    data.setdefault("examples", [])
    return data


def save_train_data(data: Dict[str, Any]) -> None:
    """Persist the train.json file."""
    with _lock:
        TRAIN_FILE_PATH.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def add_training_example(
    user_text: str,
    preferred_response: str,
    mood_label: Optional[str] = None,
    tags: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Add a single training example and return it."""
    import uuid

    data = load_train_data()
    example_id = f"ex_{uuid.uuid4().hex[:8]}"
    example = {
        "id": example_id,
        "user_text": user_text,
        "preferred_response": preferred_response,
        "mood_label": mood_label,
        "tags": tags or [],
    }
    data["examples"].append(example)
    save_train_data(data)
    return example


def list_training_examples() -> List[Dict[str, Any]]:
    data = load_train_data()
    return data.get("examples", [])


def delete_training_example(example_id: str) -> bool:
    data = load_train_data()
    before = len(data.get("examples", []))
    data["examples"] = [ex for ex in data.get("examples", []) if ex.get("id") != example_id]
    after = len(data["examples"])
    changed = before != after
    if changed:
        save_train_data(data)
    return changed


def get_relevant_examples(user_text: Optional[str], limit: int = 3) -> List[Dict[str, Any]]:
    """
    Return up to `limit` examples that look relevant to the given user_text.

    Simple heuristic: keyword overlap between user_text and example.user_text/tags.
    """
    if not user_text:
        return []

    user_lower = user_text.lower()
    words = {w for w in user_lower.split() if len(w) > 3}

    examples = list_training_examples()
    scored: List[tuple[float, Dict[str, Any]]] = []

    for ex in examples:
        text = (ex.get("user_text") or "").lower()
        tags = " ".join(ex.get("tags") or []).lower()
        combined = f"{text} {tags}"
        score = 0.0
        for w in words:
            if w in combined:
                score += 1.0
        # fallback: simple substring check
        if not words and user_lower in combined:
            score = 1.0
        if score > 0.0:
            scored.append((score, ex))

    scored.sort(key=lambda item: item[0], reverse=True)
    return [ex for _, ex in scored[:limit]]


def verify_admin_password(admin_password: Optional[str]) -> bool:
    """
    Check if the provided admin_password is valid.

    - If ADMIN_PASSWORD is set in config, require an exact match.
    - If ADMIN_PASSWORD is not set, allow all (useful for local/dev).
    """
    configured = _settings.ADMIN_PASSWORD
    if configured:
        return admin_password == configured
    # No configured password → treat as dev mode and allow
    return True


