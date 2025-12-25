import json
import os
from datetime import datetime
from typing import Dict, List, Optional

from app.core.logging import get_logger

logger = get_logger(__name__)

ADMIN_CONVERSATIONS_FILE = "admin_conversations.json"


class AdminStorage:
    """
    Manages admin conversation storage in admin_conversations.json.
    
    Structure:
    {
        "conversations": [
            {
                "id": "admin_1",
                "timestamp": "2025-12-16T...",
                "role": "admin" | "assistant",
                "content": "...",
            }
        ]
    }
    """

    def __init__(self, storage_file: str = ADMIN_CONVERSATIONS_FILE):
        self.storage_file = storage_file
        self._ensure_file()

    def _ensure_file(self):
        """Create admin_conversations.json if it doesn't exist."""
        if not os.path.exists(self.storage_file):
            initial_data = {
                "conversations": [],
                "metadata": {
                    "created_at": datetime.now().isoformat(),
                    "total_conversations": 0,
                },
            }
            self._write_file(initial_data)
            logger.info(f"Created new admin storage file: {self.storage_file}")

    def _read_file(self) -> Dict:
        """Read the entire admin storage file."""
        try:
            if not os.path.exists(self.storage_file):
                self._ensure_file()
            with open(self.storage_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError) as e:
            logger.warning(f"Error reading admin storage file: {e}. Creating new one.")
            self._ensure_file()
            return self._read_file()

    def _write_file(self, data: Dict):
        """Write data to the admin storage file."""
        try:
            with open(self.storage_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Error writing admin storage file: {e}")

    def save_admin_message(self, content: str, role: str = "admin"):
        """
        Save an admin message to storage.
        
        Args:
            content: Message content
            role: "admin" or "assistant"
        """
        storage = self._read_file()
        conversations = storage.setdefault("conversations", [])

        message = {
            "id": f"admin_{len(conversations) + 1}_{int(datetime.now().timestamp())}",
            "timestamp": datetime.now().isoformat(),
            "role": role,
            "content": content,
        }

        conversations.append(message)
        storage["metadata"] = {
            "last_updated": datetime.now().isoformat(),
            "total_conversations": len(conversations),
        }

        self._write_file(storage)
        logger.debug(f"Saved admin message: {role}")

    def save_admin_conversation(self, user_message: str, assistant_message: str):
        """Save both user and assistant messages from an admin conversation."""
        self.save_admin_message(user_message, role="admin")
        self.save_admin_message(assistant_message, role="assistant")

    def load_admin_context(self) -> str:
        """
        Load all admin conversations and format as context string for system prompt.
        
        Returns formatted string with all admin instructions/examples.
        """
        storage = self._read_file()
        conversations = storage.get("conversations", [])

        if not conversations:
            return ""

        lines: List[str] = []
        for conv in conversations:
            role_label = "Admin" if conv.get("role") == "admin" else "MoodDoctor AI"
            lines.append(f"{role_label}: {conv.get('content', '')}")

        return "\n".join(lines)

    def get_all_conversations(self) -> List[Dict]:
        """Get all admin conversations (for admin UI)."""
        storage = self._read_file()
        return storage.get("conversations", [])


# Global admin storage instance
admin_storage = AdminStorage()


def load_admin_context() -> str:
    """Convenience function to load admin context."""
    return admin_storage.load_admin_context()

