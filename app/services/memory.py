"""
Conversation memory management using MongoDB.

This module provides backward-compatible interface with the original JSON-based memory,
but now uses MongoDB for persistent storage.
"""
import logging
from typing import Dict, List, Optional

from app.db.db_service import conversation_service

logger = logging.getLogger(__name__)


class ConversationMemory:
    """
    Manages conversation history using MongoDB (backward compatible with JSON-based version).
    
    All methods are now async-aware wrappers around the database service.
    For backward compatibility, this maintains the same interface as the original
    JSON file-based implementation.
    """

    def __init__(self, memory_file: str = None):
        """
        Initialize conversation memory.
        
        Note: memory_file parameter is kept for backward compatibility but is ignored.
        All data is now stored in MongoDB.
        """
        if memory_file:
            logger.info(f"MongoDB-backed memory initialized (memory_file parameter ignored: {memory_file})")
        else:
            logger.info("MongoDB-backed memory initialized")

    async def get_conversation_history(
        self, conversation_id: str, max_messages: int = 10
    ) -> List[Dict]:
        """
        Get conversation history formatted for LLM (last N messages).
        
        Returns list of dicts with 'role' and 'content' keys.
        """
        return await conversation_service.get_conversation_history(
            conversation_id=conversation_id,
            max_messages=max_messages
        )

    async def save_message(
        self,
        conversation_id: str,
        role: str,
        content: str,
        mood_state: Optional[Dict] = None,
        mode: Optional[str] = None,
        user_id: Optional[str] = None,
    ):
        """
        Save a message to conversation history.
        
        Args:
            conversation_id: Unique conversation identifier
            role: "user" or "assistant"
            content: Message text
            mood_state: Optional mood state dict
            mode: Optional support mode
            user_id: Optional user identifier (for multi-user support)
        """
        await conversation_service.save_message(
            conversation_id=conversation_id,
            role=role,
            content=content,
            mood_state=mood_state,
            mode=mode,
            user_id=user_id
        )

    async def get_conversation_summary(self, conversation_id: str) -> Optional[str]:
        """Get a brief summary of the conversation."""
        conversation = await conversation_service.get_conversation(conversation_id)
        if conversation:
            return conversation.get("summary", "")
        return None

    async def update_conversation_summary(self, conversation_id: str, summary: str):
        """Update the conversation summary."""
        await conversation_service.update_conversation_summary(
            conversation_id=conversation_id,
            summary=summary
        )

    async def get_all_conversations(self, user_id: Optional[str] = None) -> Dict:
        """
        Get all conversations (for admin/debugging purposes).
        
        Args:
            user_id: Optional user identifier to filter conversations
            
        Returns:
            Dict with conversations and metadata
        """
        conversations = await conversation_service.get_all_conversations(user_id=user_id)
        
        # Format to match original JSON structure for backward compatibility
        return {
            "conversations": {conv["conversation_id"]: conv for conv in conversations},
            "metadata": {
                "total_conversations": len(conversations),
            }
        }

    async def delete_conversation(self, conversation_id: str) -> bool:
        """Delete a conversation from memory."""
        return await conversation_service.delete_conversation(conversation_id)


# Global memory instance
memory_store = ConversationMemory()
