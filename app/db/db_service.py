"""Database service layer for conversation CRUD operations."""
import logging
from datetime import datetime
from typing import Dict, List, Optional

from app.core.database import mongodb
from app.db.models import ConversationDocument, MessageDocument
from app.services.sheets import sheets_service

    @staticmethod
    async def save_message(
        conversation_id: str,
        role: str,
        content: str,
        mood_state: Optional[Dict] = None,
        mode: Optional[str] = None,
        user_id: Optional[str] = None
    ) -> bool:
        """
        Save a message to conversation history.
        
        Args:
            conversation_id: Unique conversation identifier
            role: Message role ('user' or 'assistant')
            content: Message content
            mood_state: Optional mood state dict
            mode: Optional support mode
            user_id: Optional user identifier
            
        Returns:
            True if successful
        """
        try:
            db = mongodb.get_db()
            collection = db.conversations
            
            # Check if conversation exists
            existing = await collection.find_one({"conversation_id": conversation_id})
            
            if not existing:
                # Create new conversation
                await ConversationService.create_conversation(conversation_id, user_id)
            
            # Create message
            message = MessageDocument(
                role=role,
                content=content,
                timestamp=datetime.now(),
                mood_state=mood_state,
                mode=mode
            )
            
            # Update conversation with new message
            result = await collection.update_one(
                {"conversation_id": conversation_id},
                {
                    "$push": {"messages": message.model_dump()},
                    "$set": {"updated_at": datetime.now()},
                    "$inc": {"total_messages": 1}
                }
            )
            
            # Log to Google Sheets (Fire and Forget)
            if user_id:
                try:
                    await sheets_service.log_chat_message(
                        user_id=user_id,
                        role=role,
                        content=content,
                        mood=mood_state.get('dominant_mood') if mood_state else None
                    )
                except Exception as ex:
                    logger.error(f"Sheets logging failed: {ex}")
            
            if result.modified_count > 0:
                logger.debug(f"Saved {role} message to conversation {conversation_id}")
                return True
            else:
                logger.warning(f"Failed to save message to conversation {conversation_id}")
                return False
                
        except Exception as e:
            logger.error(f"Error saving message to conversation {conversation_id}: {e}")
            raise

    @staticmethod
    async def get_conversation_history(
        conversation_id: str,
        max_messages: int = 10
    ) -> List[Dict]:
        """
        Get conversation history formatted for LLM (last N messages).
        
        Args:
            conversation_id: Unique conversation identifier
            max_messages: Maximum number of recent messages to retrieve
            
        Returns:
            List of message dicts with 'role' and 'content' keys
        """
        try:
            db = mongodb.get_db()
            collection = db.conversations
            
            conversation = await collection.find_one({"conversation_id": conversation_id})
            
            if not conversation:
                logger.debug(f"Conversation {conversation_id} not found")
                return []
            
            messages = conversation.get("messages", [])
            
            # Get last N messages
            recent_messages = messages[-max_messages:] if len(messages) > max_messages else messages
            
            # Format for LLM (only role and content)
            formatted = [
                {
                    "role": msg.get("role", "user"),
                    "content": msg.get("content", "")
                }
                for msg in recent_messages
            ]
            
            logger.debug(f"Retrieved {len(formatted)} messages for conversation {conversation_id}")
            return formatted
            
        except Exception as e:
            logger.error(f"Error getting conversation history for {conversation_id}: {e}")
            return []

    @staticmethod
    async def get_conversation(conversation_id: str) -> Optional[Dict]:
        """
        Get full conversation details.
        
        Args:
            conversation_id: Unique conversation identifier
            
        Returns:
            Conversation document dict or None if not found
        """
        try:
            db = mongodb.get_db()
            collection = db.conversations
            
            conversation = await collection.find_one({"conversation_id": conversation_id})
            
            if conversation:
                # Remove MongoDB _id field
                conversation.pop("_id", None)
                logger.debug(f"Retrieved conversation {conversation_id}")
            else:
                logger.debug(f"Conversation {conversation_id} not found")
            
            return conversation
            
        except Exception as e:
            logger.error(f"Error getting conversation {conversation_id}: {e}")
            return None

    @staticmethod
    async def get_all_conversations(
        user_id: Optional[str] = None,
        skip: int = 0,
        limit: int = 50
    ) -> List[Dict]:
        """
        Get all conversations, optionally filtered by user_id.
        
        Args:
            user_id: Optional user identifier to filter by
            skip: Number of documents to skip (pagination)
            limit: Maximum number of documents to return
            
        Returns:
            List of conversation documents
        """
        try:
            db = mongodb.get_db()
            collection = db.conversations
            
            # Build query filter
            query_filter = {}
            if user_id:
                query_filter["user_id"] = user_id
            
            # Get conversations sorted by updated_at (most recent first)
            cursor = collection.find(query_filter).sort("updated_at", -1).skip(skip).limit(limit)
            conversations = await cursor.to_list(length=limit)
            
            # Remove MongoDB _id field from each
            for conv in conversations:
                conv.pop("_id", None)
            
            logger.debug(f"Retrieved {len(conversations)} conversations for user {user_id or 'all'}")
            return conversations
            
        except Exception as e:
            logger.error(f"Error getting conversations: {e}")
            return []

    @staticmethod
    async def get_user_conversations(
        user_id: str,
        skip: int = 0,
        limit: int = 50
    ) -> List[Dict]:
        """
        Get all conversations for a specific user.
        
        Args:
            user_id: User identifier
            skip: Number of documents to skip (pagination)
            limit: Maximum number of documents to return
            
        Returns:
            List of conversation documents for this user
        """
        return await ConversationService.get_all_conversations(user_id, skip, limit)

    @staticmethod
    async def delete_conversation(conversation_id: str) -> bool:
        """
        Delete a conversation.
        
        Args:
            conversation_id: Unique conversation identifier
            
        Returns:
            True if deleted, False if not found
        """
        try:
            db = mongodb.get_db()
            collection = db.conversations
            
            result = await collection.delete_one({"conversation_id": conversation_id})
            
            if result.deleted_count > 0:
                logger.info(f"Deleted conversation {conversation_id}")
                return True
            else:
                logger.warning(f"Conversation {conversation_id} not found for deletion")
                return False
                
        except Exception as e:
            logger.error(f"Error deleting conversation {conversation_id}: {e}")
            return False

    @staticmethod
    async def update_conversation_summary(
        conversation_id: str,
        summary: str
    ) -> bool:
        """
        Update conversation summary.
        
        Args:
            conversation_id: Unique conversation identifier
            summary: New summary text
            
        Returns:
            True if updated successfully
        """
        try:
            db = mongodb.get_db()
            collection = db.conversations
            
            result = await collection.update_one(
                {"conversation_id": conversation_id},
                {
                    "$set": {
                        "summary": summary,
                        "updated_at": datetime.now()
                    }
                }
            )
            
            if result.modified_count > 0:
                logger.debug(f"Updated summary for conversation {conversation_id}")
                return True
            else:
                logger.warning(f"Conversation {conversation_id} not found for summary update")
                return False
                
        except Exception as e:
            logger.error(f"Error updating summary for conversation {conversation_id}: {e}")
            return False


# Singleton instance
conversation_service = ConversationService()
