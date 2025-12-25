"""MongoDB document models using Pydantic."""
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class MessageDocument(BaseModel):
    """Individual message in a conversation."""
    
    role: str = Field(..., description="Message role: 'user' or 'assistant'")
    content: str = Field(..., description="Message content/text")
    timestamp: datetime = Field(default_factory=datetime.now, description="Message timestamp")
    mood_state: Optional[Dict[str, Any]] = Field(None, description="Detected mood state for this message")
    mode: Optional[str] = Field(None, description="Support mode used: listening, calming, motivation, stability, crisis-aware")
    
    class Config:
        json_schema_extra = {
            "example": {
                "role": "user",
                "content": "I'm feeling really anxious today",
                "timestamp": "2025-12-18T20:00:00",
                "mood_state": {
                    "dominant_mood": "anxious",
                    "energy_level": "low",
                    "stability": "overwhelmed",
                    "risk_score": 0.3
                },
                "mode": "calming"
            }
        }


class ConversationDocument(BaseModel):
    """Main conversation document stored in MongoDB."""
    
    conversation_id: str = Field(..., description="Unique conversation identifier")
    user_id: Optional[str] = Field(None, description="Optional user identifier to group conversations")
    created_at: datetime = Field(default_factory=datetime.now, description="Conversation creation timestamp")
    updated_at: datetime = Field(default_factory=datetime.now, description="Last update timestamp")
    messages: List[MessageDocument] = Field(default_factory=list, description="List of messages in this conversation")
    summary: str = Field(default="", description="Brief conversation summary")
    total_messages: int = Field(default=0, description="Total number of messages")
    
    class Config:
        json_schema_extra = {
            "example": {
                "conversation_id": "chat_1234567890",
                "user_id": "user_abc123",
                "created_at": "2025-12-18T20:00:00",
                "updated_at": "2025-12-18T20:30:00",
                "messages": [
                    {
                        "role": "user",
                        "content": "Hello",
                        "timestamp": "2025-12-18T20:00:00"
                    }
                ],
                "summary": "Initial greeting",
                "total_messages": 2
            }
        }


class MetadataDocument(BaseModel):
    """Database metadata."""
    
    created_at: datetime = Field(default_factory=datetime.now, description="Database creation timestamp")
    last_updated: datetime = Field(default_factory=datetime.now, description="Last update timestamp")
    total_conversations: int = Field(default=0, description="Total number of conversations")
    total_users: int = Field(default=0, description="Total number of unique users")
    
    class Config:
        json_schema_extra = {
            "example": {
                "created_at": "2025-12-18T20:00:00",
                "last_updated": "2025-12-18T21:00:00",
                "total_conversations": 150,
                "total_users": 25
            }
        }
