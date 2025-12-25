"""User database models for authentication."""
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, Field


class UserDocument(BaseModel):
    """User document stored in MongoDB."""
    
    user_id: str = Field(..., description="Unique user identifier")
    email: EmailStr = Field(..., description="User email address (unique)")
    hashed_password: str = Field(..., description="Bcrypt hashed password")
    full_name: str = Field(..., description="User's full name")
    is_verified: bool = Field(default=False, description="Email verified via OTP")
    is_active: bool = Field(default=True, description="Account active status")
    oauth_provider: Optional[str] = Field(None, description="OAuth provider: 'google' or None for email")
    oauth_id: Optional[str] = Field(None, description="OAuth provider user ID")
    created_at: datetime = Field(default_factory=datetime.now, description="Account creation time")
    last_login: Optional[datetime] = Field(None, description="Last login timestamp")
    
    class Config:
        json_schema_extra = {
            "example": {
                "user_id": "user_abc123",
                "email": "john@example.com",
                "full_name": "John Doe",
                "is_verified": True,
                "is_active": True,
                "oauth_provider": None,
                "created_at": "2025-12-18T20:00:00"
            }
        }


class OTPDocument(BaseModel):
    """OTP verification code document."""
    
    email: EmailStr = Field(..., description="Email address")
    otp_code: str = Field(..., description="6-digit OTP code")
    expires_at: datetime = Field(..., description="OTP expiration time")
    created_at: datetime = Field(default_factory=datetime.now, description="OTP creation time")
    
    class Config:
        json_schema_extra = {
            "example": {
                "email": "john@example.com",
                "otp_code": "123456",
                "expires_at": "2025-12-18T20:10:00",
                "created_at": "2025-12-18T20:00:00"
            }
        }


class UserResponse(BaseModel):
    """User response model (without sensitive data)."""
    
    user_id: str
    email: EmailStr
    full_name: str
    is_verified: bool
    oauth_provider: Optional[str] = None
    created_at: datetime
    
    class Config:
        json_schema_extra = {
            "example": {
                "user_id": "user_abc123",
                "email": "john@example.com",
                "full_name": "John Doe",
                "is_verified": True,
                "oauth_provider": None,
                "created_at": "2025-12-18T20:00:00"
            }
        }
